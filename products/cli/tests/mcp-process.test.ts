import { afterAll, describe, expect, it } from 'vitest';
import { spawn, spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// The built bundle as a real child process, talking MCP over its standard streams (mcp-spec.md §2).
const bundle = join(__dirname, '..', 'dist', 'nodecrypto.mjs');
const tmp = mkdtempSync(join(tmpdir(), 'nc-mcp-'));
afterAll(() => rmSync(tmp, { recursive: true, force: true }));

const draft = JSON.parse(readFileSync(join(__dirname, '..', '..', '..', 'examples', 'workflows', 'drafts', 'aes-gcm.json'), 'utf8'));
const vector = JSON.parse(readFileSync(join(__dirname, '..', '..', '..', 'examples', 'workflows', 'aes-gcm.expect.json'), 'utf8'));
const meta = { 'io.modelcontextprotocol/protocolVersion': '2026-07-28', 'io.modelcontextprotocol/clientCapabilities': {} };

/** Starts `nodecrypto mcp`, sends the messages, closes stdin and returns everything the process produced. */
function session(messages: object[], args: string[] = [], env: Record<string, string> = {}) {
  return new Promise<{ code: number | null; stdout: string; stderr: string; replies: any[] }>((resolve, reject) => {
    const p = spawn(process.execPath, [bundle, 'mcp', ...args], { env: { ...process.env, ...env } });
    let stdout = '';
    let stderr = '';
    p.stdout.setEncoding('utf8').on('data', (d) => (stdout += d));
    p.stderr.setEncoding('utf8').on('data', (d) => (stderr += d));
    p.on('error', reject);
    p.on('close', (code) => resolve({ code, stdout, stderr, replies: stdout.split('\n').filter(Boolean).map((l) => JSON.parse(l)) }));
    p.stdin.end(messages.map((m) => JSON.stringify(m) + '\n').join(''));
  });
}
const call = (id: number, name: string, args: object) => ({ jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: args, _meta: meta } });
const text = (r: any) => JSON.parse(r.result.content[0].text);

describe('nodecrypto mcp (built bundle)', () => {
  it('modern session: discover, list, catalog, validate, run, expand to --out-dir; ends with exit code 0', async () => {
    const out = join(tmp, 'modern');
    const r = await session(
      [
        { jsonrpc: '2.0', id: 1, method: 'server/discover', params: { _meta: meta } },
        { jsonrpc: '2.0', id: 2, method: 'tools/list', params: { _meta: meta } },
        call(3, 'catalog', { search: 'aes encrypt' }),
        call(4, 'validate', { draft }),
        call(5, 'run', { draft, inputs: vector.inputs, expect: vector.outputs }),
        call(6, 'expand', { draft }),
      ],
      ['--out-dir', out]
    );
    expect(r.code).toBe(0);
    expect(r.stderr).toBe('');
    expect(r.stdout.endsWith('\n')).toBe(true);
    expect(r.replies.map((x) => x.id)).toEqual([1, 2, 3, 4, 5, 6]);
    expect(r.replies.every((x) => x.jsonrpc === '2.0' && (x.result || x.error))).toBe(true); // nothing but protocol messages
    expect(r.replies[0].result.supportedVersions).toEqual(['2026-07-28']);
    expect(r.replies[0].result._meta['io.modelcontextprotocol/serverInfo'].name).toBe('nodecrypto');
    expect(r.replies[1].result.tools.map((t: any) => t.name)).toEqual(['guide', 'catalog', 'validate', 'expand', 'run']);
    expect(text(r.replies[2]).map((n: any) => n.type)).toContain('symmetric-aes-encrypt');
    expect(text(r.replies[3])).toEqual({ ok: true, kind: 'draft', issues: [] });
    expect(r.replies[4].result.isError).toBe(false);
    expect(text(r.replies[4]).expect).toEqual({ match: true, diffs: [] });
    const saved = text(r.replies[5]);
    expect(saved.ok).toBe(true);
    expect(saved.path.startsWith(out)).toBe(true);
    expect(existsSync(saved.path)).toBe(true);
    expect(JSON.parse(readFileSync(saved.path, 'utf8')).workflow.nodes.length).toBe(saved.nodes);
  });

  it('legacy session: initialize, initialized, list, call; NODECRYPTO_OUT_DIR is the default folder', async () => {
    const out = join(tmp, 'env');
    const r = await session(
      [
        { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 't', version: '1' } } },
        { jsonrpc: '2.0', method: 'notifications/initialized' },
        { jsonrpc: '2.0', id: 2, method: 'tools/list' },
        { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'expand', arguments: { draft } } },
      ],
      [],
      { NODECRYPTO_OUT_DIR: out }
    );
    expect(r.code).toBe(0);
    expect(r.stderr).toBe('');
    expect(r.replies.map((x) => x.id)).toEqual([1, 2, 3]); // the notification got no reply
    expect(r.replies[0].result.protocolVersion).toBe('2025-06-18');
    expect(r.replies[1].result.tools).toHaveLength(5);
    expect(text(r.replies[2]).path.startsWith(out)).toBe(true);
  });

  it('--out-dir wins over the environment', async () => {
    const r = await session([call(1, 'expand', { draft })], ['--out-dir', join(tmp, 'flag')], { NODECRYPTO_OUT_DIR: join(tmp, 'ignored') });
    expect(text(r.replies[0]).path.startsWith(join(tmp, 'flag'))).toBe(true);
  });

  it('exits 0 on empty input and survives garbage lines', async () => {
    const none = await session([]);
    expect(none).toMatchObject({ code: 0, stdout: '', stderr: '' });
    const p = spawnSync(process.execPath, [bundle, 'mcp'], { input: 'not json\n{"jsonrpc":"2.0","id":1,"method":"ping","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}\n', encoding: 'utf8' });
    const lines = p.stdout.split('\n').filter(Boolean).map((l) => JSON.parse(l));
    expect(lines[0].error.code).toBe(-32700);
    expect(lines[1].result.resultType).toBe('complete');
    expect(p.status).toBe(0);
  });

  it('--help prints usage; bad options exit 64 without touching stdout', () => {
    const help = spawnSync(process.execPath, [bundle, 'mcp', '--help'], { encoding: 'utf8' });
    expect(help.status).toBe(0);
    expect(help.stdout).toContain('Usage: nodecrypto mcp');
    expect(help.stdout).toContain('NODECRYPTO_OUT_DIR');
    for (const args of [['--bogus'], ['extra'], ['--out-dir']]) {
      const r = spawnSync(process.execPath, [bundle, 'mcp', ...args], { encoding: 'utf8' });
      expect(r.status, args.join(' ')).toBe(64);
      expect(r.stdout).toBe('');
      expect(r.stderr).toContain('error[CLI_USAGE]');
    }
  });

  it('the top-level help lists the command and other commands still work', () => {
    expect(spawnSync(process.execPath, [bundle, '--help'], { encoding: 'utf8' }).stdout).toContain('mcp [--out-dir <folder>]');
    const v = spawnSync(process.execPath, [bundle, '--version'], { encoding: 'utf8' });
    expect(v.status).toBe(0);
    expect(v.stdout).toMatch(/^nodecrypto \d/);
  });
});
