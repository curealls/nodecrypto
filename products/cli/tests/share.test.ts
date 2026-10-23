import { describe, expect, it } from 'vitest';
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { decodeShare, SHARE_MAX_LENGTH, SHARE_WARN_LENGTH } from 'nodecrypto-engine/dag/shareLink';
import { validatePackage } from 'nodecrypto-engine/dag/package';
import { defaultNodeRegistry } from 'nodecrypto-engine/registry/nodeRegistry';
import { share, type Deps } from '../src/commands';
import { mcpTools, type McpDeps } from '../src/mcp/tools';

const root = new URL('../../../', import.meta.url);
const read = (rel: string) => readFileSync(new URL(rel, root), 'utf8');
const aesGcm = read('examples/workflows/aes-gcm.ncw');
const varsAes = read('examples/workflows/variables-aes-ecb.ncw');
const draft = JSON.parse(read('examples/workflows/drafts/aes-gcm.json'));
const files = (map: Record<string, string>): Deps => ({
  readFile: async (p) => {
    if (p in map) return map[p];
    throw new Error('ENOENT');
  },
  readStdin: async () => '',
});
const body = (url: string) => url.slice(url.indexOf('#share=') + 7);
const known = new Set(defaultNodeRegistry.getMap().keys());

/** A draft whose one constant is `hexChars` random hex digits: it hardly compresses, so it drives the link length. */
const big = (hexChars: number) => ({
  draft: 1,
  name: 'big',
  nodes: [{ id: 'pt', type: 'input-static-value', props: { type: 'bytes', valueBytes: randomBytes(hexChars / 2).toString('hex') } }],
  edges: [],
});

describe('share command (cli-spec.md §4.7)', () => {
  it('a package gives a link that decodes to the same package', async () => {
    const r = await share({ file: 'a.ncw' }, files({ 'a.ncw': aesGcm }));
    expect(r.exitCode).toBe(0);
    expect(r.text).toMatch(/^https:\/\/app\.nodecrypto\.dev\/#share=1\.[A-Za-z0-9_-]+\n$/);
    expect(r.stderr).toBe('');
    expect(await decodeShare(body(r.text.trim()))).toEqual(JSON.parse(aesGcm));
    expect(r.data).toEqual({ ok: true, url: r.text.trim(), length: r.text.trim().length });
  });

  it('a draft is validated and expanded first', async () => {
    const r = await share({ file: 'd.json' }, files({ 'd.json': JSON.stringify(draft) }));
    expect(r.exitCode).toBe(0);
    const pkg = await decodeShare(body(r.text.trim()));
    expect(validatePackage(pkg, known)).toBeNull();
    expect(pkg.workflow.nodes.length).toBe(draft.nodes.length);
  });

  it('a broken draft makes no link and exits 1', async () => {
    const r = await share({ file: 'd.json' }, files({ 'd.json': JSON.stringify({ ...draft, edges: [{ from: 'x.a', to: 'y.b' }] }) }));
    expect(r.exitCode).toBe(1);
    expect(r.text).toBe('');
  });

  it('--app sets the address and a hash in it is dropped', async () => {
    const a = await share({ file: 'a.ncw', app: 'http://localhost:3000/' }, files({ 'a.ncw': aesGcm }));
    expect(a.text.startsWith('http://localhost:3000/#share=1.')).toBe(true);
    const b = await share({ file: 'a.ncw', app: 'https://x.example/app#old' }, files({ 'a.ncw': aesGcm }));
    expect(b.text.startsWith('https://x.example/app#share=1.')).toBe(true);
  });

  it('variables are written as values: no names, no variables field', async () => {
    const r = await share({ file: 'v.ncw' }, files({ 'v.ncw': varsAes }));
    expect(r.exitCode).toBe(0);
    const pkg = await decodeShare(body(r.text.trim()));
    expect(JSON.stringify(pkg)).not.toContain('$var');
    expect(pkg.variables).toBeUndefined();
    expect(validatePackage(pkg, known)).toBeNull();
  });

  it('a reference without a value makes no link', async () => {
    const pkg = JSON.parse(varsAes);
    delete pkg.variables;
    const r = await share({ file: 'v.ncw' }, files({ 'v.ncw': JSON.stringify(pkg) }));
    expect(r.exitCode).toBe(1);
    expect(r.stderr).toContain('SHARE_VARIABLE_UNRESOLVED');
  });

  it('warns over 8,000 chars and refuses over 64,000', async () => {
    const mid = await share({ file: 'b.json' }, files({ 'b.json': JSON.stringify(big(20000)) }));
    expect(mid.exitCode).toBe(0);
    expect(mid.text.trim().length).toBeGreaterThan(SHARE_WARN_LENGTH);
    expect(mid.stderr).toContain('warning:');
    const huge = await share({ file: 'b.json' }, files({ 'b.json': JSON.stringify(big(130000)) }));
    expect(huge.exitCode).toBe(1);
    expect(huge.text).toBe('');
    expect(huge.stderr).toContain('SHARE_TOO_LONG');
    expect(SHARE_MAX_LENGTH).toBe(64000);
  });
});

describe('share through the process', () => {
  const bundle = new URL('../dist/nodecrypto.mjs', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1');
  const cli = (args: string[], input?: string) => spawnSync(process.execPath, [bundle, ...args], { encoding: 'utf8', input });

  it('reads stdin, prints one line, --json and --app, and rejects --app elsewhere', () => {
    const r = cli(['share', '-'], aesGcm);
    expect(r.status).toBe(0);
    expect(r.stdout.trim().split('\n')).toHaveLength(1);
    expect(r.stdout.startsWith('https://app.nodecrypto.dev/#share=1.')).toBe(true);
    const j = JSON.parse(cli(['share', '-', '--json', '--app', 'http://localhost:3000/'], aesGcm).stdout);
    expect(j.ok).toBe(true);
    expect(j.url.startsWith('http://localhost:3000/#share=1.')).toBe(true);
    expect(cli(['validate', '-', '--app', 'x'], aesGcm).status).toBe(64);
  });
});

describe('expand returns shareUrl (mcp-spec.md §5.3)', () => {
  const deps = (): McpDeps => ({
    readFile: async (p) => readFileSync(p, 'utf8'),
    readStdin: async () => '',
    writeFile: async () => {},
    mkdir: async () => {},
    exists: async () => false,
    homedir: () => '/home/me',
  });
  const expand = async (d: unknown) => {
    const r = await mcpTools(deps()).find((t) => t.name === 'expand')!.handler({ draft: d });
    return { ...r, json: JSON.parse(r.text) };
  };

  it('the link opens the same package; a long one carries a note; one over the limit has no link', async () => {
    const ok = await expand(draft);
    expect(ok.json.shareUrl).toMatch(/^https:\/\/app\.nodecrypto\.dev\/#share=1\./);
    expect(ok.json.shareNote).toBeUndefined();
    expect((await decodeShare(body(ok.json.shareUrl))).workflow.nodes.length).toBe(draft.nodes.length);
    expect(ok.json.openHint).toContain('plain text');
    const mid = await expand(big(20000));
    expect(mid.json.shareUrl).toBeTruthy();
    expect(mid.json.shareNote).toContain('cut it off');
    const huge = await expand(big(130000));
    expect(huge.isError).toBeFalsy();
    expect(huge.json.shareUrl).toBeUndefined();
    expect(huge.json.shareNote).toContain('64000');
  });
});
