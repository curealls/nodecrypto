import { describe, expect, it } from 'vitest';
import { readdirSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { catalog, expand, guide, validateCmd } from '../src/commands';
import { createServer } from '../src/mcp/server';
import { mcpInfo, mcpTools, type McpDeps } from '../src/mcp/tools';

const dir = new URL('../../../examples/workflows/', import.meta.url);
const path = (name: string) => new URL(name, dir).pathname.replace(/^\/([A-Za-z]:)/, '$1');
const realRead = async (p: string) => readFileSync(p, 'utf8');

/** In-memory file system: `disk` maps absolute paths to contents. */
function fakeDeps(over: Partial<McpDeps> = {}) {
  const disk = new Map<string, string>();
  const made: string[] = [];
  const deps: McpDeps = {
    readFile: realRead,
    readStdin: async () => {
      throw new Error('stdin must not be read');
    },
    writeFile: async (p, c) => void disk.set(p, c),
    mkdir: async (p) => void made.push(p),
    exists: async (p) => disk.has(p),
    homedir: () => resolve('/home/me'),
    ...over,
  };
  const call = async (name: string, args: Record<string, unknown>) => {
    const t = mcpTools(deps).find((x) => x.name === name)!;
    const r = await t.handler(args);
    return { ...r, json: (() => { try { return JSON.parse(r.text); } catch { return undefined; } })() };
  };
  return { disk, made, deps, call };
}

const draft = {
  draft: 1,
  name: 'AES ECB: demo/1',
  nodes: [
    { id: 'in', type: 'workflow-input', outputs: [{ id: 'key', dataType: 'bytes', name: 'Key', defaultValue: '000102030405060708090a0b0c0d0e0f' }] },
    { id: 'pt', type: 'input-static-value', props: { type: 'bytes', valueBytes: '00112233445566778899aabbccddeeff' } },
    { id: 'aes', type: 'symmetric-aes-encrypt', props: { mode: 'ECB', padding: 'None' } },
    { id: 'out', type: 'workflow-output', inputs: [{ id: 'ct', dataType: 'bytes', name: 'Ciphertext' }] },
  ],
  edges: [
    { from: 'in.key', to: 'aes.key' },
    { from: 'pt.value', to: 'aes.plaintext' },
    { from: 'aes.ciphertext', to: 'out.ct' },
  ],
};
const FIPS197 = '69c4e0d86a7b0430d8cdb78070b4c55a';

describe('tools match the CLI', () => {
  it('declares the five tools in order, strict schemas, annotations', () => {
    const tools = mcpTools(fakeDeps().deps);
    expect(tools.map((t) => t.name)).toEqual(['guide', 'catalog', 'validate', 'expand', 'run']);
    for (const t of tools) expect(t.inputSchema).toMatchObject({ type: 'object', additionalProperties: false });
    expect(tools.find((t) => t.name === 'expand')!.annotations).toEqual({ readOnlyHint: false, destructiveHint: true, idempotentHint: true });
    expect(tools.find((t) => t.name === 'run')!.annotations).toEqual({ readOnlyHint: true });
    expect(mcpInfo().instructions).toContain('Call guide first');
  });

  it('guide', async () => {
    const r = await fakeDeps().call('guide', {});
    expect(r.isError).toBeFalsy();
    expect(r.text).toBe(guide().text);
  });

  it('catalog: type, list, search, no match, mixed modes', async () => {
    const { call } = fakeDeps();
    expect((await call('catalog', { type: 'symmetric-aes-encrypt' })).json).toEqual(catalog({ type: 'symmetric-aes-encrypt' }).data);
    expect((await call('catalog', { list: true })).json).toEqual(catalog({ list: true }).data);
    const found = (await call('catalog', { search: 'aes encrypt' })).json;
    expect(found).toEqual(catalog({ search: 'aes encrypt' }).data);
    expect(found.map((n: { type: string }) => n.type)).toContain('symmetric-aes-encrypt');
    const none = await call('catalog', { search: 'zzzz-nothing' });
    expect(none.isError).toBe(true);
    expect(none.json.issues[0].code).toBe('CATALOG_NO_MATCH');
    const mixed = await call('catalog', { type: 'x', list: true });
    expect(mixed.isError).toBe(true);
    expect(mixed.json.issues[0].code).toBe('CLI_USAGE');
  });

  it('validate: draft object, file path, issues', async () => {
    const { call } = fakeDeps();
    const ok = await call('validate', { draft });
    expect(ok.isError).toBeFalsy();
    expect(ok.json).toEqual({ ok: true, kind: 'draft', issues: [] });
    const viaFile = await call('validate', { path: path('drafts/aes-gcm.json') });
    expect(viaFile.json).toEqual((await validateCmd({ file: path('drafts/aes-gcm.json') }, { readFile: realRead, readStdin: async () => '' })).data);
    const broken = await call('validate', { draft: { ...draft, edges: [{ from: 'in.key', to: 'aes.nope' }] } });
    expect(broken.isError).toBe(true);
    expect(broken.json.issues.length).toBeGreaterThan(0);
    expect(broken.json.issues[0]).toHaveProperty('code');
  });

  it('run: inputs as object or JSON text, expect, trace, mismatch', async () => {
    const { call } = fakeDeps();
    const ok = await call('run', { draft, expect: { Ciphertext: FIPS197 } });
    expect(ok.isError).toBeFalsy();
    expect(ok.json.outputs).toEqual({ Ciphertext: FIPS197 });
    expect(ok.json.expect).toEqual({ match: true, diffs: [] });
    const text = await call('run', { draft, inputs: '{"Key":"000102030405060708090a0b0c0d0e0f"}', expect: JSON.stringify({ Ciphertext: FIPS197.toUpperCase() }) });
    expect(text.json.expect.match).toBe(true);
    const bad = await call('run', { draft, expect: { Ciphertext: '00' } });
    expect(bad.isError).toBe(true);
    expect(bad.json.expect.match).toBe(false);
    expect(bad.json.expect.diffs[0]).toMatchObject({ key: 'Ciphertext', expected: '00', actual: FIPS197 });
    const traced = await call('run', { draft, trace: true });
    expect(traced.json.trace.aes.ciphertext).toBe(FIPS197);
    const missing = await call('run', { draft, inputs: { Nope: '00' } });
    expect(missing.json.issues[0].code).toBe('RUN_INPUT_UNKNOWN');
  });

  it('run: vars as an object, as JSON text and as a path', async () => {
    const { call } = fakeDeps();
    const withVar = { ...draft, nodes: draft.nodes.map((n) => (n.id === 'pt' ? { ...n, props: { type: 'bytes', valueBytes: { $var: '$data.pt' } } } : n)) };
    const vars = { format: 'nodecrypto-values', formatVersion: 1, variables: { 'data.pt': { name: 'pt', type: 'bytes', default: '00112233445566778899aabbccddeeff', description: '' } } };
    const without = await call('run', { draft: withVar });
    expect(without.isError).toBe(true); // the reference cannot be resolved
    const viaObject = await call('run', { draft: withVar, vars, expect: { Ciphertext: FIPS197 } });
    expect(viaObject.isError).toBeFalsy();
    expect(viaObject.json.expect.match).toBe(true);
    const viaText = await call('run', { draft: withVar, vars: JSON.stringify(vars), expect: { Ciphertext: FIPS197 } });
    expect(viaText.json.expect.match).toBe(true); // JSON text is not a path: it would be unreadable as one
    const viaPath = await fakeDeps({ readFile: async (p) => (p === '/v.json' ? JSON.stringify(vars) : realRead(p)) }).call('run', { draft: withVar, vars: '/v.json', expect: { Ciphertext: FIPS197 } });
    expect(viaPath.json.expect.match).toBe(true);
  });

  it('standard input is never read: "-" is just an unreadable file', async () => {
    const { call } = fakeDeps();
    for (const args of [{ path: '-' }, { draft, vars: '-' }]) {
      const r = await call(args.path ? 'validate' : 'run', args);
      expect(r.isError).toBe(true);
      expect(r.json.issues[0].code).toBe('CLI_FILE_UNREADABLE');
    }
  });

  it('every example runs through the tool and matches its expected outputs', async () => {
    const { call } = fakeDeps();
    const names = readdirSync(dir).filter((f) => f.endsWith('.ncw')).map((f) => f.slice(0, -4));
    expect(names.length).toBeGreaterThan(0);
    for (const name of names) {
      const e = JSON.parse(readFileSync(path(`${name}.expect.json`), 'utf8'));
      const r = await call('run', { path: path(`${name}.ncw`), inputs: e.inputs, expect: e.outputs });
      expect(r.isError, name).toBeFalsy();
      expect(r.json.expect, name).toEqual({ match: true, diffs: [] });
    }
  });
});

describe('argument errors', () => {
  it('draft and path: exactly one', async () => {
    const { call } = fakeDeps();
    for (const name of ['validate', 'expand', 'run']) {
      const none = await call(name, {});
      expect(none.isError).toBe(true);
      expect(none.json.issues[0]).toMatchObject({ code: 'MCP_ARGS_INVALID', path: 'draft' });
      const both = await call(name, { draft, path: path('drafts/aes-gcm.json') });
      expect(both.json.issues[0].code).toBe('MCP_ARGS_INVALID');
    }
  });

  it('unknown names and wrong types', async () => {
    const { call } = fakeDeps();
    const unknown = await call('validate', { draft, extra: 1 });
    expect(unknown.json.issues[0]).toMatchObject({ code: 'MCP_ARGS_INVALID', path: 'extra' });
    expect(unknown.json.issues[0].message).toContain('allowed: draft, path');
    expect((await call('validate', { draft: 'not an object' })).json.issues[0]).toMatchObject({ code: 'MCP_ARGS_INVALID', path: 'draft' });
    expect((await call('run', { draft, trace: 'yes' })).json.issues[0].path).toBe('trace');
    expect((await call('run', { draft, inputs: 5 })).json.issues[0].path).toBe('inputs');
    expect((await call('guide', { x: 1 })).json.issues[0].code).toBe('MCP_ARGS_INVALID');
  });
});

describe('expand saves the .ncw (mcp-spec.md §5)', () => {
  const home = resolve('/home/me');
  const defaultDir = join(home, 'nodecrypto-workflows');

  it('default folder is ~/nodecrypto-workflows, named after the draft, content equals `expand -o`', async () => {
    const { call, disk, made } = fakeDeps();
    const r = await call('expand', { draft });
    expect(r.isError).toBeFalsy();
    const file = join(defaultDir, 'AES-ECB-demo1.ncw');
    expect(r.json).toEqual({ ok: true, path: file, overwritten: false, nodes: 4, edges: 3, openHint: 'Open this file in the NodeCrypto web app: File > Open.' });
    expect(made).toEqual([defaultDir]);
    const cli = await expand({ file: path('drafts/aes-gcm.json') }, { readFile: realRead, readStdin: async () => '' });
    const saved = await call('expand', { path: path('drafts/aes-gcm.json') });
    expect(disk.get(saved.json.path)).toBe(cli.text); // 2-space JSON + final newline
    expect(JSON.parse(disk.get(file)!).workflow.nodes).toHaveLength(4);
    expect(r.text).not.toContain('"edges":[{'); // the package body is not returned
  });

  it('folder order: outDir (option/env) wins over home', async () => {
    const out = resolve('/work/out');
    const { call } = fakeDeps({ outDir: out });
    expect((await call('expand', { draft })).json.path).toBe(join(out, 'AES-ECB-demo1.ncw'));
  });

  it('output: absolute path as is, relative path under the default folder, folders are created', async () => {
    const { call, made } = fakeDeps();
    const abs = resolve('/proj/flows/a.ncw');
    expect((await call('expand', { draft, output: abs })).json.path).toBe(abs);
    expect((await call('expand', { draft, output: 'sub/b.NCW' })).json.path).toBe(join(defaultDir, 'sub', 'b.NCW'));
    expect(made).toEqual([resolve('/proj/flows'), join(defaultDir, 'sub')]);
  });

  it('only .ncw: other extensions are refused and nothing is written', async () => {
    const { call, disk } = fakeDeps();
    for (const output of ['package.json', 'notes.txt', 'noext', resolve('/proj/a.ncw.json')]) {
      const r = await call('expand', { draft, output });
      expect(r.isError, output).toBe(true);
      expect(r.json.issues[0].code).toBe('MCP_OUTPUT_EXTENSION');
    }
    expect(disk.size).toBe(0);
  });

  it('overwrites by default and says so; overwrite:false refuses', async () => {
    const { call, disk } = fakeDeps();
    const output = resolve('/proj/a.ncw');
    disk.set(output, 'old');
    const again = await call('expand', { draft, output });
    expect(again.json.overwritten).toBe(true);
    expect(disk.get(output)).not.toBe('old');
    disk.set(output, 'old');
    const refused = await call('expand', { draft, output, overwrite: false });
    expect(refused.isError).toBe(true);
    expect(refused.json.issues[0].code).toBe('MCP_OUTPUT_EXISTS');
    expect(disk.get(output)).toBe('old');
    expect((await call('expand', { draft, output: resolve('/proj/new.ncw'), overwrite: false })).json.ok).toBe(true);
  });

  it('write failures are reported', async () => {
    const { call } = fakeDeps({ writeFile: async () => { throw new Error('EISDIR: illegal operation on a directory'); } });
    const r = await call('expand', { draft });
    expect(r.isError).toBe(true);
    expect(r.json.issues[0]).toMatchObject({ code: 'MCP_OUTPUT_WRITE_FAILED' });
    expect(r.json.issues[0].message).toContain('EISDIR');
    const noDir = await fakeDeps({ mkdir: async () => { throw new Error('EACCES'); } }).call('expand', { draft });
    expect(noDir.json.issues[0].code).toBe('MCP_OUTPUT_WRITE_FAILED');
  });

  it('an invalid draft writes nothing and returns the issues', async () => {
    const { call, disk, made } = fakeDeps();
    const r = await call('expand', { draft: { ...draft, edges: [{ from: 'in.key', to: 'aes.nope' }] } });
    expect(r.isError).toBe(true);
    expect(r.json.issues[0]).toHaveProperty('code');
    expect(disk.size + made.length).toBe(0);
  });

  it('file name from the draft name: forbidden characters dropped, long names cut, empty becomes workflow', async () => {
    const { call } = fakeDeps();
    const named = (name: string) => call('expand', { draft: { ...draft, name } }).then((r) => r.json.path.slice(defaultDir.length + 1));
    expect(await named('  ../x: y*?  ')).toBe('x-y.ncw');
    expect(await named('한글 이름')).toBe('한글-이름.ncw');
    expect(await named('a'.repeat(100))).toBe('a'.repeat(80) + '.ncw');
    expect(await named('///')).toBe('workflow.ncw');
  });

  it('a saved package validates and runs, and expanding a package file keeps it', async () => {
    const { call, disk } = fakeDeps();
    const saved = (await call('expand', { draft })).json.path;
    const again = fakeDeps({ readFile: async (p) => (disk.get(p) ?? realRead(p)) });
    expect((await again.call('validate', { path: saved })).json).toEqual({ ok: true, kind: 'package', issues: [] });
    expect((await again.call('run', { path: saved, expect: { Ciphertext: FIPS197 } })).json.expect.match).toBe(true);
    const copy = resolve('/proj/copy.ncw');
    await again.call('expand', { path: saved, output: copy });
    expect(again.disk.get(copy)).toBe(disk.get(saved));
  });
});

describe('through the protocol', () => {
  it('a modern tools/call reaches expand and a legacy one reaches run', async () => {
    const { deps, disk } = fakeDeps();
    const h = createServer(mcpInfo(), mcpTools(deps));
    const modern = JSON.parse((await h(JSON.stringify({
      jsonrpc: '2.0', id: 1, method: 'tools/call',
      params: { name: 'expand', arguments: { draft, output: resolve('/proj/m.ncw') }, _meta: { 'io.modelcontextprotocol/protocolVersion': '2026-07-28', 'io.modelcontextprotocol/clientCapabilities': {} } },
    })))!);
    expect(modern.result.isError).toBe(false);
    expect(JSON.parse(modern.result.content[0].text).ok).toBe(true);
    expect(disk.has(resolve('/proj/m.ncw'))).toBe(true);
    await h(JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'initialize', params: { protocolVersion: '2025-11-25' } }));
    const legacy = JSON.parse((await h(JSON.stringify({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'run', arguments: { draft, expect: { Ciphertext: FIPS197 } } } })))!);
    expect(JSON.parse(legacy.result.content[0].text).expect.match).toBe(true);
    const list = JSON.parse((await h(JSON.stringify({ jsonrpc: '2.0', id: 4, method: 'tools/list' })))!);
    expect(list.result.tools.map((t: { name: string }) => t.name)).toEqual(['guide', 'catalog', 'validate', 'expand', 'run']);
  });
});
