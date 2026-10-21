import { beforeAll, describe, expect, it } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { catalog, expand, run, validateCmd, version, type Deps } from '../src/commands';

const root = new URL('../../../', import.meta.url);
const cmac = readFileSync(new URL('examples/workflows/cmac-subkey.ncw', root), 'utf8');
const KEY = '000102030405060708090a0b0c0d0e0f';
const FIPS197 = '69c4e0d86a7b0430d8cdb78070b4c55a';

const draft = (aesProps: Record<string, unknown> = { mode: 'ECB', padding: 'None' }, keyDefault?: string) => ({
  draft: 1,
  name: 'aes-ecb',
  nodes: [
    { id: 'in', type: 'workflow-input', outputs: [{ id: 'key', dataType: 'bytes', name: 'Key', ...(keyDefault ? { defaultValue: keyDefault } : {}) }] },
    { id: 'pt', type: 'input-static-value', props: { type: 'bytes', valueBytes: '00112233445566778899aabbccddeeff' } },
    { id: 'aes', type: 'symmetric-aes-encrypt', props: aesProps },
    { id: 'out', type: 'workflow-output', inputs: [{ id: 'ct', dataType: 'bytes', name: 'Ciphertext' }] },
  ],
  edges: [
    { from: 'in.key', to: 'aes.key' },
    { from: 'pt.value', to: 'aes.plaintext' },
    { from: 'aes.ciphertext', to: 'out.ct' },
  ],
});

const files = (map: Record<string, string>): Deps => ({
  readFile: async (p) => {
    if (p in map) return map[p];
    throw new Error('ENOENT');
  },
  readStdin: async () => '',
});

describe('node memo (data.note) is ignored by validate and run', () => {
  const withNotes = () => {
    const pkg = JSON.parse(cmac);
    for (const n of pkg.workflow.nodes) n.data.note = `# ${n.id}
memo`;
    return JSON.stringify(pkg);
  };

  it('validate passes a file whose nodes carry memos', async () => {
    const r = await validateCmd({ file: 'm.ncw' }, files({ 'm.ncw': withNotes() }));
    expect(r.exitCode).toBe(0);
  });

  it('run gives the same result with and without memos', async () => {
    const a = await run({ file: 'a.ncw', json: true }, files({ 'a.ncw': cmac }));
    const b = await run({ file: 'm.ncw', json: true }, files({ 'm.ncw': withNotes() }));
    expect(b.exitCode).toBe(a.exitCode);
    expect(b.data).toEqual(a.data);
  });
});

describe('validate', () => {
  it('a good draft passes', async () => {
    const r = await validateCmd({ file: 'd.json' }, files({ 'd.json': JSON.stringify(draft()) }));
    expect(r.exitCode).toBe(0);
    expect(r.text).toContain('OK (draft)');
    expect(r.data).toEqual({ ok: true, kind: 'draft', issues: [] });
  });

  it('a bad draft lists code, path and hint with exit code 1', async () => {
    const r = await validateCmd({ file: 'd.json' }, files({ 'd.json': JSON.stringify(draft({ mode: 'GCMM' })) }));
    expect(r.exitCode).toBe(1);
    const d = r.data as { ok: boolean; issues: { code: string; path: string; message: string; hint?: string }[] };
    expect(d.ok).toBe(false);
    expect(d.issues[0]).toMatchObject({ code: 'PROP_INVALID_VALUE', path: 'nodes[2].props.mode' });
    expect(d.issues[0].hint).toBeTruthy();
    expect(r.text).toContain('error[PROP_INVALID_VALUE] nodes[2].props.mode');
  });

  it('JSON that cannot be read is a problem, a missing file a usage error', async () => {
    expect((await validateCmd({ file: 'x' }, files({ x: '{' }))).exitCode).toBe(1);
    expect((await validateCmd({ file: 'nope' }, files({}))).exitCode).toBe(64);
    expect((await validateCmd({}, files({}))).exitCode).toBe(64);
  });

  it('an existing package passes', async () => {
    expect((await validateCmd({ file: 'c.ncw' }, files({ 'c.ncw': cmac }))).exitCode).toBe(0);
  });
});

describe('expand', () => {
  it('turns a draft into a package that validates and runs', async () => {
    const e = await expand({ file: 'd.json', output: 'out.ncw' }, files({ 'd.json': JSON.stringify(draft()) }));
    expect(e.exitCode).toBe(0);
    expect(e.files?.[0].path).toBe('out.ncw');
    const pkg = JSON.parse(e.files![0].content);
    expect(pkg.format).toBe('nodecrypto');
    const r = await run({ file: 'p.ncw', inputs: `{"Key":"${KEY}"}` }, files({ 'p.ncw': e.files![0].content }));
    expect(r.exitCode).toBe(0);
    expect(r.data).toMatchObject({ outputs: { Ciphertext: FIPS197 } });
  });

  it('does not write when the draft has problems', async () => {
    const e = await expand({ file: 'd.json', output: 'out.ncw' }, files({ 'd.json': JSON.stringify(draft({ mode: 'nope' })) }));
    expect(e.exitCode).toBe(1);
    expect(e.files).toBeUndefined();
  });
});

describe('run', () => {
  const deps = files({ 'd.json': JSON.stringify(draft()), 'dd.json': JSON.stringify(draft(undefined, KEY)), 'c.ncw': cmac });

  it('prints outputs and passes --expect (case-insensitive hex)', async () => {
    const r = await run({ file: 'd.json', inputs: `{"Key":"${KEY.toUpperCase()}"}`, expect: `{"Ciphertext":"${FIPS197.toUpperCase()}"}` }, deps);
    expect(r.exitCode).toBe(0);
    expect(r.text).toBe(`Ciphertext: ${FIPS197}\n# expect: matched 1 of 1 keys\n`);
    expect(r.stderr).toBe('');
    expect(r.data).toEqual({ ok: true, outputs: { Ciphertext: FIPS197 }, nodes: expect.any(Array), expect: { match: true, diffs: [] } });
  });

  it('uses the port defaultValue when no input is given', async () => {
    expect((await run({ file: 'dd.json' }, deps)).data).toMatchObject({ outputs: { Ciphertext: FIPS197 } });
  });

  it('reports a mismatch with exit code 1', async () => {
    const r = await run({ file: 'dd.json', expect: '{"Ciphertext":"00"}' }, deps);
    expect(r.exitCode).toBe(1);
    expect(r.data).toMatchObject({ ok: false, code: 'RUN_EXPECT_MISMATCH', expect: { diffs: [{ key: 'Ciphertext', expected: '00', actual: FIPS197 }] } });
    expect(r.stderr).toContain('mismatch Ciphertext');
    expect(r.text).not.toContain('# expect:');
  });

  it('--trace adds every successful node\'s outputs, before the expect line', async () => {
    const r = await run({ file: 'dd.json', trace: true, expect: `{"Ciphertext":"${FIPS197}"}` }, deps);
    expect(r.exitCode).toBe(0);
    const t = (r.data as any).trace;
    expect(t.aes).toMatchObject({ ciphertext: FIPS197 });
    expect(t.pt.value).toBe('00112233445566778899aabbccddeeff');
    expect(Object.keys(t)).toEqual(['in', 'pt', 'aes', 'out']);
    expect(r.text).toContain(`trace aes.ciphertext: ${FIPS197}\n`);
    expect(r.text.startsWith(`Ciphertext: ${FIPS197}\n`)).toBe(true);
    expect(r.text.endsWith('# expect: matched 1 of 1 keys\n')).toBe(true);
  });

  it('without --trace there is no trace field or line', async () => {
    const r = await run({ file: 'dd.json' }, deps);
    expect(r.data).not.toHaveProperty('trace');
    expect(r.text).toBe(`Ciphertext: ${FIPS197}\n`);
  });

  it('--trace keeps the values of nodes that succeeded before a node error', async () => {
    const r = await run({ file: 'd.json', inputs: '{"Key":"00"}', trace: true }, deps);
    expect(r.exitCode).toBe(2);
    const t = (r.data as any).trace;
    expect(t.pt.value).toBe('00112233445566778899aabbccddeeff');
    expect(t).not.toHaveProperty('aes');
  });

  it('input problems exit with 1', async () => {
    const code = async (inputs?: string) => ((await run({ file: 'd.json', inputs }, deps)).data as any).issues[0].code;
    expect(await code()).toBe('RUN_INPUT_MISSING');
    expect(await code('{"Key":"00","Other":"00"}')).toBe('RUN_INPUT_UNKNOWN');
    expect(await code('{"Key":"abc"}')).toBe('RUN_INPUT_INVALID');
    expect((await run({ file: 'd.json', inputs: '{"Key":"00"}' }, deps)).exitCode).toBe(2);
  });

  it('a node error exits with 2 and names the node', async () => {
    const r = await run({ file: 'd.json', inputs: '{"Key":"00"}' }, deps);
    expect(r.exitCode).toBe(2);
    expect(r.data).toMatchObject({ ok: false, code: 'RUN_NODE_ERROR' });
    expect((r.data as any).nodes.find((n: any) => n.id === 'aes')).toMatchObject({ status: 'error' });
    expect(r.stderr).toContain('aes:');
  });

  it('a validation failure stops before running', async () => {
    const bad = files({ 'b.json': JSON.stringify(draft({ mode: 'nope' })) });
    expect((await run({ file: 'b.json' }, bad)).exitCode).toBe(1);
  });

  it('without Workflow Output the terminal node outputs are keyed <node id>.<port id>', async () => {
    const r = await run({ file: 'c.ncw', expect: '{"node-1791034725445-1efh.k1":"fbeed618357133667c85e08f7236a8de","node-1791034725445-1efh.k2":"f7ddac306ae266ccf90bc11ee46d513b"}' }, deps);
    expect(r.exitCode).toBe(0);
  });
});

describe('portNames on a fixed-port node (authoring.md §2.2)', () => {
  const named = (portNames: unknown) => {
    const d = draft();
    (d.nodes[2] as any).portNames = portNames;
    return JSON.stringify(d);
  };
  const names = { plaintext: 'Sensor Payload', ciphertext: 'Encrypted Payload' };

  it('validate and run are not affected; trace and expect keys stay on port ids', async () => {
    const deps = files({ 'n.json': named(names) });
    expect((await validateCmd({ file: 'n.json' }, deps)).exitCode).toBe(0);
    const r = await run({ file: 'n.json', inputs: `{"Key":"${KEY}"}`, trace: true, expect: `{"Ciphertext":"${FIPS197}"}` }, deps);
    expect(r.exitCode).toBe(0);
    expect((r.data as any).trace.aes).toMatchObject({ ciphertext: FIPS197 });
    expect(r.text).toContain(`trace aes.ciphertext: ${FIPS197}
`);
  });

  it('expand writes the new names and keeps the port ids', async () => {
    const e = await expand({ file: 'n.json', output: 'out.ncw' }, files({ 'n.json': named(names) }));
    expect(e.exitCode).toBe(0);
    const aes = JSON.parse(e.files![0].content).workflow.nodes.find((n: any) => n.id === 'aes').data;
    expect(aes.inputs.find((p: any) => p.id === 'plaintext').name).toBe('Sensor Payload');
    expect(aes.outputs.find((p: any) => p.id === 'ciphertext').name).toBe('Encrypted Payload');
    expect(aes.inputs.find((p: any) => p.id === 'key').name).toBe('Key');
  });

  it('a bad name shows code, path and hint in the text and the JSON output', async () => {
    const deps = files({ 'b.json': named({ iv: 'IV', plaintext: 'a/b' }) });
    const r = await validateCmd({ file: 'b.json' }, deps);
    expect(r.exitCode).toBe(1);
    const issues = (r.data as any).issues as { code: string; path: string; hint?: string }[];
    expect(issues.map((i) => i.code).sort()).toEqual(['PORT_NAME_INVALID', 'PORT_NAME_UNKNOWN_PORT']);
    for (const i of issues) {
      expect(i.path).toMatch(/^nodes\[2\]\.portNames\./);
      expect(i.hint).toBeTruthy();
      expect(r.text).toContain(`error[${i.code}] ${i.path}`);
    }
  });

  it('run stops on a bad name before running', async () => {
    const r = await run({ file: 'b.json', inputs: `{"Key":"${KEY}"}` }, files({ 'b.json': named({ plaintext: 'Key' }) }));
    expect(r.exitCode).toBe(1);
    expect((r.data as any).issues[0].code).toBe('PORT_NAME_DUPLICATE');
  });
});

describe('catalog and version', () => {
  it('prints one node, or similar types for an unknown one', () => {
    expect((catalog({ type: 'symmetric-aes-encrypt' }).data as any).type).toBe('symmetric-aes-encrypt');
    const u = catalog({ type: 'symmetric-aes-enc' });
    expect(u.exitCode).toBe(1);
    expect(u.stderr).toContain('symmetric-aes-encrypt');
  });

  it('--list prints one tab-separated line per node, and a JSON array with --json', () => {
    const all = (catalog({}).data as any).nodes;
    const l = catalog({ list: true });
    const lines = l.text.trimEnd().split('\n');
    expect(lines).toHaveLength(all.length);
    expect(lines.every((x) => x.split('\t').length === 3)).toBe(true);
    expect(l.data).toHaveLength(all.length);
    expect(l.data).toEqual(expect.arrayContaining([expect.objectContaining({ type: 'symmetric-aes-encrypt', category: expect.any(String) })]));
  });

  it('--search ANDs case-insensitive keywords over type, label, category and description', () => {
    const types = (a: string) => ((catalog({ search: a }).data as any[]) ?? []).map((r) => r.type);
    expect(types('AES')).toContain('symmetric-aes-encrypt');
    expect(types('hkdf')).toEqual(expect.arrayContaining([expect.stringContaining('hkdf')]));
    expect(types('aes')).not.toContain('hash-sha2');
    expect(types('aes encrypt').length).toBeLessThan(types('aes').length);
    expect(catalog({ search: 'aes' }).text).toContain('symmetric-aes-encrypt\t');
  });

  it('--search with no match exits 1 with CATALOG_NO_MATCH; blank keywords and combined modes are usage errors', () => {
    const n = catalog({ search: 'zzz-no-such-node' });
    expect(n.exitCode).toBe(1);
    expect(n.stderr).toContain('CATALOG_NO_MATCH');
    expect(catalog({ search: '  ' }).exitCode).toBe(64);
    expect(catalog({ list: true, search: 'aes' }).exitCode).toBe(64);
    expect(catalog({ type: 'symmetric-aes-encrypt', list: true }).exitCode).toBe(64);
  });

  it('reports versions', () => {
    expect(version(true).data).toMatchObject({ cli: expect.any(String), engine: expect.any(String), packageFormat: 2, draft: 1 });
  });
});

describe('built bundle', () => {
  const bundle = new URL('../dist/nodecrypto.mjs', import.meta.url);
  beforeAll(() => {
    if (!existsSync(bundle)) {
      const b = spawnSync('npx', ['vite', 'build'], { cwd: new URL('..', import.meta.url), shell: true, encoding: 'utf8' });
      if (b.status !== 0) throw new Error(b.stdout + b.stderr);
    }
  }, 120_000);

  const cli = (...args: string[]) => spawnSync(process.execPath, [bundle.pathname.replace(/^\/([A-Za-z]:)/, '$1'), ...args], { encoding: 'utf8' });

  it('runs a package file from the command line', () => {
    const r = cli('run', new URL('examples/workflows/cmac-subkey.ncw', root).pathname.replace(/^\/([A-Za-z]:)/, '$1'), '--json');
    expect(r.status).toBe(0);
    expect(JSON.parse(r.stdout).outputs['node-1791034725445-1efh.k1']).toBe('fbeed618357133667c85e08f7236a8de');
  });

  it('exits with 64 for an unknown command', () => {
    expect(cli('frobnicate').status).toBe(64);
  });
});
