import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { DAGRunner } from '../../src/dag/runner';
import { validatePackage } from '../../src/dag/package';
import { defaultNodeRegistry } from '../../src/registry/nodeRegistry';
import { draftToPackage, expandDraft, isDraft } from '../../src/authoring/draft';

const known = new Set(defaultNodeRegistry.getMap().keys());
const example = JSON.parse(readFileSync(new URL('../../../../examples/workflows/cmac-subkey.ncw', import.meta.url), 'utf8'));

async function run(wf: { nodes: any[]; edges: any[] }, injected: Record<string, Record<string, any>> = {}) {
  const r = await DAGRunner.execute(
    wf.nodes.map((n) => ({
      id: n.id,
      type: n.data.nodeType,
      label: n.data.label,
      properties: injected[n.id] ? { ...n.data.properties, injectedValues: injected[n.id] } : n.data.properties,
      inputs: n.data.inputs,
      outputs: n.data.outputs,
    })),
    wf.edges.map((e) => ({ id: e.id, source: e.source, sourceHandle: e.sourceHandle, target: e.target, targetHandle: e.targetHandle })),
    defaultNodeRegistry.getMap()
  );
  expect(r.success, r.error).toBe(true);
  return r.nodeOutputs;
}
const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');
const expand = (d: any) => {
  const r = expandDraft(d);
  if (!r.ok) throw new Error(JSON.stringify(r.issues.map((i) => [i.code, i.path])));
  return r.workflow;
};

const script = example.workflow.nodes.find((n: any) => n.data.nodeType === 'utility-script').data.properties.code;
const cmacDraft = (aesProps: Record<string, any> = { mode: 'ECB', padding: 'None' }) => ({
  draft: 1,
  name: 'cmac-subkey',
  nodes: [
    { id: 'key', type: 'input-static-value', label: 'Key', props: { type: 'bytes', valueBytes: '2b7e151628aed2a6abf7158809cf4f3c' } },
    { id: 'zero', type: 'input-static-value', props: { type: 'bytes', valueBytes: '00000000000000000000000000000000' } },
    { id: 'aes', type: 'symmetric-aes-encrypt', props: aesProps },
    { id: 'sub', type: 'utility-script', props: { code: script },
      inputs: [{ id: 'l', dataType: 'bytes' }], outputs: [{ id: 'k1', dataType: 'bytes' }, { id: 'k2', dataType: 'bytes' }] },
  ],
  edges: [
    { from: 'zero.value', to: 'aes.plaintext' },
    { from: 'key.value', to: 'aes.key' },
    { from: 'aes.ciphertext', to: 'sub.l' },
  ],
});

describe('draft loader (authoring.md §2)', () => {
  it('isDraft tells drafts from packages', () => {
    expect(isDraft({ draft: 1 })).toBe(true);
    expect(isDraft({ format: 'nodecrypto' })).toBe(false);
  });

  it('cmac-subkey as a draft runs to the same K1/K2 as the saved .ncw', async () => {
    const expected = await run(example.workflow);
    const eNode = example.workflow.nodes.find((n: any) => n.data.nodeType === 'utility-script').id;
    const got = await run(expand(cmacDraft()));
    expect(hex(got.sub.k1)).toBe(hex(expected[eNode].k1));
    expect(hex(got.sub.k2)).toBe(hex(expected[eNode].k2));
    expect(hex(got.sub.k1)).toBe('fbeed618357133667c85e08f7236a8de'); // RFC 4493 K1
  });

  it('props equal to the defaults can be omitted', () => {
    const a = expand(cmacDraft({ mode: 'ECB', padding: 'None' }));
    const b = expand(cmacDraft({}));
    expect(b.nodes).toEqual(a.nodes);
  });

  it('expansion is deterministic and fills what the canvas file carries', () => {
    const wf = expand(cmacDraft());
    expect(expand(cmacDraft())).toEqual(wf);
    expect(wf.id).toMatch(/^wf-[0-9a-f]{8}$/);
    const aes = wf.nodes.find((n) => n.id === 'aes');
    expect(aes.data.inputs.map((p: any) => p.id)).toEqual(['key', 'plaintext', 'iv', 'nonce', 'aad']); // hidden ports included
    expect(aes.data.properties).toMatchObject({ mode: 'ECB', padding: 'None', errorUnify: false });
    expect(aes.data.executionState).toBeUndefined();
    expect(wf.nodes.find((n) => n.id === 'key').data.label).toBe('Key');
    expect(wf.edges[0]).toMatchObject({ id: 'edge-zero-value-aes-plaintext', source: 'zero', sourceHandle: 'value', target: 'aes', targetHandle: 'plaintext', data: { dataType: 'bytes' } });
  });

  it('variable-port nodes (Workflow Input/Output, Concatenator, ValueSet + Switch) expand and run', async () => {
    const wf = expand({
      draft: 1,
      name: 'dynamic',
      nodes: [
        { id: 'in', type: 'workflow-input', outputs: [{ id: 'a', dataType: 'bytes' }, { id: 'b', dataType: 'bytes', name: 'B' }] },
        { id: 'cat', type: 'utility-concat', inputs: [{ id: 'p', dataType: 'bytes' }, { id: 'q', dataType: 'bytes' }] },
        { id: 'vs', type: 'input-value-set', props: { rows: { out_1: { mode: 'fixed', value: 'cafe' } } },
          outputs: [{ id: 'out_1', dataType: 'bytes', name: 'Row' }, { id: 'set', dataType: 'set', name: 'Set' }] },
        { id: 'sw', type: 'switch', props: { activeInput: 'in_1' }, inputs: [{ id: 'in_1', dataType: 'set' }], outputs: [{ id: 'out_1', dataType: 'bytes', name: 'Row' }] },
        { id: 'sc', type: 'utility-script', props: { code: 'y = x << 1\n' }, inputs: [{ id: 'x', dataType: 'bytes' }], outputs: [{ id: 'y', dataType: 'bytes' }] },
        { id: 'out', type: 'workflow-output', inputs: [{ id: 'joined', dataType: 'bytes' }, { id: 'row', dataType: 'bytes' }, { id: 'shifted', dataType: 'bytes' }] },
      ],
      edges: [
        { from: 'in.a', to: 'cat.p' },
        { from: 'in.b', to: 'cat.q' },
        { from: 'cat.combined', to: 'out.joined' },
        { from: 'vs.set', to: 'sw.in_1' },
        { from: 'sw.out_1', to: 'out.row' },
        { from: 'in.a', to: 'sc.x' },
        { from: 'sc.y', to: 'out.shifted' },
      ],
    });
    expect(wf.nodes.find((n) => n.id === 'in').data.outputs[1]).toEqual({ id: 'b', name: 'B', dataType: 'bytes' });
    const o = await run(wf, { in: { a: new Uint8Array([1]), b: new Uint8Array([2, 3]) } });
    expect(hex(o.out.joined)).toBe('010203');
    expect(hex(o.out.row)).toBe('cafe');
    expect(hex(o.out.shifted)).toBe('02');
  });

  it('a Switch with two sets runs on the active one only', async () => {
    const vs = (id: string, value: string) => ({
      id, type: 'input-value-set', props: { rows: { out_1: { mode: 'fixed', value } } },
      outputs: [{ id: 'out_1', dataType: 'bytes', name: 'Row' }, { id: 'set', dataType: 'set', name: 'Set' }],
    });
    const wf = expand({
      draft: 1,
      name: 'switch',
      nodes: [
        vs('a', 'aa'), vs('b', 'bb'),
        { id: 'sw', type: 'switch', props: { activeInput: 'in_2' }, inputs: [{ id: 'in_1', dataType: 'set' }, { id: 'in_2', dataType: 'set' }], outputs: [{ id: 'out_1', dataType: 'bytes', name: 'Row' }] },
      ],
      edges: [{ from: 'a.set', to: 'sw.in_1' }, { from: 'b.set', to: 'sw.in_2' }],
    });
    expect(hex((await run(wf)).sw.out_1)).toBe('bb');
  });

  it('the expanded package passes validatePackage and a variables block makes it closed', () => {
    const r = draftToPackage(cmacDraft());
    expect(r.ok && validatePackage(r.package, known)).toBeNull();
    expect(r.ok && r.package.formatVersion).toBe(1);
    expect(r.ok && r.package.variables).toBeUndefined();
    const closed = draftToPackage({ ...cmacDraft(), variables: {} });
    expect(closed.ok && closed.package.variables).toEqual({});
  });

  it('auto layout: columns follow stages, nodes do not overlap, positioned nodes stay', () => {
    const d: any = cmacDraft();
    d.nodes[0].position = { x: 16, y: 32 };
    const wf = expand(d);
    expect(wf.nodes.find((n) => n.id === 'key').position).toEqual({ x: 16, y: 32 });
    const pos = wf.nodes.map((n) => `${n.position.x},${n.position.y}`);
    expect(new Set(pos).size).toBe(pos.length);
    for (const n of wf.nodes) expect(n.position.x % 16 === 0 && n.position.y % 16 === 0).toBe(true);
    const x = (id: string) => wf.nodes.find((n) => n.id === id).position.x;
    for (const e of wf.edges) expect(x(e.source)).toBeLessThan(x(e.target));
    expect(x('zero')).toBe(64);
    expect(x('sub')).toBe(64 + 400 * 2);
  });

  it('reports expansion problems with path and hint', () => {
    const r = expandDraft({
      draft: 1,
      name: 'bad',
      extra: 1,
      nodes: [
        { id: 'a', type: 'symmetric-aes-encrypt' },
        { id: 'a', type: 'symmetric-aes-encrypt' },
        { id: 'b', type: 'symmetric-aes-encrpt' },
        { id: 'c', type: 'link' },
        { id: 'd', type: 'utility-concat' },
      ],
      edges: [{ from: 'a', to: 'a.key' }, { from: 'zz.out', to: 'a.key' }],
    });
    expect(r.ok).toBe(false);
    if (r.ok) return;
    const by = Object.fromEntries(r.issues.map((i) => [i.code, i]));
    expect(by.DRAFT_UNKNOWN_FIELD.path).toBe('extra');
    expect(by.NODE_ID_DUPLICATE.path).toBe('nodes[1].id');
    expect(by.NODE_TYPE_UNKNOWN.hint).toContain('symmetric-aes-encrypt');
    expect(by.NODE_TYPE_NOT_ALLOWED.path).toBe('nodes[3].type');
    expect(by.PORT_LIST_REQUIRED.path).toBe('nodes[4].inputs');
    expect(by.EDGE_BAD_REFERENCE.path).toBe('edges[0].from');
    expect(by.EDGE_NODE_UNKNOWN.path).toBe('edges[1].from');
    expect(by.EDGE_NODE_UNKNOWN.msg.key).toBe('errors:authoring.EDGE_NODE_UNKNOWN');
  });

  describe('node memo (authoring.md §2.2, D-13)', () => {
    const base = (note: unknown) => ({
      draft: 1,
      name: 'n',
      nodes: [{ id: 'h', type: 'hash-digest', props: { algorithm: 'SHA-256' }, note }],
    });

    it('a note becomes data.note and does not touch the properties', () => {
      const wf = expand(base('# Why\nbecause `x`'));
      expect(wf.nodes[0].data.note).toBe('# Why\nbecause `x`');
      expect(wf.nodes[0].data.properties).not.toHaveProperty('note');
    });

    it('a blank note leaves no field', () => {
      expect('note' in expand(base('  \n ')).nodes[0].data).toBe(false);
    });

    it('a non-string or an over-long note is DRAFT_BAD_STRUCTURE at nodes[i].note', () => {
      for (const bad of [5, { a: 1 }, 'x'.repeat(20001)]) {
        const r = expandDraft(base(bad));
        expect(r.ok).toBe(false);
        if (r.ok) continue;
        expect(r.issues.map((i) => [i.code, i.path])).toEqual([['DRAFT_BAD_STRUCTURE', 'nodes[0].note']]);
      }
      expect(expandDraft(base('x'.repeat(20000))).ok).toBe(true);
    });

    it('survives into the package and the package validates', () => {
      const r = draftToPackage(base('memo'));
      expect(r.ok).toBe(true);
      if (!r.ok) return;
      expect(r.package.workflow.nodes[0].data.note).toBe('memo');
      expect(validatePackage(JSON.parse(JSON.stringify(r.package)), known)).toBeNull();
    });
  });
  describe('portNames (authoring.md §2.2)', () => {
    const named = () => {
      const d: any = cmacDraft();
      d.nodes[2].portNames = { plaintext: 'Zero Block', ciphertext: 'Zero Block', key: 'Session Key' };
      return d;
    };

    it('renames only the name; id, order and dataType stay, and the package validates', () => {
      const plain = expand(cmacDraft()).nodes.find((n: any) => n.id === 'aes').data;
      const d: any = named();
      const w = expand(d).nodes.find((n: any) => n.id === 'aes').data;
      const strip = (l: any[]) => l.map(({ name, ...p }) => p);
      expect(strip(w.inputs)).toEqual(strip(plain.inputs));
      expect(strip(w.outputs)).toEqual(strip(plain.outputs));
      expect(w.inputs.find((p: any) => p.id === 'key').name).toBe('Session Key');
      expect(w.inputs.find((p: any) => p.id === 'plaintext').name).toBe('Zero Block');
      expect(w.outputs.find((p: any) => p.id === 'ciphertext').name).toBe('Zero Block'); // same name on both sides is fine
      const r = draftToPackage(d);
      expect(r.ok).toBe(true);
      if (r.ok) expect(validatePackage(JSON.parse(JSON.stringify(r.package)), known)).toBeNull();
    });

    it('does not change the run result', async () => {
      const out = (d: any) => run(expand(d));
      const [a, b] = [await out(cmacDraft()), await out(named())];
      expect(JSON.stringify(b)).toBe(JSON.stringify(a));
    });

    it('a portNames that is not an object is DRAFT_BAD_STRUCTURE', () => {
      const d: any = cmacDraft();
      d.nodes[2].portNames = ['key'];
      const r = expandDraft(d);
      expect(r.ok ? [] : r.issues.map((i) => [i.code, i.path])).toEqual([['DRAFT_BAD_STRUCTURE', 'nodes[2].portNames']]);
    });
  });
});
