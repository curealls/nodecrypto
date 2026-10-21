import { describe, it, expect } from 'vitest';
import { DAGRunner } from 'nodecrypto-engine/dag/runner';
import { defaultNodeRegistry } from 'nodecrypto-engine/registry/nodeRegistry';
import { bytesToHex } from 'nodecrypto-engine/crypto/utils/encoding';
import {
  computeDefinitionId, deriveInterface, registerCustomNodes, getSessionDefinition, CustomNodeDefinition,
} from 'nodecrypto-engine/dag/customNode';
import { buildPackage, validatePackage } from 'nodecrypto-engine/dag/package';

const registry = defaultNodeRegistry.getMap();
const port = (id: string, dataType: 'bytes' | 'int' | 'bool' | 'string' = 'bytes') => ({ id, name: id, dataType, required: true });

const CMAC_SUBKEYS = `def dbl(x: bytes) -> bytes:
    rb = h"00" * (len(x) - 1) + (h"87" if len(x) == 16 else h"1b")
    r = x << 1
    if x[0] & 0x80 != 0:
        r ^= rb
    return r

k1 = dbl(l)
k2 = dbl(k1)
`;

const script = (id: string, code: string, inputs: any[], outputs: any[], extra: Record<string, any> = {}) => ({
  id, type: 'utility-script', inputs, outputs,
  properties: { code, scriptVersion: 1, ...extra },
});

// Static key -> AES-ECB(zero block) -> script (RFC 4493 §4)
function cmacGraph(code = CMAC_SUBKEYS, extra: Record<string, any> = {}) {
  const nodes: any[] = [
    { id: 'key', type: 'input-static-value', properties: { type: 'bytes', valueBytes: '2b7e151628aed2a6abf7158809cf4f3c' } },
    { id: 'zero', type: 'input-static-value', properties: { type: 'bytes', valueBytes: '00000000000000000000000000000000' } },
    { id: 'aes', type: 'symmetric-aes-encrypt', properties: { mode: 'ECB', padding: 'None' } },
    script('s', code, [port('l')], [port('k1'), port('k2')], extra),
  ];
  const edges = [
    { id: 'e1', source: 'zero', sourceHandle: 'value', target: 'aes', targetHandle: 'plaintext' },
    { id: 'e2', source: 'key', sourceHandle: 'value', target: 'aes', targetHandle: 'key' },
    { id: 'e3', source: 'aes', sourceHandle: 'ciphertext', target: 's', targetHandle: 'l' },
  ];
  return { nodes, edges };
}
const run = (g: { nodes: any[]; edges: any[] }) => DAGRunner.execute(g.nodes, g.edges, registry);

describe('script node (ND-8.3)', () => {
  it('is registered empty: no ports, empty code', () => {
    const inst = defaultNodeRegistry.createNodeInstance('utility-script');
    expect(inst.data.category).toBe('utility');
    expect(inst.data.inputs.map((p) => `${p.id}:${p.dataType}`)).toEqual([]);
    expect(inst.data.outputs.map((p) => `${p.id}:${p.dataType}`)).toEqual([]);
    expect(inst.data.properties.code).toBe('');
    expect(inst.data.properties.scriptVersion).toBe(1);
  });

  it('runs a portless empty script', async () => {
    expect((await run({ nodes: [script('s', '', [], [])], edges: [] })).success).toBe(true);
  });

  it('computes the RFC 4493 CMAC subkeys', async () => {
    const r = await run(cmacGraph());
    expect(r.success).toBe(true);
    expect(bytesToHex(r.nodeOutputs.s.k1)).toBe('fbeed618357133667c85e08f7236a8de');
    expect(bytesToHex(r.nodeOutputs.s.k2)).toBe('f7ddac306ae266ccf90bc11ee46d513b');
  });

  it('passes fail(code, message) to the node error and taskError, and blocks downstream', async () => {
    const g = cmacGraph(`k1 = l\nk2 = l\nif len(l) == 16:\n    fail("MY_CODE", "boom")\n`);
    g.nodes.push({ id: 'down', type: 'converter-bytes-to-hex', properties: {} });
    g.edges.push({ id: 'e4', source: 's', sourceHandle: 'k1', target: 'down', targetHandle: 'bytes' });
    const r = await run(g);
    expect(r.nodeStates.s).toMatchObject({ status: 'error', errorCode: 'MY_CODE', errorMessage: 'boom' });
    expect(r.taskError).toEqual({ nodeId: 's', code: 'MY_CODE', message: 'boom' });
    expect(r.nodeStates.down).toMatchObject({ status: 'error', skipped: true });
  });

  it('reports built-in runtime errors by code', async () => {
    const r = await run(cmacGraph(`k1 = l ^ h"00"\nk2 = l\n`));
    expect(r.nodeStates.s.errorCode).toBe('BYTES_LENGTH_MISMATCH');
  });

  it('turns a failed static check or unknown scriptVersion into SCRIPT_COMPILE_ERROR', async () => {
    const bad = await run(cmacGraph(`k1 = nope\nk2 = l\n`));
    expect(bad.nodeStates.s.errorCode).toBe('SCRIPT_COMPILE_ERROR');
    const ver = await run(cmacGraph(CMAC_SUBKEYS, { scriptVersion: 99 }));
    expect(ver.nodeStates.s.errorCode).toBe('SCRIPT_COMPILE_ERROR');
  });

  it('applies "unify" to every script error', async () => {
    const r = await run(cmacGraph(`k1 = l ^ h"00"\nk2 = l\n`, { errorUnify: true, errorUnifyCode: 'U', errorUnifyMessage: 'unified' }));
    expect(r.taskError).toEqual({ nodeId: 's', code: 'U', message: 'unified' });
  });

  it('carries ints beyond 2^64 between nodes without losing precision', async () => {
    const nodes = [
      { id: 'n', type: 'input-static-value', properties: { type: 'int', valueInt: 4294967296 } }, // 2^32
      script('a', 'm = n * n * n * n\nsmall = n // 2\n', [port('n', 'int')], [port('m', 'int'), port('small', 'int')]),
      script('b', 'y = x == 340282366920938463463374607431768211456\n', [port('x', 'int')], [port('y', 'bool')]),
    ];
    const edges = [
      { id: 'e1', source: 'n', sourceHandle: 'value', target: 'a', targetHandle: 'n' },
      { id: 'e2', source: 'a', sourceHandle: 'm', target: 'b', targetHandle: 'x' },
    ];
    const r = await DAGRunner.execute(nodes, edges, registry);
    expect(r.success).toBe(true);
    expect(r.nodeOutputs.a.m).toBe(2n ** 128n); // outside the safe range: bigint
    expect(r.nodeOutputs.a.small).toBe(2147483648); // inside: number
    expect(r.nodeOutputs.b.y).toBe(true);
  });
});

describe('script node in packages', () => {
  const def = (code: string): CustomNodeDefinition => {
    const nodes: any[] = [
      { id: 'wi', type: 'cryptoNode', position: { x: 0, y: 0 }, data: { nodeType: 'workflow-input', outputs: [port('in')], properties: {} } },
      { id: 's', type: 'cryptoNode', position: { x: 0, y: 0 }, data: { nodeType: 'utility-script', inputs: [port('in1')], outputs: [port('out1')], properties: { code, scriptVersion: 1 } } },
      { id: 'wo', type: 'cryptoNode', position: { x: 0, y: 0 }, data: { nodeType: 'workflow-output', inputs: [port('out')], properties: {} } },
    ];
    const edges = [
      { id: 'e1', source: 'wi', sourceHandle: 'in', target: 's', targetHandle: 'in1' },
      { id: 'e2', source: 's', sourceHandle: 'out1', target: 'wo', targetHandle: 'out' },
    ];
    return { manifest: { label: 'S', version: '', description: '', category: 'Lib', ...deriveInterface(nodes) }, workflow: { nodes, edges } };
  };

  it('gives CRLF and LF code the same identifier, and different code a different one', () => {
    const lf = computeDefinitionId(def('x = in1\nout1 = x\n'));
    expect(computeDefinitionId(def('x = in1\r\nout1 = x\r\n'))).toBe(lf);
    expect(computeDefinitionId(def('x = in1\rout1 = x\r'))).toBe(lf);
    expect(computeDefinitionId(def('out1 = in1\n'))).not.toBe(lf);
  });

  it('round-trips a custom node containing a script node through save and open', async () => {
    const d = def('out1 = in1 ^ in1\n');
    const id = computeDefinitionId(d);
    registerCustomNodes({ [id]: d });
    const body = {
      name: 'W',
      nodes: [{ id: 'c', type: 'cryptoNode', position: { x: 0, y: 0 }, data: { nodeType: id, inputs: [port('in')], outputs: [port('out')], properties: {} } }],
      edges: [],
    };
    const pkg = buildPackage(body, { label: 'T', version: '1', description: '', category: 'Lib' }, getSessionDefinition);
    expect(Object.keys(pkg.definitions)).toEqual([id]);
    expect(validatePackage(JSON.parse(JSON.stringify(pkg)), new Set(registry.keys()))).toBeNull();
    const r = await DAGRunner.execute(
      [{ id: 'k', type: 'input-static-value', properties: { type: 'bytes', valueBytes: 'aabb' } }, { id: 'c', type: id, inputs: [port('in')], outputs: [port('out')] }],
      [{ id: 'e', source: 'k', sourceHandle: 'value', target: 'c', targetHandle: 'in' }],
      defaultNodeRegistry.getMap(),
    );
    expect(r.success).toBe(true);
    expect(bytesToHex(r.nodeOutputs.c.out)).toBe('0000');
  });
});
