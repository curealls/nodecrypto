import { describe, it, expect } from 'vitest';
import { DAGRunner } from '../../src/dag/runner';
import { defaultNodeRegistry } from '../../src/registry/nodeRegistry';
import { bytesToHex } from '@noble/hashes/utils.js';

// authoring.md §2.3: a node read from a file has no showWhen functions; hidden required inputs must not count as missing.
describe('hidden required inputs of a node read from a file', () => {
  const def = defaultNodeRegistry.get('padding-asymmetric')!;
  const stripped = () => JSON.parse(JSON.stringify(def.inputs)); // what a .ncw carries: ports without showWhen
  const hash = '00'.repeat(32);

  it('PSS-Encode needs only Message Hash (Message and Encoded Message are hidden)', async () => {
    const nodes = [
      { id: 'h', type: 'input-static-value', properties: { type: 'bytes', valueBytes: hash } },
      { id: 'p', type: 'padding-asymmetric', properties: { scheme: 'PSS-Encode', targetLength: 128, saltLength: 32 }, inputs: stripped() },
    ];
    const r = await DAGRunner.execute(nodes as any, [{ id: 'e', source: 'h', sourceHandle: 'value', target: 'p', targetHandle: 'mHash' }], defaultNodeRegistry);
    expect(r.success).toBe(true);
    expect(bytesToHex(r.nodeOutputs.p.result).length).toBe(256);
  });

  it('a visible required input that is not connected is still reported', async () => {
    const nodes = [{ id: 'p', type: 'padding-asymmetric', properties: { scheme: 'PSS-Encode', targetLength: 128 }, inputs: stripped() }];
    const r = await DAGRunner.execute(nodes as any, [], defaultNodeRegistry);
    expect(r.success).toBe(false);
    expect(r.nodeStates.p.errorMessage).toContain('Message Hash');
    expect(r.nodeStates.p.errorMessage).not.toContain('Encoded Message');
  });
});
