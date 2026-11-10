import { describe, it, expect } from 'vitest';
import { buildPackage, contentSignature } from 'nodecrypto-engine/dag/package';

const wf = (data: object) => ({
  id: 'w', name: 'w', description: '', nodes: [{ id: 'h', type: 'cryptoNode', position: { x: 0, y: 0 }, data: { nodeType: 'hash-digest', label: 'H', inputs: [], outputs: [], properties: { algorithm: 'SHA-256' }, ...data } }],
  edges: [], viewport: { x: 0, y: 0, zoom: 1 }, metadata: {},
});

describe('run state is not saved', () => {
  it('drops the run-start pending flag along with the other run results', () => {
    const pkg = buildPackage(wf({ pending: true, executionState: 'success' }) as any, { label: 'w', version: '', description: '', category: '' }, () => undefined);
    expect(pkg.workflow.nodes[0].data).not.toHaveProperty('pending');
    expect(pkg.workflow.nodes[0].data).not.toHaveProperty('executionState');
  });

  it('running alone does not mark the canvas modified', () => {
    const before = wf({});
    const ran = wf({ pending: false, executionState: 'success' });
    expect(contentSignature(ran.nodes, ran.edges)).toBe(contentSignature(before.nodes, before.edges));
  });
});
