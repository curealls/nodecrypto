import { describe, it, expect } from 'vitest';
import { DAGRunner } from 'nodecrypto-engine/dag/runner';
import { defaultNodeRegistry } from 'nodecrypto-engine/registry/nodeRegistry';

// execution-semantics.md §4.5: the optional beforeNodeExecute callback runs once per node, after `running` and before the computation.
const nodes = [
  { id: 'a', type: 'input-static-value', label: 'a', properties: { type: 'bytes', valueBytes: '0011' } },
  { id: 'b', type: 'converter-bytes-to-hex', label: 'b', properties: {} },
] as any[];
const out = defaultNodeRegistry.get('input-static-value')!.outputs[0].id;
const inp = defaultNodeRegistry.get('converter-bytes-to-hex')!.inputs[0].id;
const edges = [{ id: 'e', source: 'a', sourceHandle: out, target: 'b', targetHandle: inp }];
const run = (options = {}) => DAGRunner.execute(nodes, edges, defaultNodeRegistry.getMap(), options);

describe('beforeNodeExecute', () => {
  it('is called once per node, after its running status, and does not change the result', async () => {
    const events: string[] = [];
    const withCb = await run({
      onNodeStatusChange: (id: string, s: any) => events.push(`${id}:${s.status}`),
      beforeNodeExecute: async (id: string) => { events.push(`${id}:before`); await new Promise((r) => setTimeout(r, 1)); },
    });
    expect(events.filter((e) => e.endsWith(':before'))).toEqual(['a:before', 'b:before']);
    expect(events.indexOf('a:running')).toBeLessThan(events.indexOf('a:before'));
    expect(events.indexOf('a:before')).toBeLessThan(events.indexOf('a:success'));
    const plain = await run();
    expect(withCb.nodeOutputs).toEqual(plain.nodeOutputs);
    expect(withCb.order).toEqual(plain.order);
  });
});
