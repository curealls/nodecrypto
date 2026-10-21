import { describe, it, expect } from 'vitest';
import { DAGScheduler } from 'nodecrypto-engine/dag/scheduler';
import { DAGEdgeConnection } from 'nodecrypto-engine/dag/types';

describe('DAGScheduler Topological Sorting and Cycle Detection', () => {
  it('schedules a linear 3-node pipeline sequentially', () => {
    const nodes = ['node-1', 'node-2', 'node-3'];
    const edges: DAGEdgeConnection[] = [
      { id: 'e1', source: 'node-1', sourceHandle: 'out', target: 'node-2', targetHandle: 'in' },
      { id: 'e2', source: 'node-2', sourceHandle: 'out', target: 'node-3', targetHandle: 'in' },
    ];

    const plan = DAGScheduler.schedule(nodes, edges);

    expect(plan.hasCycle).toBe(false);
    expect(plan.order).toEqual(['node-1', 'node-2', 'node-3']);
    expect(plan.stages).toEqual([['node-1'], ['node-2'], ['node-3']]);
  });

  it('partitions diamond branching graph into 3 parallel stages', () => {
    // A -> B, A -> C, B -> D, C -> D
    const nodes = ['A', 'B', 'C', 'D'];
    const edges: DAGEdgeConnection[] = [
      { id: 'e1', source: 'A', sourceHandle: 'out', target: 'B', targetHandle: 'in' },
      { id: 'e2', source: 'A', sourceHandle: 'out', target: 'C', targetHandle: 'in' },
      { id: 'e3', source: 'B', sourceHandle: 'out', target: 'D', targetHandle: 'in1' },
      { id: 'e4', source: 'C', sourceHandle: 'out', target: 'D', targetHandle: 'in2' },
    ];

    const plan = DAGScheduler.schedule(nodes, edges);

    expect(plan.hasCycle).toBe(false);
    expect(plan.stages.length).toBe(3);
    expect(plan.stages[0]).toEqual(['A']);
    // B and C can be executed concurrently in Stage 1
    expect(new Set(plan.stages[1])).toEqual(new Set(['B', 'C']));
    expect(plan.stages[2]).toEqual(['D']);
  });

  it('detects cyclical dependency and identifies cycle nodes', () => {
    // A -> B -> C -> A
    const nodes = ['A', 'B', 'C'];
    const edges: DAGEdgeConnection[] = [
      { id: 'e1', source: 'A', sourceHandle: 'out', target: 'B', targetHandle: 'in' },
      { id: 'e2', source: 'B', sourceHandle: 'out', target: 'C', targetHandle: 'in' },
      { id: 'e3', source: 'C', sourceHandle: 'out', target: 'A', targetHandle: 'in' },
    ];

    const plan = DAGScheduler.schedule(nodes, edges);

    expect(plan.hasCycle).toBe(true);
    expect(plan.order).toEqual([]);
    expect(new Set(plan.cycleNodes)).toEqual(new Set(['A', 'B', 'C']));
  });

  it('extracts upstream ancestor dependencies for sub-graph execution', () => {
    // Root1 -> Mid1 -> Target
    // Root2 -> Mid2 -> Target
    // Independent
    const edges: DAGEdgeConnection[] = [
      { id: 'e1', source: 'Root1', sourceHandle: 'out', target: 'Mid1', targetHandle: 'in' },
      { id: 'e2', source: 'Mid1', sourceHandle: 'out', target: 'Target', targetHandle: 'in1' },
      { id: 'e3', source: 'Root2', sourceHandle: 'out', target: 'Mid2', targetHandle: 'in' },
      { id: 'e4', source: 'Mid2', sourceHandle: 'out', target: 'Target', targetHandle: 'in2' },
      { id: 'e5', source: 'Independent', sourceHandle: 'out', target: 'Other', targetHandle: 'in' },
    ];

    const ancestors = DAGScheduler.getAncestors('Target', edges);
    expect(new Set(ancestors)).toEqual(new Set(['Root1', 'Mid1', 'Root2', 'Mid2']));
    expect(ancestors).not.toContain('Independent');
    expect(ancestors).not.toContain('Other');
  });
});
