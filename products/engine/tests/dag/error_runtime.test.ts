import { describe, it, expect } from 'vitest';
import { DAGRunner } from 'nodecrypto-engine/dag/runner';
import { NodeError } from 'nodecrypto-engine/dag/errors';
import { NodeDefinition } from 'nodecrypto-engine/dag/types';

function def(overrides: Partial<NodeDefinition> & Pick<NodeDefinition, 'type' | 'execute'>): NodeDefinition {
  return {
    label: overrides.type,
    category: 'utility',
    description: '',
    inputs: [],
    outputs: [],
    propertySchema: [],
    ...overrides,
  };
}

const okNode = def({
  type: 'ok',
  execute: async () => ({ value: 1 }),
});

const throwingNode = def({
  type: 'throwing',
  errorProfile: { kind: 'fixed', cases: [{ code: 'BAD_INPUT', message: 'bad input' }] },
  execute: async () => {
    throw new NodeError('BAD_INPUT', 'bad input');
  },
});

const judgementNode = def({
  type: 'judgement',
  outputs: [{ id: 'result', name: 'Result', dataType: 'bool' }],
  errorProfile: { kind: 'judgement', port: 'result' },
  execute: async () => ({ result: true }),
});

const registry = new Map([
  ['ok', okNode],
  ['throwing', throwingNode],
  ['judgement', judgementNode],
]);

describe('DAGRunner error runtime infrastructure (T03)', () => {
  it('runs a normal graph to success with no taskError', async () => {
    const result = await DAGRunner.execute([{ id: 'n1', type: 'ok' }], [], registry);
    expect(result.success).toBe(true);
    expect(result.nodeStates['n1'].status).toBe('success');
    expect(result.taskError).toBeUndefined();
  });

  it('captures a built-in NodeError code and sets taskError', async () => {
    const result = await DAGRunner.execute([{ id: 'n1', type: 'throwing' }], [], registry);
    expect(result.nodeStates['n1'].status).toBe('error');
    expect(result.nodeStates['n1'].errorCode).toBe('BAD_INPUT');
    expect(result.taskError).toEqual({ nodeId: 'n1', code: 'BAD_INPUT', message: 'bad input' });
  });

  it('reinterprets a judgement success as an error when it matches errorOnValue', async () => {
    const result = await DAGRunner.execute(
      [{ id: 'n1', type: 'judgement', properties: { errorOnValue: 'true' } }],
      [],
      registry
    );
    expect(result.nodeStates['n1'].status).toBe('error');
    expect(result.nodeStates['n1'].errorCode).toBe('JUDGEMENT_JUDGEMENT_FAILED');
    expect(result.taskError?.nodeId).toBe('n1');
  });

  it('picks the earliest-scheduled node when two independent branches fail at once', async () => {
    const result = await DAGRunner.execute(
      [
        { id: 'a', type: 'throwing' },
        { id: 'b', type: 'throwing' },
      ],
      [],
      registry
    );
    expect(result.taskError?.nodeId).toBe('a');
  });

  it('marks chained skips and excludes them from taskError selection', async () => {
    const result = await DAGRunner.execute(
      [
        { id: 'src', type: 'throwing' },
        { id: 'dependent', type: 'ok' },
      ],
      [{ id: 'e1', source: 'src', sourceHandle: 'value', target: 'dependent', targetHandle: 'value' }],
      registry
    );
    expect(result.nodeStates['dependent'].skipped).toBe(true);
    expect(result.taskError?.nodeId).toBe('src');
  });
});
