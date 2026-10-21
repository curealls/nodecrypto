import { describe, it, expect } from 'vitest';
import { buildTaskResponse } from 'nodecrypto-engine/dag/taskResponse';

describe('buildTaskResponse (api-spec §2.1/§2.2)', () => {
  const exit = {
    inputs: [{ id: 'p1', name: 'ciphertext' }, { id: 'p2', name: 'ok' }],
    outputValues: { p1: new Uint8Array([0xa1, 0x0b]), p2: true },
  };

  it('success maps Task Exit port names to hex/raw values', () => {
    expect(buildTaskResponse([exit], null, 2.4)).toEqual({
      status: 'success',
      executionTimeMs: 2.4,
      outputs: { ciphertext: 'a10b', ok: true },
    });
  });

  it('error drops outputs entirely (D-05)', () => {
    const err = { nodeId: 'n3', code: 'INVALID_KEY_LENGTH', message: 'bad key' };
    expect(buildTaskResponse([exit], err, 1)).toEqual({ status: 'error', error: err });
  });
});
