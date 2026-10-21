import { describe, it, expect } from 'vitest';
import { DAGRunner } from 'nodecrypto-engine/dag/runner';
import { defaultNodeRegistry } from 'nodecrypto-engine/registry/nodeRegistry';
import { ed25519GenerateKeyPair, ed25519Sign } from 'nodecrypto-engine/crypto/asymmetric/ed25519';
import { bytesToHex } from 'nodecrypto-engine/crypto/utils/encoding';

describe('Judgement node error catalog (T05)', () => {
  const registry = defaultNodeRegistry.getMap();

  it('Value Comparator stays SUCCESS with a pure-data result when errorOnValue is unset (default)', async () => {
    const nodes = [
      { id: 'a', type: 'input-static-value', properties: { type: 'string', valueString: 'x' } },
      { id: 'b', type: 'input-static-value', properties: { type: 'string', valueString: 'y' } },
      { id: 'cmp', type: 'utility-compare', properties: { operator: '==' } },
    ];
    const edges = [
      { id: 'e1', source: 'a', sourceHandle: 'value', target: 'cmp', targetHandle: 'a' },
      { id: 'e2', source: 'b', sourceHandle: 'value', target: 'cmp', targetHandle: 'b' },
    ];
    const result = await DAGRunner.execute(nodes, edges, registry);
    expect(result.nodeStates['cmp'].status).toBe('success');
    expect(result.nodeStates['cmp'].outputs.result).toBe(false);
    expect(result.taskError).toBeUndefined();
  });

  it('reinterprets Value Comparator as ERROR when result matches errorOnValue=false, and skips downstream', async () => {
    const nodes = [
      { id: 'a', type: 'input-static-value', properties: { type: 'string', valueString: 'x' } },
      { id: 'b', type: 'input-static-value', properties: { type: 'string', valueString: 'y' } },
      { id: 'cmp', type: 'utility-compare', properties: { operator: '==', errorOnValue: 'false' } },
      { id: 'downstream', type: 'output-inspector', properties: {} },
    ];
    const edges = [
      { id: 'e1', source: 'a', sourceHandle: 'value', target: 'cmp', targetHandle: 'a' },
      { id: 'e2', source: 'b', sourceHandle: 'value', target: 'cmp', targetHandle: 'b' },
      { id: 'e3', source: 'cmp', sourceHandle: 'result', target: 'downstream', targetHandle: 'data' },
    ];
    const result = await DAGRunner.execute(nodes, edges, registry);
    expect(result.nodeStates['cmp'].status).toBe('error');
    expect(result.nodeStates['cmp'].errorCode).toBe('UTILITY_COMPARE_JUDGEMENT_FAILED');
    expect(result.nodeStates['cmp'].skipped).toBeUndefined();
    expect(result.nodeStates['downstream'].status).toBe('error');
    expect(result.nodeStates['downstream'].skipped).toBe(true);
    expect(result.taskError?.nodeId).toBe('cmp');
  });

  it('uses the user-supplied code/message when both are set', async () => {
    const nodes = [
      { id: 'a', type: 'input-static-value', properties: { type: 'string', valueString: 'same' } },
      { id: 'b', type: 'input-static-value', properties: { type: 'string', valueString: 'same' } },
      {
        id: 'cmp',
        type: 'utility-compare',
        properties: { operator: '==', errorOnValue: 'true', errorCode: 'DUPLICATE_VALUE', errorMessage: '값이 동일합니다' },
      },
    ];
    const edges = [
      { id: 'e1', source: 'a', sourceHandle: 'value', target: 'cmp', targetHandle: 'a' },
      { id: 'e2', source: 'b', sourceHandle: 'value', target: 'cmp', targetHandle: 'b' },
    ];
    const result = await DAGRunner.execute(nodes, edges, registry);
    expect(result.nodeStates['cmp'].status).toBe('error');
    expect(result.nodeStates['cmp'].errorCode).toBe('DUPLICATE_VALUE');
    expect(result.nodeStates['cmp'].errorMessage).toBe('값이 동일합니다');
  });

  it('reinterprets Ed25519 Verify as ERROR when isValid matches errorOnValue=false', async () => {
    const { publicKey } = ed25519GenerateKeyPair();
    const message = new Uint8Array([1, 2, 3]);
    const goodSig = ed25519Sign(message, ed25519GenerateKeyPair().privateKey); // signed with an unrelated key -> won't verify
    const nodes = [
      { id: 'msg', type: 'input-static-value', properties: { type: 'bytes', valueBytes: bytesToHex(message) } },
      { id: 'sig', type: 'input-static-value', properties: { type: 'bytes', valueBytes: bytesToHex(goodSig) } },
      { id: 'pk', type: 'input-static-value', properties: { type: 'bytes', valueBytes: bytesToHex(publicKey) } },
      { id: 'verify', type: 'asymmetric-ed25519-verify', properties: { errorOnValue: 'false' } },
    ];
    const edges = [
      { id: 'e1', source: 'msg', sourceHandle: 'value', target: 'verify', targetHandle: 'message' },
      { id: 'e2', source: 'sig', sourceHandle: 'value', target: 'verify', targetHandle: 'signature' },
      { id: 'e3', source: 'pk', sourceHandle: 'value', target: 'verify', targetHandle: 'publicKey' },
    ];
    const result = await DAGRunner.execute(nodes, edges, registry);
    expect(result.nodeStates['verify'].outputs.isValid).toBe(false);
    expect(result.nodeStates['verify'].status).toBe('error');
    expect(result.nodeStates['verify'].errorCode).toBe('ASYMMETRIC_ED25519_VERIFY_JUDGEMENT_FAILED');
  });
});
