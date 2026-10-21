import { describe, it, expect } from 'vitest';
import { DAGRunner } from 'nodecrypto-engine/dag/runner';
import { defaultNodeRegistry } from 'nodecrypto-engine/registry/nodeRegistry';

describe('Symmetric node fixed error catalog (T04)', () => {
  const registry = defaultNodeRegistry.getMap();

  it('surfaces INVALID_KEY_LENGTH for a wrong-length AES key', async () => {
    const nodes = [
      { id: 'key', type: 'input-static-value', properties: { type: 'bytes', valueBytes: 'aabb' } },
      { id: 'pt', type: 'input-static-value', properties: { type: 'bytes', valueBytes: '00112233445566778899aabbccddeeff' } },
      { id: 'enc', type: 'symmetric-aes-encrypt', properties: { mode: 'ECB', padding: 'PKCS7' } },
    ];
    const edges = [
      { id: 'e1', source: 'pt', sourceHandle: 'value', target: 'enc', targetHandle: 'plaintext' },
      { id: 'e2', source: 'key', sourceHandle: 'value', target: 'enc', targetHandle: 'key' },
    ];
    const result = await DAGRunner.execute(nodes, edges, registry);
    expect(result.nodeStates['enc'].status).toBe('error');
    expect(result.nodeStates['enc'].errorCode).toBe('INVALID_KEY_LENGTH');
    expect(result.taskError?.nodeId).toBe('enc');
  });

  it('surfaces AUTH_TAG_MISMATCH when an AES-GCM tag is tampered with', async () => {
    const nodes = [
      { id: 'key', type: 'input-static-value', properties: { type: 'bytes', valueBytes: '00000000000000000000000000000000' } },
      { id: 'ct', type: 'input-static-value', properties: { type: 'bytes', valueBytes: '00' } },
      { id: 'tag', type: 'input-static-value', properties: { type: 'bytes', valueBytes: 'ffffffffffffffffffffffffffffffff' } },
      { id: 'dec', type: 'symmetric-aes-decrypt', properties: { mode: 'GCM' } },
    ];
    const edges = [
      { id: 'e1', source: 'ct', sourceHandle: 'value', target: 'dec', targetHandle: 'ciphertext' },
      { id: 'e2', source: 'key', sourceHandle: 'value', target: 'dec', targetHandle: 'key' },
      { id: 'e3', source: 'tag', sourceHandle: 'value', target: 'dec', targetHandle: 'tag' },
    ];
    const result = await DAGRunner.execute(nodes, edges, registry);
    expect(result.nodeStates['dec'].status).toBe('error');
    expect(result.nodeStates['dec'].errorCode).toBe('AUTH_TAG_MISMATCH');
  });

  it('surfaces INVALID_PADDING for a corrupted PKCS7 block', async () => {
    const nodes = [
      { id: 'data', type: 'input-static-value', properties: { type: 'bytes', valueBytes: '0102030405060708090a0b0c0d0e0f11' } },
      { id: 'unpad', type: 'padding-block-unpad', properties: { paddingType: 'PKCS7', blockSize: 16 } },
    ];
    const edges = [
      { id: 'e1', source: 'data', sourceHandle: 'value', target: 'unpad', targetHandle: 'data' },
    ];
    const result = await DAGRunner.execute(nodes, edges, registry);
    expect(result.nodeStates['unpad'].status).toBe('error');
    expect(result.nodeStates['unpad'].errorCode).toBe('INVALID_PADDING');
  });

  it('applies the errorUnify override in place of the built-in code/message', async () => {
    const nodes = [
      { id: 'key', type: 'input-static-value', properties: { type: 'bytes', valueBytes: 'aa' } },
      { id: 'pt', type: 'input-static-value', properties: { type: 'bytes', valueBytes: '0011223344556677' } },
      {
        id: 'des',
        type: 'symmetric-des-encrypt',
        properties: { mode: 'ECB', padding: 'PKCS7', errorUnify: true, errorUnifyCode: 'DES_BAD_KEY', errorUnifyMessage: '키가 8바이트가 아닙니다' },
      },
    ];
    const edges = [
      { id: 'e1', source: 'key', sourceHandle: 'value', target: 'des', targetHandle: 'key' },
      { id: 'e2', source: 'pt', sourceHandle: 'value', target: 'des', targetHandle: 'plaintext' },
    ];
    const result = await DAGRunner.execute(nodes, edges, registry);
    expect(result.nodeStates['des'].status).toBe('error');
    expect(result.nodeStates['des'].errorCode).toBe('DES_BAD_KEY');
    expect(result.nodeStates['des'].errorMessage).toBe('키가 8바이트가 아닙니다');
  });

  it('does not unify errors when errorUnify is off (default)', async () => {
    const nodes = [
      { id: 'key', type: 'input-static-value', properties: { type: 'bytes', valueBytes: 'aa' } },
      { id: 'pt', type: 'input-static-value', properties: { type: 'bytes', valueBytes: '0011223344556677' } },
      { id: 'des', type: 'symmetric-des-encrypt', properties: { mode: 'ECB', padding: 'PKCS7' } },
    ];
    const edges = [
      { id: 'e1', source: 'key', sourceHandle: 'value', target: 'des', targetHandle: 'key' },
      { id: 'e2', source: 'pt', sourceHandle: 'value', target: 'des', targetHandle: 'plaintext' },
    ];
    const result = await DAGRunner.execute(nodes, edges, registry);
    expect(result.nodeStates['des'].errorCode).toBe('INVALID_KEY_LENGTH');
  });
});
