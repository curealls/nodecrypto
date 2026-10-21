import { describe, it, expect } from 'vitest';
import { DAGRunner } from 'nodecrypto-engine/dag/runner';
import { defaultNodeRegistry } from 'nodecrypto-engine/registry/nodeRegistry';

describe('Remaining node fixed error catalog (T06)', () => {
  const registry = defaultNodeRegistry.getMap();

  it('surfaces INVALID_HEX_CHAR for a non-hex string in Hex to Bytes', async () => {
    const nodes = [
      { id: 'in', type: 'input-static-value', properties: { type: 'string', valueString: 'zz' } },
      { id: 'hex', type: 'converter-hex-to-bytes', properties: {} },
    ];
    const edges = [{ id: 'e1', source: 'in', sourceHandle: 'value', target: 'hex', targetHandle: 'string' }];
    const result = await DAGRunner.execute(nodes, edges, registry);
    expect(result.nodeStates['hex'].status).toBe('error');
    expect(result.nodeStates['hex'].errorCode).toBe('INVALID_HEX_CHAR');
  });

  it('surfaces INVALID_BASE64_INPUT for an invalid Base64 string', async () => {
    const nodes = [
      { id: 'in', type: 'input-static-value', properties: { type: 'string', valueString: '!!!!' } },
      { id: 'b64', type: 'converter-base64-to-bytes', properties: {} },
    ];
    const edges = [{ id: 'e1', source: 'in', sourceHandle: 'value', target: 'b64', targetHandle: 'string' }];
    const result = await DAGRunner.execute(nodes, edges, registry);
    expect(result.nodeStates['b64'].status).toBe('error');
    expect(result.nodeStates['b64'].errorCode).toBe('INVALID_BASE64_INPUT');
  });

  it('surfaces INVALID_BASE58_CHAR for a string containing "0" (excluded from the Base58 alphabet)', async () => {
    const nodes = [
      { id: 'in', type: 'input-static-value', properties: { type: 'string', valueString: '0' } },
      { id: 'b58', type: 'converter-base58-to-bytes', properties: {} },
    ];
    const edges = [{ id: 'e1', source: 'in', sourceHandle: 'value', target: 'b58', targetHandle: 'string' }];
    const result = await DAGRunner.execute(nodes, edges, registry);
    expect(result.nodeStates['b58'].status).toBe('error');
    expect(result.nodeStates['b58'].errorCode).toBe('INVALID_BASE58_CHAR');
  });

  it('surfaces UNSUPPORTED_MULTIBASE_PREFIX for an unrecognized Multibase prefix', async () => {
    const nodes = [
      { id: 'in', type: 'input-static-value', properties: { type: 'string', valueString: 'qx' } },
      { id: 'mb', type: 'converter-multibase-to-bytes', properties: {} },
    ];
    const edges = [{ id: 'e1', source: 'in', sourceHandle: 'value', target: 'mb', targetHandle: 'string' }];
    const result = await DAGRunner.execute(nodes, edges, registry);
    expect(result.nodeStates['mb'].status).toBe('error');
    expect(result.nodeStates['mb'].errorCode).toBe('UNSUPPORTED_MULTIBASE_PREFIX');
  });

  it('surfaces INVALID_KEY_LENGTH for a wrong-length CMAC key', async () => {
    const nodes = [
      { id: 'data', type: 'input-static-value', properties: { type: 'bytes', valueBytes: '00112233' } },
      { id: 'key', type: 'input-static-value', properties: { type: 'bytes', valueBytes: 'aa' } },
      { id: 'cmac', type: 'mac-cmac', properties: { cipher: 'AES' } },
    ];
    const edges = [
      { id: 'e1', source: 'data', sourceHandle: 'value', target: 'cmac', targetHandle: 'data' },
      { id: 'e2', source: 'key', sourceHandle: 'value', target: 'cmac', targetHandle: 'key' },
    ];
    const result = await DAGRunner.execute(nodes, edges, registry);
    expect(result.nodeStates['cmac'].status).toBe('error');
    expect(result.nodeStates['cmac'].errorCode).toBe('INVALID_KEY_LENGTH');
  });

  it('surfaces INVALID_KDF_PARAMS for zero PBKDF2 iterations', async () => {
    const nodes = [
      { id: 'pw', type: 'input-static-value', properties: { type: 'bytes', valueBytes: '00112233' } },
      { id: 'kdf', type: 'kdf-pbkdf2', properties: { iterations: -1, keyLength: 32 } },
    ];
    const edges = [{ id: 'e1', source: 'pw', sourceHandle: 'value', target: 'kdf', targetHandle: 'password' }];
    const result = await DAGRunner.execute(nodes, edges, registry);
    expect(result.nodeStates['kdf'].status).toBe('error');
    expect(result.nodeStates['kdf'].errorCode).toBe('INVALID_KDF_PARAMS');
  });

  it('surfaces INVALID_CRC_PARAMETER for a malformed custom CRC polynomial', async () => {
    const nodes = [
      { id: 'data', type: 'input-static-value', properties: { type: 'bytes', valueBytes: '00112233' } },
      { id: 'crc', type: 'utility-crc', properties: { preset: 'custom', customPoly: 'ZZZZ' } },
    ];
    const edges = [{ id: 'e1', source: 'data', sourceHandle: 'value', target: 'crc', targetHandle: 'data' }];
    const result = await DAGRunner.execute(nodes, edges, registry);
    expect(result.nodeStates['crc'].status).toBe('error');
    expect(result.nodeStates['crc'].errorCode).toBe('INVALID_CRC_PARAMETER');
  });

  it('surfaces INVALID_KEY_MATERIAL for a too-short ECC private key', async () => {
    const nodes = [
      { id: 'data', type: 'input-static-value', properties: { type: 'bytes', valueBytes: '00112233' } },
      { id: 'key', type: 'input-static-value', properties: { type: 'bytes', valueBytes: 'aabbccddee' } },
      { id: 'sign', type: 'asymmetric-ecc-sign', properties: { curve: 'p256', autoHash: true } },
    ];
    const edges = [
      { id: 'e1', source: 'data', sourceHandle: 'value', target: 'sign', targetHandle: 'data' },
      { id: 'e2', source: 'key', sourceHandle: 'value', target: 'sign', targetHandle: 'privateKey' },
    ];
    const result = await DAGRunner.execute(nodes, edges, registry);
    expect(result.nodeStates['sign'].status).toBe('error');
    expect(result.nodeStates['sign'].errorCode).toBe('INVALID_KEY_MATERIAL');
  });

  it('surfaces INVALID_KEY_MATERIAL for a wrong-length ML-KEM public key', async () => {
    const nodes = [
      { id: 'pk', type: 'input-static-value', properties: { type: 'bytes', valueBytes: 'aabbccddee' } },
      { id: 'encaps', type: 'pqc-mlkem-encaps', properties: { variant: 768 } },
    ];
    const edges = [{ id: 'e1', source: 'pk', sourceHandle: 'value', target: 'encaps', targetHandle: 'publicKey' }];
    const result = await DAGRunner.execute(nodes, edges, registry);
    expect(result.nodeStates['encaps'].status).toBe('error');
    expect(result.nodeStates['encaps'].errorCode).toBe('INVALID_KEY_MATERIAL');
  });

  it('surfaces INVALID_KEY_FORMAT for a malformed RSA private key', async () => {
    const nodes = [
      { id: 'ct', type: 'input-static-value', properties: { type: 'bytes', valueBytes: '00112233' } },
      { id: 'key', type: 'input-static-value', properties: { type: 'bytes', valueBytes: '010203' } },
      { id: 'dec', type: 'asymmetric-rsa-decrypt', properties: { hash: 'SHA-256' } },
    ];
    const edges = [
      { id: 'e1', source: 'ct', sourceHandle: 'value', target: 'dec', targetHandle: 'ciphertext' },
      { id: 'e2', source: 'key', sourceHandle: 'value', target: 'dec', targetHandle: 'privateKey' },
    ];
    const result = await DAGRunner.execute(nodes, edges, registry);
    expect(result.nodeStates['dec'].status).toBe('error');
    expect(result.nodeStates['dec'].errorCode).toBe('INVALID_KEY_FORMAT');
  });

  it('declares errorProfile: none for a node that genuinely cannot fail (Random Value)', () => {
    const def = registry.get('input-random');
    expect(def?.errorProfile).toEqual({ kind: 'none' });
  });
});
