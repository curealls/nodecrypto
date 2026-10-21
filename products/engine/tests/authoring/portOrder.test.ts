import { describe, it, expect } from 'vitest';
import { defaultNodeRegistry } from '../../src/registry/nodeRegistry';

// node-catalog.md §2.2-13: key-role input ports come first.
const cases: Record<string, string[]> = {
  'symmetric-aes-encrypt': ['key', 'plaintext', 'iv', 'nonce', 'aad'],
  'symmetric-aes-decrypt': ['key', 'ciphertext', 'iv', 'nonce', 'tag', 'aad'],
  'symmetric-tdes-encrypt': ['key', 'plaintext', 'iv'],
  'symmetric-des-decrypt': ['key', 'ciphertext', 'iv'],
  'symmetric-chacha20-poly1305-encrypt': ['key', 'plaintext', 'nonce', 'aad'],
  'symmetric-chacha20-poly1305-decrypt': ['key', 'ciphertext', 'nonce', 'tag', 'aad'],
  'symmetric-chacha20-stream': ['key', 'data', 'nonce'],
  'mac-hmac': ['key', 'data'],
  'mac-cmac': ['key', 'data'],
  'asymmetric-rsa-encrypt': ['publicKey', 'plaintext', 'label'],
  'asymmetric-rsa-decrypt': ['privateKey', 'ciphertext', 'label'],
  'asymmetric-rsa-sign': ['privateKey', 'data'],
  'asymmetric-rsa-verify': ['publicKey', 'data', 'signature'],
  'asymmetric-ecc-sign': ['privateKey', 'data'],
  'asymmetric-ecc-verify': ['publicKey', 'data', 'signature'],
  'asymmetric-ed25519-sign': ['privateKey', 'message'],
  'asymmetric-ed25519-verify': ['publicKey', 'message', 'signature'],
  'pqc-mlkem-decaps': ['secretKey', 'ciphertext'],
  'pqc-mldsa-sign': ['secretKey', 'message'],
  'pqc-mldsa-verify': ['publicKey', 'message', 'signature'],
  'pqc-slhdsa-sign': ['secretKey', 'message'],
  'pqc-slhdsa-verify': ['publicKey', 'message', 'signature'],
  'pqc-hybridkem-decaps': ['secretKey', 'ciphertext'],
};

describe('node definitions: key-first input order', () => {
  it.each(Object.entries(cases))('%s', (type, ids) => {
    expect(defaultNodeRegistry.get(type)!.inputs.map((p) => p.id)).toEqual(ids);
  });

  it('every block cipher pair puts key first', () => {
    const t = [...defaultNodeRegistry.getMap().keys()].filter((k) => /^symmetric-.*-(en|de)crypt$/.test(k));
    expect(t.length).toBeGreaterThan(10);
    for (const k of t) expect(defaultNodeRegistry.get(k)!.inputs[0].id, k).toBe('key');
  });
});
