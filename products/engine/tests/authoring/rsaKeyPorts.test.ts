import { describe, it, expect } from 'vitest';
import { defaultNodeRegistry } from '../../src/registry/nodeRegistry';

describe('RSA node order (D-12): palette follows registry order', () => {
  it('keygen, Encoder, Decoder, Encrypt, Decrypt, Sign, Verify are consecutive', () => {
    const rsa = defaultNodeRegistry.getAll().filter((d) => d.type.startsWith('asymmetric-rsa-')).map((d) => d.type);
    expect(rsa).toEqual([
      'asymmetric-rsa-keygen', 'asymmetric-rsa-key-encode', 'asymmetric-rsa-key-decode',
      'asymmetric-rsa-encrypt', 'asymmetric-rsa-decrypt', 'asymmetric-rsa-sign', 'asymmetric-rsa-verify',
    ]);
    const all = defaultNodeRegistry.getAll().map((d) => d.type);
    expect(all.indexOf('asymmetric-rsa-verify') - all.indexOf('asymmetric-rsa-keygen')).toBe(6);
  });
});

describe('RSA nodes: DER bytes only (D-01, D-19, D-20)', () => {
  it('key generator outputs only the two DER ports', () => {
    const d = defaultNodeRegistry.get('asymmetric-rsa-keygen')!;
    expect(d.outputs.map((p) => [p.id, p.dataType])).toEqual([
      ['publicKeyDer', 'bytes'],
      ['privateKeyDer', 'bytes'],
    ]);
  });

  it('key generator properties are only key size and public exponent (D-23)', () => {
    expect(defaultNodeRegistry.get('asymmetric-rsa-keygen')!.propertySchema.map((f) => f.id)).toEqual(['modulusLength', 'publicExponent']);
  });

  it.each([
    ['asymmetric-rsa-encrypt', 'publicKey'],
    ['asymmetric-rsa-decrypt', 'privateKey'],
    ['asymmetric-rsa-sign', 'privateKey'],
    ['asymmetric-rsa-verify', 'publicKey'],
  ])('%s key input is bytes', (type, id) => {
    expect(defaultNodeRegistry.get(type)!.inputs.find((p) => p.id === id)!.dataType).toBe('bytes');
  });
});
