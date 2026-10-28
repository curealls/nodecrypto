import { describe, it, expect } from 'vitest';
import { generateKeyPairSync, sign, verify } from 'node:crypto';
import { sha256 } from '@noble/hashes/sha2.js';
import { eccSign, eccVerify } from '../../src/crypto/asymmetric/ecc';

// node-catalog.md ND-5.5: ECDSA with SHA-256 over the message, interoperable with OpenSSL (the digest is not hashed a second time).
const msg = new TextEncoder().encode('Hello');
const b = (s: string) => new Uint8Array(Buffer.from(s, 'base64url'));

describe.each([['p256', 'P-256'], ['secp256k1', 'secp256k1']] as const)('ECDSA %s with OpenSSL', (curve, namedCurve) => {
  const kp = generateKeyPairSync('ec', { namedCurve });
  const jwk = kp.privateKey.export({ format: 'jwk' }) as any;
  const priv = b(jwk.d);
  const pub = new Uint8Array([4, ...b(jwk.x), ...b(jwk.y)]);

  // OpenSSL does not normalize S: about half of the signatures have the high-S form, which is still a valid signature.
  it('verifies signatures made by OpenSSL, low-S and high-S alike', () => {
    const n = curve === 'p256' ? 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n : 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
    const seen = new Set<boolean>();
    for (let i = 0; i < 40; i++) {
      const sig = new Uint8Array(sign('sha256', msg, { key: kp.privateKey, dsaEncoding: 'ieee-p1363' }));
      seen.add(BigInt('0x' + Buffer.from(sig.slice(32)).toString('hex')) > n / 2n);
      expect(eccVerify(sig, sha256(msg), pub, curve)).toBe(true);
    }
    expect(seen.size).toBe(2); // both forms were exercised
    const sig = new Uint8Array(sign('sha256', msg, { key: kp.privateKey, dsaEncoding: 'ieee-p1363' }));
    expect(eccVerify(sig, sha256(new TextEncoder().encode('Hellp')), pub, curve)).toBe(false);
  });

  it('makes a signature that OpenSSL verifies', () => {
    const sig = eccSign(sha256(msg), priv, curve);
    expect(sig.length).toBe(64);
    expect(verify('sha256', msg, { key: kp.publicKey, dsaEncoding: 'ieee-p1363' }, Buffer.from(sig))).toBe(true);
  });
});
