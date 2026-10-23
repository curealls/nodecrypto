import { describe, it, expect } from 'vitest';
import { decodeRsaKey } from 'nodecrypto-engine/crypto/asymmetric/rsaKeyCodec';
import { NodeError } from 'nodecrypto-engine/dag/errors';

const subtle = globalThis.crypto.subtle;
const b64u = (s: string) => new Uint8Array(Buffer.from(s, 'base64url'));

async function makeKey(modulusLength: number, publicExponent: number[]) {
  const pair = await subtle.generateKey(
    { name: 'RSA-OAEP', modulusLength, publicExponent: new Uint8Array(publicExponent), hash: 'SHA-256' },
    true,
    ['encrypt', 'decrypt'],
  );
  return {
    spki: new Uint8Array(await subtle.exportKey('spki', pair.publicKey)),
    pkcs8: new Uint8Array(await subtle.exportKey('pkcs8', pair.privateKey)),
    jwk: (await subtle.exportKey('jwk', pair.privateKey)) as Record<string, string>,
  };
}

const rejects = (fn: () => unknown) => {
  try { fn(); } catch (e) {
    expect(e).toBeInstanceOf(NodeError);
    expect((e as NodeError).code).toBe('INVALID_KEY_FORMAT');
    return;
  }
  throw new Error('expected INVALID_KEY_FORMAT');
};

describe('RSA key decoder (SPKI / PKCS#8 DER)', () => {
  it('matches JWK components for e = 65537 (2048-bit)', async () => {
    const { spki, pkcs8, jwk } = await makeKey(2048, [1, 0, 1]);
    const pub = decodeRsaKey(spki, 'Public');
    expect(pub.n).toEqual(b64u(jwk.n));
    expect(pub.e).toEqual(b64u(jwk.e));
    expect(pub.d).toBeUndefined();

    const prv = decodeRsaKey(pkcs8, 'Private');
    expect(prv.n).toEqual(b64u(jwk.n));
    expect(prv.e).toEqual(b64u(jwk.e));
    expect(prv.d).toEqual(b64u(jwk.d));
    expect(prv.p).toEqual(b64u(jwk.p));
    expect(prv.q).toEqual(b64u(jwk.q));
    expect(prv.dp).toEqual(b64u(jwk.dp));
    expect(prv.dq).toEqual(b64u(jwk.dq));
    expect(prv.qInv).toEqual(b64u(jwk.qi));
  });

  it('reads e = 3 (1024-bit)', async () => {
    const { spki, pkcs8, jwk } = await makeKey(1024, [3]);
    expect(Array.from(decodeRsaKey(spki, 'Public').e)).toEqual([3]);
    const prv = decodeRsaKey(pkcs8, 'Private');
    expect(Array.from(prv.e)).toEqual([3]);
    expect(prv.d).toEqual(b64u(jwk.d));
  });

  describe('rejects with INVALID_KEY_FORMAT', () => {
    it('truncated DER', async () => {
      const { spki, pkcs8 } = await makeKey(1024, [1, 0, 1]);
      rejects(() => decodeRsaKey(spki.subarray(0, 50), 'Public'));
      rejects(() => decodeRsaKey(pkcs8.subarray(0, 200), 'Private'));
      rejects(() => decodeRsaKey(new Uint8Array(0), 'Public'));
    });

    it('algorithm OID mismatch', async () => {
      const { spki } = await makeKey(1024, [1, 0, 1]);
      const bad = spki.slice();
      // rsaEncryption OID 2a864886f70d010101: flip the last arc byte (01 -> 0b)
      const i = bad.findIndex((_, k) => k > 0 && bad[k - 1] === 0x0d && bad[k] === 0x01 && bad[k + 1] === 0x01 && bad[k + 2] === 0x01);
      bad[i + 2] = 0x0b;
      rejects(() => decodeRsaKey(bad, 'Public'));
    });

    it('RSASSA-PSS OID', async () => {
      const { spki } = await makeKey(1024, [1, 0, 1]);
      const pss = spki.slice();
      const i = pss.findIndex((_, k) => k > 0 && pss[k - 1] === 0x0d && pss[k] === 0x01 && pss[k + 1] === 0x01 && pss[k + 2] === 0x01);
      pss[i + 2] = 0x0a;
      expect(() => decodeRsaKey(pss, 'Public')).toThrow(/RSASSA-PSS/);
      rejects(() => decodeRsaKey(pss, 'Public'));
    });

    it('key type mismatch', async () => {
      const { spki, pkcs8 } = await makeKey(1024, [1, 0, 1]);
      rejects(() => decodeRsaKey(spki, 'Private'));
      rejects(() => decodeRsaKey(pkcs8, 'Public'));
    });

    it('PEM text bytes', async () => {
      const { spki } = await makeKey(1024, [1, 0, 1]);
      const pem = `-----BEGIN PUBLIC KEY-----\n${Buffer.from(spki).toString('base64')}\n-----END PUBLIC KEY-----`;
      rejects(() => decodeRsaKey(new TextEncoder().encode(pem), 'Public'));
    });

    it('PKCS#1 DER', async () => {
      const { pkcs8 } = await makeKey(1024, [1, 0, 1]);
      // RSAPrivateKey is the OCTET STRING payload of PKCS#8 (starts after the AlgorithmIdentifier);
      // RSAPublicKey is {n, e}
      const prv = decodeRsaKey(pkcs8, 'Private');
      const start = pkcs8.findIndex((_, k) => k > 20 && pkcs8[k] === 0x30 && pkcs8[k + 1] === 0x82);
      const pkcs1Private = pkcs8.subarray(start);
      rejects(() => decodeRsaKey(pkcs1Private, 'Private'));
      rejects(() => decodeRsaKey(pkcs1Private, 'Public'));

      const int = (v: Uint8Array) => {
        const body = v[0] & 0x80 ? Uint8Array.from([0, ...v]) : v;
        return Uint8Array.from([0x02, 0x81, body.length, ...body]);
      };
      const inner = Uint8Array.from([...int(prv.n), ...int(prv.e)]);
      const pkcs1Public = Uint8Array.from([0x30, 0x81, inner.length, ...inner]);
      rejects(() => decodeRsaKey(pkcs1Public, 'Public'));
      rejects(() => decodeRsaKey(pkcs1Public, 'Private'));
    });
  });
});
