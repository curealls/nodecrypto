import { describe, it, expect } from 'vitest';
import { decodeRsaKey, encodeRsaPublicKey, encodeRsaPrivateKey } from 'nodecrypto-engine/crypto/asymmetric/rsaKeyCodec';
import { NodeError } from 'nodecrypto-engine/dag/errors';

const subtle = globalThis.crypto.subtle;
const b64u = (s: string) => new Uint8Array(Buffer.from(s, 'base64url'));

async function makeKey(modulusLength: number, publicExponent: number[], name: 'RSA-OAEP' | 'RSA-PSS' = 'RSA-OAEP') {
  const pair = await subtle.generateKey(
    { name, modulusLength, publicExponent: new Uint8Array(publicExponent), hash: 'SHA-256' },
    true,
    name === 'RSA-OAEP' ? ['encrypt', 'decrypt'] : ['sign', 'verify'],
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
    expect((e as NodeError).code).toBe('RSA_COMPONENTS_INVALID');
    return;
  }
  throw new Error('expected RSA_COMPONENTS_INVALID');
};

const be = (v: bigint) => {
  const out: number[] = [];
  for (; v > 0n; v >>= 8n) out.unshift(Number(v & 0xffn));
  return Uint8Array.from(out);
};

describe('RSA key encoder (N, e, d -> SPKI / PKCS#8 DER)', () => {
  const cases: [number, number[]][] = [[2048, [1, 0, 1]], [3072, [1, 0, 1]], [1024, [3]], [2048, [3]]];

  it.each(cases)('round-trips WebCrypto DER through Decoder -> Encoder (%i bits, e=%j)', async (bits, e) => {
    const { spki, pkcs8 } = await makeKey(bits, e);
    const pub = decodeRsaKey(spki, 'Public');
    expect(encodeRsaPublicKey(pub.n, pub.e)).toEqual(spki);
    const prv = decodeRsaKey(pkcs8, 'Private');
    expect(encodeRsaPrivateKey({ n: prv.n, e: prv.e, d: prv.d! })).toEqual(pkcs8);
  }, 120000);

  it('recovers p and q equal to the key\'s own factors', async () => {
    for (let i = 0; i < 5; i++) {
      const { pkcs8, jwk } = await makeKey(1024, [1, 0, 1]);
      const prv = decodeRsaKey(pkcs8, 'Private');
      const out = decodeRsaKey(encodeRsaPrivateKey({ n: prv.n, e: prv.e, d: prv.d! }), 'Private');
      const factors = [out.p, out.q].map((x) => Buffer.from(x!).toString('hex')).sort();
      const expected = [jwk.p, jwk.q].map((x) => Buffer.from(b64u(x)).toString('hex')).sort();
      expect(factors).toEqual(expected);
      expect(Buffer.compare(Buffer.from(out.p!), Buffer.from(out.q!))).toBe(1);
    }
  });

  it('tolerates leading zero bytes in inputs', async () => {
    const { spki } = await makeKey(1024, [1, 0, 1]);
    const pub = decodeRsaKey(spki, 'Public');
    expect(encodeRsaPublicKey(Uint8Array.from([0, 0, ...pub.n]), Uint8Array.from([0, ...pub.e]))).toEqual(spki);
  });

  it('builds keys WebCrypto imports and that work for OAEP and PSS', async () => {
    const oaep = await makeKey(2048, [1, 0, 1]);
    const prv = decodeRsaKey(oaep.pkcs8, 'Private');
    const pubDer = encodeRsaPublicKey(prv.n, prv.e);
    const prvDer = encodeRsaPrivateKey({ n: prv.n, e: prv.e, d: prv.d! });
    const pubKey = await subtle.importKey('spki', pubDer, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
    const prvKey = await subtle.importKey('pkcs8', prvDer, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['decrypt']);
    const msg = new TextEncoder().encode('hello rsa');
    const ct = await subtle.encrypt({ name: 'RSA-OAEP' }, pubKey, msg);
    expect(new Uint8Array(await subtle.decrypt({ name: 'RSA-OAEP' }, prvKey, ct))).toEqual(msg);

    const pss = await makeKey(2048, [1, 0, 1], 'RSA-PSS');
    const p2 = decodeRsaKey(pss.pkcs8, 'Private');
    const signKey = await subtle.importKey('pkcs8', encodeRsaPrivateKey({ n: p2.n, e: p2.e, d: p2.d! }), { name: 'RSA-PSS', hash: 'SHA-256' }, false, ['sign']);
    const verifyKey = await subtle.importKey('spki', encodeRsaPublicKey(p2.n, p2.e), { name: 'RSA-PSS', hash: 'SHA-256' }, false, ['verify']);
    const sig = await subtle.sign({ name: 'RSA-PSS', saltLength: 32 }, signKey, msg);
    expect(await subtle.verify({ name: 'RSA-PSS', saltLength: 32 }, verifyKey, sig, msg)).toBe(true);
  });

  it('encodes a textbook key (p=61, q=53, e=17, d=2753) structurally', () => {
    const der = encodeRsaPrivateKey({ n: be(3233n), e: be(17n), d: be(2753n) });
    const k = decodeRsaKey(der, 'Private');
    expect(k.n).toEqual(be(3233n));
    expect(k.p).toEqual(be(61n));
    expect(k.q).toEqual(be(53n));
    expect(k.dp).toEqual(be(2753n % 60n));
    expect(k.dq).toEqual(be(2753n % 52n));
    expect(k.qInv).toEqual(be(38n)); // 53^-1 mod 61
    expect(decodeRsaKey(encodeRsaPublicKey(be(3233n), be(17n)), 'Public').e).toEqual(be(17n));
  });

  it('rejects invalid components with RSA_COMPONENTS_INVALID', async () => {
    const { pkcs8 } = await makeKey(1024, [1, 0, 1]);
    const k = decodeRsaKey(pkcs8, 'Private');
    rejects(() => encodeRsaPublicKey(new Uint8Array(0), k.e));
    rejects(() => encodeRsaPublicKey(Uint8Array.of(0), k.e));
    rejects(() => encodeRsaPublicKey(be(3232n), be(17n))); // even N
    rejects(() => encodeRsaPublicKey(k.n, be(65538n))); // even e
    rejects(() => encodeRsaPublicKey(k.n, be(1n)));
    rejects(() => encodeRsaPrivateKey({ n: k.n, e: k.e, d: k.n })); // d >= N
    rejects(() => encodeRsaPrivateKey({ n: k.n, e: k.e, d: Uint8Array.of(1) }));
    const bad = k.d!.slice();
    bad[bad.length - 1] ^= 2; // d no longer matches e
    rejects(() => encodeRsaPrivateKey({ n: k.n, e: k.e, d: bad }));
  });

  it('recovers primes of a 4096-bit key in reasonable time', async () => {
    const { pkcs8 } = await makeKey(4096, [1, 0, 1]);
    const k = decodeRsaKey(pkcs8, 'Private');
    const t0 = performance.now();
    const der = encodeRsaPrivateKey({ n: k.n, e: k.e, d: k.d! });
    const ms = performance.now() - t0;
    console.log(`RSA-4096 p,q recovery + encode: ${ms.toFixed(0)} ms`);
    expect(der).toEqual(pkcs8);
    expect(ms).toBeLessThan(5000);
  }, 180000);
});
