import { describe, expect, it } from 'vitest';
import { sha3_512 } from '@noble/hashes/sha3.js';
import { hexToBytes, bytesToHex } from 'nodecrypto-engine/crypto/utils/encoding';
import { mlKemDecapsulate, mlKemEncapsulate, type MlKemSecurityLevel } from 'nodecrypto-engine/crypto/pqc/ml_kem';
import vectors from './vectors/ml-kem-cctv.json';

// ML-KEM known answers from the C2SP CCTV project (see `source` in the JSON). The full-size decapsulation key
// (dk: 1632/2400/3168 bytes) is checked against an independent implementation, which round trips cannot do.
//
// Key generation is NOT compared: the CCTV vectors follow the FIPS 203 initial public draft, where K-PKE.KeyGen
// derives (rho, sigma) = G(d). The final standard uses G(d || k) (k = 2, 3, 4), so ek and dk differ by design.
// Encaps/Decaps are unchanged between the draft (with the i/j order fix the vectors apply) and the final standard.
const levels = Object.keys(vectors.intermediate) as ('512' | '768' | '1024')[];
const level = (l: string) => Number(l) as MlKemSecurityLevel;
const K_OF = { '512': 2, '768': 3, '1024': 4 } as const;

describe('ML-KEM (FIPS 203) CCTV intermediate vectors', () => {
  it.each(levels)('ML-KEM-%s: the vectors are draft-keygen vectors (rho = G(d), not G(d || k))', (l) => {
    const v = vectors.intermediate[l];
    const rho = (g: Uint8Array) => bytesToHex(sha3_512(g).slice(0, 32));
    expect(v.ek.endsWith(rho(hexToBytes(v.d)))).toBe(true);
    expect(v.ek.endsWith(rho(hexToBytes(v.d + K_OF[l].toString(16).padStart(2, '0'))))).toBe(false);
  });

  it.each(levels)('ML-KEM-%s: encapsulation with m gives the expected ciphertext and shared secret', (l) => {
    const v = vectors.intermediate[l];
    const e = mlKemEncapsulate(hexToBytes(v.ek), level(l), hexToBytes(v.m));
    expect(bytesToHex(e.ciphertext)).toBe(v.c);
    expect(bytesToHex(e.sharedSecret)).toBe(v.K);
  });

  it.each(levels)('ML-KEM-%s: decapsulating the expected ciphertext with the full-size dk gives K', (l) => {
    const v = vectors.intermediate[l];
    expect(bytesToHex(mlKemDecapsulate(hexToBytes(v.c), hexToBytes(v.dk), level(l)))).toBe(v.K);
  });
});

describe('ML-KEM (FIPS 203) CCTV strcmp vector', () => {
  it('ML-KEM-768: a rejected ciphertext yields the implicit-rejection key, not an error', () => {
    const v = vectors.strcmp['768'];
    expect(bytesToHex(mlKemDecapsulate(hexToBytes(v.c), hexToBytes(v.dk), 768))).toBe(v.K);
  });
});
