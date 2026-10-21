/**
 * KISA Standard SEED-128 Block Cipher Implementation
 * 128-bit block, 128-bit key, 16-round Feistel Network (TTAS.KO-12.0004 / RFC 4269)
 */

import { applyBlockPadding, removeBlockPadding, BlockPaddingType } from '../padding/padding';
import { gcmModeEncrypt, gcmModeDecrypt, ccmModeEncrypt, ccmModeDecrypt, ctrMode } from './modes';
import { NodeError } from '../../dag/errors';

// SEED S-boxes (KISA SEED 128 Specification §2.3, Tables 1 and 2; RFC 4269 §2.2)
const S1 = [
  0xa9, 0x85, 0xd6, 0xd3, 0x54, 0x1d, 0xac, 0x25, 0x5d, 0x43, 0x18, 0x1e, 0x51, 0xfc, 0xca, 0x63,
  0x28, 0x44, 0x20, 0x9d, 0xe0, 0xe2, 0xc8, 0x17, 0xa5, 0x8f, 0x03, 0x7b, 0xbb, 0x13, 0xd2, 0xee,
  0x70, 0x8c, 0x3f, 0xa8, 0x32, 0xdd, 0xf6, 0x74, 0xec, 0x95, 0x0b, 0x57, 0x5c, 0x5b, 0xbd, 0x01,
  0x24, 0x1c, 0x73, 0x98, 0x10, 0xcc, 0xf2, 0xd9, 0x2c, 0xe7, 0x72, 0x83, 0x9b, 0xd1, 0x86, 0xc9,
  0x60, 0x50, 0xa3, 0xeb, 0x0d, 0xb6, 0x9e, 0x4f, 0xb7, 0x5a, 0xc6, 0x78, 0xa6, 0x12, 0xaf, 0xd5,
  0x61, 0xc3, 0xb4, 0x41, 0x52, 0x7d, 0x8d, 0x08, 0x1f, 0x99, 0x00, 0x19, 0x04, 0x53, 0xf7, 0xe1,
  0xfd, 0x76, 0x2f, 0x27, 0xb0, 0x8b, 0x0e, 0xab, 0xa2, 0x6e, 0x93, 0x4d, 0x69, 0x7c, 0x09, 0x0a,
  0xbf, 0xef, 0xf3, 0xc5, 0x87, 0x14, 0xfe, 0x64, 0xde, 0x2e, 0x4b, 0x1a, 0x06, 0x21, 0x6b, 0x66,
  0x02, 0xf5, 0x92, 0x8a, 0x0c, 0xb3, 0x7e, 0xd0, 0x7a, 0x47, 0x96, 0xe5, 0x26, 0x80, 0xad, 0xdf,
  0xa1, 0x30, 0x37, 0xae, 0x36, 0x15, 0x22, 0x38, 0xf4, 0xa7, 0x45, 0x4c, 0x81, 0xe9, 0x84, 0x97,
  0x35, 0xcb, 0xce, 0x3c, 0x71, 0x11, 0xc7, 0x89, 0x75, 0xfb, 0xda, 0xf8, 0x94, 0x59, 0x82, 0xc4,
  0xff, 0x49, 0x39, 0x67, 0xc0, 0xcf, 0xd7, 0xb8, 0x0f, 0x8e, 0x42, 0x23, 0x91, 0x6c, 0xdb, 0xa4,
  0x34, 0xf1, 0x48, 0xc2, 0x6f, 0x3d, 0x2d, 0x40, 0xbe, 0x3e, 0xbc, 0xc1, 0xaa, 0xba, 0x4e, 0x55,
  0x3b, 0xdc, 0x68, 0x7f, 0x9c, 0xd8, 0x4a, 0x56, 0x77, 0xa0, 0xed, 0x46, 0xb5, 0x2b, 0x65, 0xfa,
  0xe3, 0xb9, 0xb1, 0x9f, 0x5e, 0xf9, 0xe6, 0xb2, 0x31, 0xea, 0x6d, 0x5f, 0xe4, 0xf0, 0xcd, 0x88,
  0x16, 0x3a, 0x58, 0xd4, 0x62, 0x29, 0x07, 0x33, 0xe8, 0x1b, 0x05, 0x79, 0x90, 0x6a, 0x2a, 0x9a,
];

const S2 = [
  0x38, 0xe8, 0x2d, 0xa6, 0xcf, 0xde, 0xb3, 0xb8, 0xaf, 0x60, 0x55, 0xc7, 0x44, 0x6f, 0x6b, 0x5b,
  0xc3, 0x62, 0x33, 0xb5, 0x29, 0xa0, 0xe2, 0xa7, 0xd3, 0x91, 0x11, 0x06, 0x1c, 0xbc, 0x36, 0x4b,
  0xef, 0x88, 0x6c, 0xa8, 0x17, 0xc4, 0x16, 0xf4, 0xc2, 0x45, 0xe1, 0xd6, 0x3f, 0x3d, 0x8e, 0x98,
  0x28, 0x4e, 0xf6, 0x3e, 0xa5, 0xf9, 0x0d, 0xdf, 0xd8, 0x2b, 0x66, 0x7a, 0x27, 0x2f, 0xf1, 0x72,
  0x42, 0xd4, 0x41, 0xc0, 0x73, 0x67, 0xac, 0x8b, 0xf7, 0xad, 0x80, 0x1f, 0xca, 0x2c, 0xaa, 0x34,
  0xd2, 0x0b, 0xee, 0xe9, 0x5d, 0x94, 0x18, 0xf8, 0x57, 0xae, 0x08, 0xc5, 0x13, 0xcd, 0x86, 0xb9,
  0xff, 0x7d, 0xc1, 0x31, 0xf5, 0x8a, 0x6a, 0xb1, 0xd1, 0x20, 0xd7, 0x02, 0x22, 0x04, 0x68, 0x71,
  0x07, 0xdb, 0x9d, 0x99, 0x61, 0xbe, 0xe6, 0x59, 0xdd, 0x51, 0x90, 0xdc, 0x9a, 0xa3, 0xab, 0xd0,
  0x81, 0x0f, 0x47, 0x1a, 0xe3, 0xec, 0x8d, 0xbf, 0x96, 0x7b, 0x5c, 0xa2, 0xa1, 0x63, 0x23, 0x4d,
  0xc8, 0x9e, 0x9c, 0x3a, 0x0c, 0x2e, 0xba, 0x6e, 0x9f, 0x5a, 0xf2, 0x92, 0xf3, 0x49, 0x78, 0xcc,
  0x15, 0xfb, 0x70, 0x75, 0x7f, 0x35, 0x10, 0x03, 0x64, 0x6d, 0xc6, 0x74, 0xd5, 0xb4, 0xea, 0x09,
  0x76, 0x19, 0xfe, 0x40, 0x12, 0xe0, 0xbd, 0x05, 0xfa, 0x01, 0xf0, 0x2a, 0x5e, 0xa9, 0x56, 0x43,
  0x85, 0x14, 0x89, 0x9b, 0xb0, 0xe5, 0x48, 0x79, 0x97, 0xfc, 0x1e, 0x82, 0x21, 0x8c, 0x1b, 0x5f,
  0x77, 0x54, 0xb2, 0x1d, 0x25, 0x4f, 0x00, 0x46, 0xed, 0x58, 0x52, 0xeb, 0x7e, 0xda, 0xc9, 0xfd,
  0x30, 0x95, 0x65, 0x3c, 0xb6, 0xe4, 0xbb, 0x7c, 0x0e, 0x50, 0x39, 0x26, 0x32, 0x84, 0x69, 0x93,
  0x37, 0xe7, 0x24, 0xa4, 0xcb, 0x53, 0x0a, 0x87, 0xd9, 0x4c, 0x83, 0x8f, 0xce, 0x3b, 0x4a, 0xb7,
];

// KC constants (Derived from Golden Ratio: (sqrt(5)-1)/2 * 2^32)
const KC = [
  0x9e3779b9, 0x3c6ef373, 0x78dde6e6, 0xf1bbcdcc,
  0xe3779b99, 0xc6ef3733, 0x8dde6e67, 0x1bbcdccf,
  0x3779b99e, 0x6ef3733c, 0xdde6e678, 0xbbcdccf1,
  0x779b99e3, 0xef3733c6, 0xde6e678d, 0xbcdccf1b,
];

// Block permutation masks of G (specification §2.2).
const M = [0xfc, 0xf3, 0xcf, 0x3f];

function gFunc(x: number): number {
  const y0 = S1[x & 0xff];
  const y1 = S2[(x >>> 8) & 0xff];
  const y2 = S1[(x >>> 16) & 0xff];
  const y3 = S2[(x >>> 24) & 0xff];

  const z0 = (y0 & M[0]) ^ (y1 & M[1]) ^ (y2 & M[2]) ^ (y3 & M[3]);
  const z1 = (y0 & M[1]) ^ (y1 & M[2]) ^ (y2 & M[3]) ^ (y3 & M[0]);
  const z2 = (y0 & M[2]) ^ (y1 & M[3]) ^ (y2 & M[0]) ^ (y3 & M[1]);
  const z3 = (y0 & M[3]) ^ (y1 & M[0]) ^ (y2 & M[1]) ^ (y3 & M[2]);

  return ((z3 << 24) | (z2 << 16) | (z1 << 8) | z0) >>> 0;
}

/** Round function F (specification §2.1): (C, D) with subkeys (K0, K1) -> (C', D'). */
function fFunc(c: number, d: number, k0: number, k1: number): [number, number] {
  const c0 = (c ^ k0) >>> 0;
  let t1 = gFunc((c0 ^ d ^ k1) >>> 0);
  let t0 = gFunc((t1 + c0) >>> 0);
  t1 = gFunc((t1 + t0) >>> 0);
  t0 = (t0 + t1) >>> 0;
  return [t0, t1];
}

export function generateSeedRoundKeys(key: Uint8Array): [number, number][] {
  if (key.length === 32) {
    const k1 = key.slice(0, 16);
    const k2 = key.slice(16, 32);
    return [...generateSeedRoundKeys(k1), ...generateSeedRoundKeys(k2)];
  }

  let a = ((key[0] << 24) | (key[1] << 16) | (key[2] << 8) | key[3]) >>> 0;
  let b = ((key[4] << 24) | (key[5] << 16) | (key[6] << 8) | key[7]) >>> 0;
  let c = ((key[8] << 24) | (key[9] << 16) | (key[10] << 8) | key[11]) >>> 0;
  let d = ((key[12] << 24) | (key[13] << 16) | (key[14] << 8) | key[15]) >>> 0;

  const roundKeys: [number, number][] = [];

  for (let i = 0; i < 16; i++) {
    const kc = KC[i];
    const k0 = gFunc(((a + c - kc) >>> 0));
    const k1 = gFunc(((b - d + kc) >>> 0));
    roundKeys.push([k0, k1]);

    if (i % 2 === 0) {
      // Rotate 64-bit (A || B) right by 8 bits
      const tA = a;
      a = ((a >>> 8) | (b << 24)) >>> 0;
      b = ((b >>> 8) | (tA << 24)) >>> 0;
    } else {
      // Rotate 64-bit (C || D) left by 8 bits
      const tC = c;
      c = ((c << 8) | (d >>> 24)) >>> 0;
      d = ((d << 8) | (tC >>> 24)) >>> 0;
    }
  }

  return roundKeys;
}

export function seedBlock(block: Uint8Array, roundKeys: [number, number][], isDecrypt: boolean): Uint8Array {
  let l0 = ((block[0] << 24) | (block[1] << 16) | (block[2] << 8) | block[3]) >>> 0;
  let l1 = ((block[4] << 24) | (block[5] << 16) | (block[6] << 8) | block[7]) >>> 0;
  let r0 = ((block[8] << 24) | (block[9] << 16) | (block[10] << 8) | block[11]) >>> 0;
  let r1 = ((block[12] << 24) | (block[13] << 16) | (block[14] << 8) | block[15]) >>> 0;

  const keys = isDecrypt ? [...roundKeys].reverse() : roundKeys;

  for (let i = 0; i < keys.length; i++) {
    const [k0, k1] = keys[i];
    const [f0, f1] = fFunc(r0, r1, k0, k1);

    const nextR0 = (l0 ^ f0) >>> 0;
    const nextR1 = (l1 ^ f1) >>> 0;

    l0 = r0;
    l1 = r1;
    r0 = nextR0;
    r1 = nextR1;
  }

  const out = new Uint8Array(16);
  // Final output is (R0, R1, L0, L1)
  out[0] = (r0 >>> 24) & 0xff;
  out[1] = (r0 >>> 16) & 0xff;
  out[2] = (r0 >>> 8) & 0xff;
  out[3] = r0 & 0xff;
  out[4] = (r1 >>> 24) & 0xff;
  out[5] = (r1 >>> 16) & 0xff;
  out[6] = (r1 >>> 8) & 0xff;
  out[7] = r1 & 0xff;
  out[8] = (l0 >>> 24) & 0xff;
  out[9] = (l0 >>> 16) & 0xff;
  out[10] = (l0 >>> 8) & 0xff;
  out[11] = l0 & 0xff;
  out[12] = (l1 >>> 24) & 0xff;
  out[13] = (l1 >>> 16) & 0xff;
  out[14] = (l1 >>> 8) & 0xff;
  out[15] = l1 & 0xff;

  return out;
}

export type SeedMode = 'CBC' | 'ECB' | 'CTR' | 'GCM' | 'CCM';
export type SeedPadding = BlockPaddingType;

export interface SeedEncryptParams {
  plaintext: Uint8Array;
  key: Uint8Array;
  iv?: Uint8Array;
  mode?: SeedMode;
  padding?: SeedPadding;
  aad?: Uint8Array;
}

export interface SeedEncryptResult {
  ciphertext: Uint8Array;
  tag?: Uint8Array;
  iv: Uint8Array;
}

export interface SeedDecryptParams {
  ciphertext: Uint8Array;
  key: Uint8Array;
  iv?: Uint8Array;
  mode?: SeedMode;
  padding?: SeedPadding;
  tag?: Uint8Array;
  aad?: Uint8Array;
}

export function seedEncrypt(params: SeedEncryptParams): SeedEncryptResult {
  const { plaintext, key, aad } = params;
  const mode = params.mode || 'CBC';
  const padding = params.padding || 'PKCS7';
  let iv = params.iv;

  if (![16, 32].includes(key.length)) {
    throw new NodeError('INVALID_KEY_LENGTH', `SEED requires a 16-byte (SEED-128) or 32-byte (SEED-256) key, got ${key.length}`);
  }

  const roundKeys = generateSeedRoundKeys(key);
  const blockEncrypt = (b: Uint8Array) => seedBlock(b, roundKeys, false);

  // Deterministic 0x00-fill default when IV/nonce is omitted (PRD §4.3 common rule) -- not a
  // random value, so the same inputs always produce the same output. Prototyping/debugging
  // convenience only; real deployments must always supply a random, non-reused IV/nonce.
  if (mode === 'GCM') {
    const actualIv = iv && iv.length === 12 ? iv : new Uint8Array(12);
    return gcmModeEncrypt(blockEncrypt, plaintext, actualIv, aad);
  }

  if (mode === 'CCM') {
    const actualNonce = iv && iv.length >= 7 && iv.length <= 13 ? iv : new Uint8Array(12);
    return ccmModeEncrypt(blockEncrypt, plaintext, actualNonce, aad);
  }

  if (mode === 'CTR') {
    const actualIv = iv && iv.length === 16 ? iv : new Uint8Array(16);
    return ctrMode(blockEncrypt, plaintext, actualIv);
  }

  const data = applyBlockPadding(plaintext, padding, 16);
  const ciphertext = new Uint8Array(data.length);
  const actualIv = iv || (mode === 'CBC' ? new Uint8Array(16) : new Uint8Array(0));
  let prevBlock = new Uint8Array(actualIv);

  for (let i = 0; i < data.length; i += 16) {
    const block = new Uint8Array(data.slice(i, i + 16));
    if (mode === 'CBC') {
      for (let b = 0; b < 16; b++) {
        block[b] ^= prevBlock[b];
      }
    }
    const encryptedBlock = seedBlock(block, roundKeys, false);
    ciphertext.set(encryptedBlock, i);
    prevBlock = new Uint8Array(encryptedBlock);
  }

  return { ciphertext, iv: actualIv };
}

export function seedDecrypt(params: SeedDecryptParams): Uint8Array {
  const { ciphertext, key, tag, aad, iv } = params;
  const mode = params.mode || 'CBC';
  const padding = params.padding || 'PKCS7';

  if (![16, 32].includes(key.length)) {
    throw new NodeError('INVALID_KEY_LENGTH', 'SEED requires a 16-byte or 32-byte key');
  }

  const roundKeys = generateSeedRoundKeys(key);
  const blockEncrypt = (b: Uint8Array) => seedBlock(b, roundKeys, false);

  if (mode === 'GCM') {
    const actualIv = iv ?? new Uint8Array(12);
    if (actualIv.length !== 12) throw new NodeError('INVALID_NONCE_LENGTH', 'SEED-GCM decryption requires a 12-byte IV');
    if (!tag || tag.length !== 16) throw new NodeError('INVALID_TAG_LENGTH', 'SEED-GCM decryption requires a 16-byte tag');
    return gcmModeDecrypt(blockEncrypt, ciphertext, actualIv, tag, aad);
  }

  if (mode === 'CCM') {
    const actualNonce = iv ?? new Uint8Array(12);
    if (!tag) throw new NodeError('INVALID_TAG_LENGTH', 'SEED-CCM decryption requires a tag');
    return ccmModeDecrypt(blockEncrypt, ciphertext, actualNonce, tag, aad);
  }

  if (mode === 'CTR') {
    const actualIv = iv ?? new Uint8Array(16);
    if (actualIv.length !== 16) throw new NodeError('INVALID_IV_LENGTH', 'SEED-CTR decryption requires a 16-byte counter');
    return ctrMode(blockEncrypt, ciphertext, actualIv).ciphertext;
  }

  if (ciphertext.length % 16 !== 0) throw new NodeError('CIPHERTEXT_NOT_BLOCK_ALIGNED', 'Ciphertext must be a multiple of 16 bytes');

  const plaintext = new Uint8Array(ciphertext.length);
  const actualIv = iv || new Uint8Array(16);
  let prevBlock = new Uint8Array(actualIv);

  for (let i = 0; i < ciphertext.length; i += 16) {
    const block = new Uint8Array(ciphertext.slice(i, i + 16));
    const decryptedBlock = seedBlock(block, roundKeys, true);
    if (mode === 'CBC') {
      for (let b = 0; b < 16; b++) {
        decryptedBlock[b] ^= prevBlock[b];
      }
      prevBlock = block;
    }
    plaintext.set(decryptedBlock, i);
  }

  return removeBlockPadding(plaintext, padding, 16);
}

