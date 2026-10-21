/**
 * KISA Standard ARIA Block Cipher Implementation
 * ARIA-128 (12 rounds), ARIA-192 (14 rounds), ARIA-256 (16 rounds)
 * Strictly adheres to IETF RFC 5794 / KS X 1213:2004
 */

import { applyBlockPadding, removeBlockPadding, BlockPaddingType } from '../padding/padding';
import { ofbMode, cfbModeEncrypt, cfbModeDecrypt, ctrMode, gcmModeEncrypt, gcmModeDecrypt, ccmModeEncrypt, ccmModeDecrypt } from './modes';
import { NodeError } from '../../dag/errors';

// SB1 (AES S-box, RFC 5794 Section 2.4.2)
const SB1 = [
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

// SB2 (RFC 5794 Section 2.4.2)
const SB2 = [
  0xe2, 0x4e, 0x54, 0xfc, 0x94, 0xc2, 0x4a, 0xcc, 0x62, 0x0d, 0x6a, 0x46, 0x3c, 0x4d, 0x8b, 0xd1,
  0x5e, 0xfa, 0x64, 0xcb, 0xb4, 0x97, 0xbe, 0x2b, 0xbc, 0x77, 0x2e, 0x03, 0xd3, 0x19, 0x59, 0xc1,
  0x1d, 0x06, 0x41, 0x6b, 0x55, 0xf0, 0x99, 0x69, 0xea, 0x9c, 0x18, 0xae, 0x63, 0xdf, 0xe7, 0xbb,
  0x00, 0x73, 0x66, 0xfb, 0x96, 0x4c, 0x85, 0xe4, 0x3a, 0x09, 0x45, 0xaa, 0x0f, 0xee, 0x10, 0xeb,
  0x2d, 0x7f, 0xf4, 0x29, 0xac, 0xcf, 0xad, 0x91, 0x8d, 0x78, 0xc8, 0x95, 0xf9, 0x2f, 0xce, 0xcd,
  0x08, 0x7a, 0x88, 0x38, 0x5c, 0x83, 0x2a, 0x28, 0x47, 0xdb, 0xb8, 0xc7, 0x93, 0xa4, 0x12, 0x53,
  0xff, 0x87, 0x0e, 0x31, 0x36, 0x21, 0x58, 0x48, 0x01, 0x8e, 0x37, 0x74, 0x32, 0xca, 0xe9, 0xb1,
  0xb7, 0xab, 0x0c, 0xd7, 0xc4, 0x56, 0x42, 0x26, 0x07, 0x98, 0x60, 0xd9, 0xb6, 0xb9, 0x11, 0x40,
  0xec, 0x20, 0x8c, 0xbd, 0xa0, 0xc9, 0x84, 0x04, 0x49, 0x23, 0xf1, 0x4f, 0x50, 0x1f, 0x13, 0xdc,
  0xd8, 0xc0, 0x9e, 0x57, 0xe3, 0xc3, 0x7b, 0x65, 0x3b, 0x02, 0x8f, 0x3e, 0xe8, 0x25, 0x92, 0xe5,
  0x15, 0xdd, 0xfd, 0x17, 0xa9, 0xbf, 0xd4, 0x9a, 0x7e, 0xc5, 0x39, 0x67, 0xfe, 0x76, 0x9d, 0x43,
  0xa7, 0xe1, 0xd0, 0xf5, 0x68, 0xf2, 0x1b, 0x34, 0x70, 0x05, 0xa3, 0x8a, 0xd5, 0x79, 0x86, 0xa8,
  0x30, 0xc6, 0x51, 0x4b, 0x1e, 0xa6, 0x27, 0xf6, 0x35, 0xd2, 0x6e, 0x24, 0x16, 0x82, 0x5f, 0xda,
  0xe6, 0x75, 0xa2, 0xef, 0x2c, 0xb2, 0x1c, 0x9f, 0x5d, 0x6f, 0x80, 0x0a, 0x72, 0x44, 0x9b, 0x6c,
  0x90, 0x0b, 0x5b, 0x33, 0x7d, 0x5a, 0x52, 0xf3, 0x61, 0xa1, 0xf7, 0xb0, 0xd6, 0x3f, 0x7c, 0x6d,
  0xed, 0x14, 0xe0, 0xa5, 0x3d, 0x22, 0xb3, 0xf8, 0x89, 0xde, 0x71, 0x1a, 0xaf, 0xba, 0xb5, 0x81,
];

// SB3 & SB4: Exact Inverses of SB1 and SB2 (RFC 5794 Section 2.4.2)
const SB3 = new Uint8Array(256);
const SB4 = new Uint8Array(256);
for (let i = 0; i < 256; i++) {
  SB3[SB1[i]] = i;
  SB4[SB2[i]] = i;
}

// Diffusion Layer A (RFC 5794 Section 2.4.3)
export function diffLayerA(x: Uint8Array): Uint8Array {
  const y = new Uint8Array(16);
  y[0]  = x[3]  ^ x[4]  ^ x[6]  ^ x[8]  ^ x[9]  ^ x[13] ^ x[14];
  y[1]  = x[2]  ^ x[5]  ^ x[7]  ^ x[8]  ^ x[9]  ^ x[12] ^ x[15];
  y[2]  = x[1]  ^ x[4]  ^ x[6]  ^ x[10] ^ x[11] ^ x[12] ^ x[15];
  y[3]  = x[0]  ^ x[5]  ^ x[7]  ^ x[10] ^ x[11] ^ x[13] ^ x[14];
  y[4]  = x[0]  ^ x[2]  ^ x[5]  ^ x[8]  ^ x[11] ^ x[14] ^ x[15];
  y[5]  = x[1]  ^ x[3]  ^ x[4]  ^ x[9]  ^ x[10] ^ x[14] ^ x[15];
  y[6]  = x[0]  ^ x[2]  ^ x[7]  ^ x[9]  ^ x[10] ^ x[12] ^ x[13];
  y[7]  = x[1]  ^ x[3]  ^ x[6]  ^ x[8]  ^ x[11] ^ x[12] ^ x[13];
  y[8]  = x[0]  ^ x[1]  ^ x[4]  ^ x[7]  ^ x[10] ^ x[13] ^ x[15];
  y[9]  = x[0]  ^ x[1]  ^ x[5]  ^ x[6]  ^ x[11] ^ x[12] ^ x[14];
  y[10] = x[2]  ^ x[3]  ^ x[5]  ^ x[6]  ^ x[8]  ^ x[13] ^ x[15];
  y[11] = x[2]  ^ x[3]  ^ x[4]  ^ x[7]  ^ x[9]  ^ x[12] ^ x[14];
  y[12] = x[1]  ^ x[2]  ^ x[6]  ^ x[7]  ^ x[9]  ^ x[11] ^ x[12];
  y[13] = x[0]  ^ x[3]  ^ x[6]  ^ x[7]  ^ x[8]  ^ x[10] ^ x[13];
  y[14] = x[0]  ^ x[3]  ^ x[4]  ^ x[5]  ^ x[9]  ^ x[11] ^ x[14];
  y[15] = x[1]  ^ x[2]  ^ x[4]  ^ x[5]  ^ x[8]  ^ x[10] ^ x[15];
  return y;
}

// Substitution Layer 1 (RFC 5794 Section 2.4.2)
export function sLayer1(x: Uint8Array): Uint8Array {
  const y = new Uint8Array(16);
  for (let i = 0; i < 16; i += 4) {
    y[i]     = SB1[x[i]];
    y[i + 1] = SB2[x[i + 1]];
    y[i + 2] = SB3[x[i + 2]];
    y[i + 3] = SB4[x[i + 3]];
  }
  return y;
}

// Substitution Layer 2 (RFC 5794 Section 2.4.2)
export function sLayer2(x: Uint8Array): Uint8Array {
  const y = new Uint8Array(16);
  for (let i = 0; i < 16; i += 4) {
    y[i]     = SB3[x[i]];
    y[i + 1] = SB4[x[i + 1]];
    y[i + 2] = SB1[x[i + 2]];
    y[i + 3] = SB2[x[i + 3]];
  }
  return y;
}

// Odd round function FO: A(SL1(D ^ RK))
function roundFO(d: Uint8Array, rk: Uint8Array): Uint8Array {
  const x = new Uint8Array(16);
  for (let i = 0; i < 16; i++) x[i] = d[i] ^ rk[i];
  return diffLayerA(sLayer1(x));
}

// Even round function FE: A(SL2(D ^ RK))
function roundFE(d: Uint8Array, rk: Uint8Array): Uint8Array {
  const x = new Uint8Array(16);
  for (let i = 0; i < 16; i++) x[i] = d[i] ^ rk[i];
  return diffLayerA(sLayer2(x));
}

function bytesToBigInt128(b: Uint8Array): bigint {
  let val = 0n;
  for (let i = 0; i < 16; i++) {
    val = (val << 8n) | BigInt(b[i]);
  }
  return val;
}

function bigIntToBytes128(n: bigint): Uint8Array {
  const out = new Uint8Array(16);
  for (let i = 15; i >= 0; i--) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
}

// 128-bit circular rotations
function rotRight128(v: Uint8Array, n: number): Uint8Array {
  const shift = BigInt(n);
  const val = bytesToBigInt128(v);
  const mask = (1n << 128n) - 1n;
  const rotated = ((val >> shift) | (val << (128n - shift))) & mask;
  return bigIntToBytes128(rotated);
}

function rotLeft128(v: Uint8Array, n: number): Uint8Array {
  const shift = BigInt(n);
  const val = bytesToBigInt128(v);
  const mask = (1n << 128n) - 1n;
  const rotated = ((val << shift) | (val >> (128n - shift))) & mask;
  return bigIntToBytes128(rotated);
}

function xor128(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) out[i] = a[i] ^ b[i];
  return out;
}

// Key Scheduling (RFC 5794 Section 2.2)
const C1 = new Uint8Array([0x51, 0x7c, 0xc1, 0xb7, 0x27, 0x22, 0x0a, 0x94, 0xfe, 0x13, 0xab, 0xe8, 0xfa, 0x9a, 0x6e, 0xe0]);
const C2 = new Uint8Array([0x6d, 0xb1, 0x4a, 0xcc, 0x9e, 0x21, 0xc8, 0x20, 0xff, 0x28, 0xb1, 0xd5, 0xef, 0x5d, 0xe2, 0xb0]);
const C3 = new Uint8Array([0xdb, 0x92, 0x37, 0x1d, 0x21, 0x26, 0xe9, 0x70, 0x03, 0x24, 0x97, 0x75, 0x04, 0xe8, 0xc9, 0x0e]);

export function generateAriaRoundKeys(masterKey: Uint8Array): { encKeys: Uint8Array[]; decKeys: Uint8Array[] } {
  const keyLen = masterKey.length;
  const rounds = keyLen === 16 ? 12 : keyLen === 24 ? 14 : 16;

  const kl = new Uint8Array(16);
  const kr = new Uint8Array(16);
  kl.set(masterKey.slice(0, 16));
  if (keyLen > 16) {
    kr.set(masterKey.slice(16));
  }

  let ck1: Uint8Array, ck2: Uint8Array, ck3: Uint8Array;
  if (keyLen === 16) {
    ck1 = C1; ck2 = C2; ck3 = C3;
  } else if (keyLen === 24) {
    ck1 = C2; ck2 = C3; ck3 = C1;
  } else {
    ck1 = C3; ck2 = C1; ck3 = C2;
  }

  // 3-round Feistel network for W0..W3
  const w0 = kl;
  const w1 = xor128(roundFO(w0, ck1), kr);
  const w2 = xor128(roundFE(w1, ck2), w0);
  const w3 = xor128(roundFO(w2, ck3), w1);

  const ek: Uint8Array[] = [
    new Uint8Array(16), // 1-indexed placeholder
    xor128(w0, rotRight128(w1, 19)),  // ek1
    xor128(w1, rotRight128(w2, 19)),  // ek2
    xor128(w2, rotRight128(w3, 19)),  // ek3
    xor128(rotRight128(w0, 19), w3),  // ek4
    xor128(w0, rotRight128(w1, 31)),  // ek5
    xor128(w1, rotRight128(w2, 31)),  // ek6
    xor128(w2, rotRight128(w3, 31)),  // ek7
    xor128(rotRight128(w0, 31), w3),  // ek8
    xor128(w0, rotLeft128(w1, 61)),   // ek9
    xor128(w1, rotLeft128(w2, 61)),   // ek10
    xor128(w2, rotLeft128(w3, 61)),   // ek11
    xor128(rotLeft128(w0, 61), w3),   // ek12
    xor128(w0, rotLeft128(w1, 31)),   // ek13
    xor128(w1, rotLeft128(w2, 31)),   // ek14
    xor128(w2, rotLeft128(w3, 31)),   // ek15
    xor128(rotLeft128(w0, 31), w3),   // ek16
    xor128(w0, rotLeft128(w1, 19)),   // ek17
  ];

  // Decryption round keys: dk1 = ek_{rounds+1}, dk2 = A(ek_{rounds}), ..., dk_{rounds+1} = ek1
  const dk: Uint8Array[] = new Array(rounds + 2);
  dk[1] = ek[rounds + 1];
  for (let r = 2; r <= rounds; r++) {
    dk[r] = diffLayerA(ek[rounds + 2 - r]);
  }
  dk[rounds + 1] = ek[1];

  return { encKeys: ek.slice(1, rounds + 2), decKeys: dk.slice(1, rounds + 2) };
}

// Block Transformation (Used for both Encryption and Decryption)
export function ariaTransformBlock(block: Uint8Array, roundKeys: Uint8Array[], rounds: number): Uint8Array {
  let p = new Uint8Array(block);

  for (let r = 1; r < rounds; r++) {
    const rk = roundKeys[r - 1];
    p = new Uint8Array(r % 2 === 1 ? roundFO(p, rk) : roundFE(p, rk));
  }

  // Final Round (Round rounds): SL2(P_{rounds-1} ^ ek_{rounds}) ^ ek_{rounds+1}
  const ekLast = roundKeys[rounds - 1];
  const ekFinal = roundKeys[rounds];
  const t = xor128(p, ekLast);
  const finalSub = sLayer2(t);
  return xor128(finalSub, ekFinal);
}

export function ariaEncryptBlock(block: Uint8Array, encKeys: Uint8Array[], rounds: number): Uint8Array {
  return ariaTransformBlock(block, encKeys, rounds);
}

export function ariaDecryptBlock(block: Uint8Array, decKeys: Uint8Array[], rounds: number): Uint8Array {
  return ariaTransformBlock(block, decKeys, rounds);
}

export type AriaMode = 'CBC' | 'ECB' | 'CTR' | 'GCM' | 'CCM' | 'OFB' | 'CFB';
export type AriaPadding = BlockPaddingType;

export interface AriaEncryptParams {
  plaintext: Uint8Array;
  key: Uint8Array;
  iv?: Uint8Array;
  mode?: AriaMode;
  padding?: AriaPadding;
  aad?: Uint8Array;
}

export interface AriaEncryptResult {
  ciphertext: Uint8Array;
  tag?: Uint8Array;
  iv: Uint8Array;
}

export interface AriaDecryptParams {
  ciphertext: Uint8Array;
  key: Uint8Array;
  iv?: Uint8Array;
  mode?: AriaMode;
  padding?: AriaPadding;
  tag?: Uint8Array;
  aad?: Uint8Array;
}

export function ariaEncrypt(params: AriaEncryptParams): AriaEncryptResult {
  const { plaintext, key, aad } = params;
  const mode = params.mode || 'CBC';
  const padding = params.padding || 'PKCS7';
  let iv = params.iv;

  if (![16, 24, 32].includes(key.length)) {
    throw new NodeError('INVALID_KEY_LENGTH', `Invalid ARIA key length: ${key.length} bytes`);
  }

  const rounds = key.length === 16 ? 12 : key.length === 24 ? 14 : 16;
  const { encKeys } = generateAriaRoundKeys(key);
  const blockEncrypt = (b: Uint8Array) => ariaTransformBlock(b, encKeys, rounds);

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

  if (mode === 'OFB') {
    const actualIv = iv && iv.length === 16 ? iv : new Uint8Array(16);
    return ofbMode(blockEncrypt, plaintext, actualIv);
  }

  if (mode === 'CFB') {
    const actualIv = iv && iv.length === 16 ? iv : new Uint8Array(16);
    return cfbModeEncrypt(blockEncrypt, plaintext, actualIv);
  }

  const data = applyBlockPadding(plaintext, padding, 16);
  const ciphertext = new Uint8Array(data.length);
  const actualIv = iv || (mode === 'CBC' ? new Uint8Array(16) : new Uint8Array(0));
  let prevBlock = new Uint8Array(actualIv);

  for (let i = 0; i < data.length; i += 16) {
    const block = new Uint8Array(data.slice(i, i + 16));
    if (mode === 'CBC') {
      for (let b = 0; b < 16; b++) block[b] ^= prevBlock[b];
    }
    const encryptedBlock = ariaTransformBlock(block, encKeys, rounds);
    ciphertext.set(encryptedBlock, i);
    prevBlock = new Uint8Array(encryptedBlock);
  }

  return { ciphertext, iv: actualIv };
}

export function ariaDecrypt(params: AriaDecryptParams): Uint8Array {
  const { ciphertext, key, tag, aad, iv } = params;
  const mode = params.mode || 'CBC';
  const padding = params.padding || 'PKCS7';

  if (![16, 24, 32].includes(key.length)) throw new NodeError('INVALID_KEY_LENGTH', 'Invalid ARIA key length');

  const rounds = key.length === 16 ? 12 : key.length === 24 ? 14 : 16;
  const { encKeys, decKeys } = generateAriaRoundKeys(key);
  const blockEncrypt = (b: Uint8Array) => ariaTransformBlock(b, encKeys, rounds);

  if (mode === 'GCM') {
    const actualIv = iv ?? new Uint8Array(12);
    if (actualIv.length !== 12) throw new NodeError('INVALID_NONCE_LENGTH', 'ARIA-GCM decryption requires a 12-byte IV');
    if (!tag || tag.length !== 16) throw new NodeError('INVALID_TAG_LENGTH', 'ARIA-GCM decryption requires a 16-byte tag');
    return gcmModeDecrypt(blockEncrypt, ciphertext, actualIv, tag, aad);
  }

  if (mode === 'CCM') {
    const actualNonce = iv ?? new Uint8Array(12);
    if (!tag) throw new NodeError('INVALID_TAG_LENGTH', 'ARIA-CCM decryption requires a tag');
    return ccmModeDecrypt(blockEncrypt, ciphertext, actualNonce, tag, aad);
  }

  if (mode === 'CTR') {
    const actualIv = iv ?? new Uint8Array(16);
    if (actualIv.length !== 16) throw new NodeError('INVALID_IV_LENGTH', 'ARIA-CTR decryption requires a 16-byte counter');
    return ctrMode(blockEncrypt, ciphertext, actualIv).ciphertext;
  }

  if (mode === 'OFB') {
    const actualIv = iv ?? new Uint8Array(16);
    if (actualIv.length !== 16) throw new NodeError('INVALID_IV_LENGTH', 'ARIA-OFB decryption requires a 16-byte IV');
    return ofbMode(blockEncrypt, ciphertext, actualIv).ciphertext;
  }

  if (mode === 'CFB') {
    const actualIv = iv ?? new Uint8Array(16);
    if (actualIv.length !== 16) throw new NodeError('INVALID_IV_LENGTH', 'ARIA-CFB decryption requires a 16-byte IV');
    return cfbModeDecrypt(blockEncrypt, ciphertext, actualIv);
  }

  if (ciphertext.length % 16 !== 0) throw new NodeError('CIPHERTEXT_NOT_BLOCK_ALIGNED', 'Ciphertext must be a multiple of 16 bytes');

  const plaintext = new Uint8Array(ciphertext.length);
  const actualIv = iv || new Uint8Array(16);
  let prevBlock = new Uint8Array(actualIv);

  for (let i = 0; i < ciphertext.length; i += 16) {
    const block = new Uint8Array(ciphertext.slice(i, i + 16));
    const rawBlock = new Uint8Array(block);
    const decryptedBlock = ariaTransformBlock(block, decKeys, rounds);

    if (mode === 'CBC') {
      for (let b = 0; b < 16; b++) decryptedBlock[b] ^= prevBlock[b];
      prevBlock = rawBlock;
    }
    plaintext.set(decryptedBlock, i);
  }

  return removeBlockPadding(plaintext, padding, 16);
}

