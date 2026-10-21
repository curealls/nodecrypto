/**
 * Pure TypeScript SM4 Block Cipher Implementation
 * Chinese National Standard GB/T 32907-2016 / GM/T 0002-2012 / RFC 8998
 * 128-bit block, 128-bit key, 32-round Unbalanced Feistel Network
 */

import { applyBlockPadding, removeBlockPadding, BlockPaddingType } from '../padding/padding';
import { gcmModeEncrypt, gcmModeDecrypt, ctrMode } from './modes';
import { NodeError } from '../../dag/errors';

// SM4 S-box
const SBOX: Uint8Array = new Uint8Array([
  0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
  0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
  0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
  0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
  0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
  0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
  0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
  0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
  0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
  0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
  0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
  0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
  0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
  0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
  0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
  0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
]);

// System Parameter FK
const FK = new Uint32Array([0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc]);

// Constant Parameter CK (32 words)
const CK = new Uint32Array(32);
for (let i = 0; i < 32; i++) {
  const b0 = (4 * i * 7) & 0xff;
  const b1 = (4 * i * 7 + 7) & 0xff;
  const b2 = (4 * i * 7 + 14) & 0xff;
  const b3 = (4 * i * 7 + 21) & 0xff;
  CK[i] = ((b0 << 24) | (b1 << 16) | (b2 << 8) | b3) >>> 0;
}

function rotl(x: number, n: number): number {
  return ((x << n) | (x >>> (32 - n))) >>> 0;
}

function sm4ByteSub(w: number): number {
  const b0 = SBOX[(w >>> 24) & 0xff];
  const b1 = SBOX[(w >>> 16) & 0xff];
  const b2 = SBOX[(w >>> 8) & 0xff];
  const b3 = SBOX[w & 0xff];
  return ((b0 << 24) | (b1 << 16) | (b2 << 8) | b3) >>> 0;
}

// Linear transform L for encryption
function sm4L(b: number): number {
  return (b ^ rotl(b, 2) ^ rotl(b, 10) ^ rotl(b, 18) ^ rotl(b, 24)) >>> 0;
}

// Linear transform L' for key schedule
function sm4LKey(b: number): number {
  return (b ^ rotl(b, 13) ^ rotl(b, 23)) >>> 0;
}

function sm4KeySchedule(keyBytes: Uint8Array): Uint32Array {
  if (keyBytes.length !== 16) {
    throw new NodeError('INVALID_KEY_LENGTH', `SM4 requires 128-bit (16 bytes) key, got ${keyBytes.length}`);
  }

  const k = new Uint32Array(36);
  for (let i = 0; i < 4; i++) {
    const idx = i * 4;
    k[i] = (((keyBytes[idx] << 24) | (keyBytes[idx + 1] << 16) | (keyBytes[idx + 2] << 8) | keyBytes[idx + 3]) ^ FK[i]) >>> 0;
  }

  const roundKeys = new Uint32Array(32);
  for (let i = 0; i < 32; i++) {
    const tmp = (k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ CK[i]) >>> 0;
    k[i + 4] = (k[i] ^ sm4LKey(sm4ByteSub(tmp))) >>> 0;
    roundKeys[i] = k[i + 4];
  }

  return roundKeys;
}

function sm4ProcessBlock(inBlock: Uint8Array, roundKeys: Uint32Array): Uint8Array {
  const x = new Uint32Array(36);
  for (let i = 0; i < 4; i++) {
    const idx = i * 4;
    x[i] = ((inBlock[idx] << 24) | (inBlock[idx + 1] << 16) | (inBlock[idx + 2] << 8) | inBlock[idx + 3]) >>> 0;
  }

  for (let r = 0; r < 32; r++) {
    const tmp = (x[r + 1] ^ x[r + 2] ^ x[r + 3] ^ roundKeys[r]) >>> 0;
    x[r + 4] = (x[r] ^ sm4L(sm4ByteSub(tmp))) >>> 0;
  }

  const out = new Uint8Array(16);
  // Reverse order x35, x34, x33, x32
  for (let i = 0; i < 4; i++) {
    const w = x[35 - i];
    out[i * 4] = (w >>> 24) & 0xff;
    out[i * 4 + 1] = (w >>> 16) & 0xff;
    out[i * 4 + 2] = (w >>> 8) & 0xff;
    out[i * 4 + 3] = w & 0xff;
  }

  return out;
}

export type Sm4Mode = 'CBC' | 'ECB' | 'CTR' | 'GCM';
export type Sm4Padding = BlockPaddingType;

export interface Sm4EncryptParams {
  plaintext: Uint8Array;
  key: Uint8Array;
  iv?: Uint8Array;
  mode?: Sm4Mode;
  padding?: Sm4Padding;
  aad?: Uint8Array;
}

export interface Sm4EncryptResult {
  ciphertext: Uint8Array;
  tag?: Uint8Array;
  iv: Uint8Array;
}

export function sm4Encrypt(params: Sm4EncryptParams): Sm4EncryptResult {
  const { plaintext, key, aad } = params;
  const mode = params.mode || 'CBC';
  const padding = params.padding || 'PKCS7';

  if (key.length !== 16) {
    throw new NodeError('INVALID_KEY_LENGTH', `SM4 requires a 16-byte key, got ${key.length}`);
  }

  const roundKeys = sm4KeySchedule(key);
  const blockEncrypt = (b: Uint8Array) => sm4ProcessBlock(b, roundKeys);

  // Deterministic 0x00-fill default when IV/nonce is omitted (PRD §4.3 common rule) -- not a
  // random value, so the same inputs always produce the same output. Prototyping/debugging
  // convenience only; real deployments must always supply a random, non-reused IV/nonce.
  if (mode === 'GCM') {
    const actualIv = params.iv && params.iv.length === 12 ? params.iv : new Uint8Array(12);
    return gcmModeEncrypt(blockEncrypt, plaintext, actualIv, aad);
  }

  if (mode === 'CTR') {
    const actualIv = params.iv && params.iv.length === 16 ? params.iv : new Uint8Array(16);
    return ctrMode(blockEncrypt, plaintext, actualIv);
  }

  const data = applyBlockPadding(plaintext, padding, 16);
  const actualIv = params.iv || (mode !== 'ECB' ? new Uint8Array(16) : new Uint8Array(0));
  const ciphertext = new Uint8Array(data.length);

  if (mode === 'ECB') {
    for (let i = 0; i < data.length; i += 16) {
      const block = data.slice(i, i + 16);
      ciphertext.set(sm4ProcessBlock(block, roundKeys), i);
    }
  } else if (mode === 'CBC') {
    let prevBlock: Uint8Array = actualIv;
    for (let i = 0; i < data.length; i += 16) {
      const block = new Uint8Array(data.slice(i, i + 16));
      for (let b = 0; b < 16; b++) block[b] ^= prevBlock[b];
      const enc = sm4ProcessBlock(block, roundKeys);
      ciphertext.set(enc, i);
      prevBlock = enc;
    }
  }

  return { ciphertext, iv: actualIv };
}

export interface Sm4DecryptParams {
  ciphertext: Uint8Array;
  key: Uint8Array;
  iv?: Uint8Array;
  mode?: Sm4Mode;
  padding?: Sm4Padding;
  tag?: Uint8Array;
  aad?: Uint8Array;
}

export function sm4Decrypt(params: Sm4DecryptParams): Uint8Array {
  const { ciphertext, key, iv, tag, aad } = params;
  const mode = params.mode || 'CBC';
  const padding = params.padding || 'PKCS7';

  if (key.length !== 16) {
    throw new NodeError('INVALID_KEY_LENGTH', 'SM4 requires a 16-byte key');
  }

  const encRoundKeys = sm4KeySchedule(key);
  const blockEncrypt = (b: Uint8Array) => sm4ProcessBlock(b, encRoundKeys);

  if (mode === 'GCM') {
    const actualGcmIv = iv ?? new Uint8Array(12);
    if (actualGcmIv.length !== 12) throw new NodeError('INVALID_NONCE_LENGTH', 'SM4-GCM decryption requires a 12-byte IV');
    if (!tag || tag.length !== 16) throw new NodeError('INVALID_TAG_LENGTH', 'SM4-GCM decryption requires a 16-byte tag');
    return gcmModeDecrypt(blockEncrypt, ciphertext, actualGcmIv, tag, aad);
  }

  if (mode === 'CTR') {
    const actualCtrIv = iv ?? new Uint8Array(16);
    if (actualCtrIv.length !== 16) throw new NodeError('INVALID_IV_LENGTH', 'SM4-CTR decryption requires a 16-byte counter');
    return ctrMode(blockEncrypt, ciphertext, actualCtrIv).ciphertext;
  }

  if (ciphertext.length % 16 !== 0) {
    throw new NodeError('CIPHERTEXT_NOT_BLOCK_ALIGNED', 'Ciphertext length must be multiple of 16 bytes for SM4');
  }

  // Decryption uses reversed round keys
  const decRoundKeys = new Uint32Array(32);
  for (let i = 0; i < 32; i++) {
    decRoundKeys[i] = encRoundKeys[31 - i];
  }

  const actualIv = params.iv || new Uint8Array(16);
  const plaintext = new Uint8Array(ciphertext.length);

  if (mode === 'ECB') {
    for (let i = 0; i < ciphertext.length; i += 16) {
      const block = ciphertext.slice(i, i + 16);
      plaintext.set(sm4ProcessBlock(block, decRoundKeys), i);
    }
  } else if (mode === 'CBC') {
    let prevBlock = new Uint8Array(actualIv);
    for (let i = 0; i < ciphertext.length; i += 16) {
      const block = ciphertext.slice(i, i + 16);
      const dec = sm4ProcessBlock(block, decRoundKeys);
      for (let b = 0; b < 16; b++) {
        dec[b] ^= prevBlock[b];
      }
      plaintext.set(dec, i);
      prevBlock = new Uint8Array(block);
    }
  }

  return removeBlockPadding(plaintext, padding, 16);
}

