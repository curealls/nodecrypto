/**
 * Pure TypeScript DES & Triple-DES (3DES / TDES) Implementation
 * Supports 2-Key (112-bit / 16 bytes), 3-Key (168-bit / 24 bytes), and Single DES (56-bit / 8 bytes)
 * in ECB and CBC modes, 8-byte block (see BlockPaddingType for the full padding option set).
 */

import { applyBlockPadding, removeBlockPadding, BlockPaddingType } from '../padding/padding';
import { NodeError } from '../../dag/errors';

// DES Initial & Final Permutations and S-Boxes
const IP = [
  58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
  62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
  57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
  61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
];

const FP = [
  40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
  38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
  36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
  34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
];

const PC1_C = [
  57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
  10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
];

const PC1_D = [
  63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
  14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4,
];

const PC2 = [
  14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
  23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
  41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
  44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
];

const SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];

const E = [
  32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9,
  8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
  16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
  24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
];

const P = [
  16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
  2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25,
];

const S_BOXES = [
  // S1
  [
    14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
    0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
    4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
    15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13,
  ],
  // S2
  [
    15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
    3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
    0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
    13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9,
  ],
  // S3
  [
    10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
    13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
    13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
    1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,
  ],
  // S4
  [
    7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
    13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
    10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
    3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14,
  ],
  // S5
  [
    2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
    14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
    4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
    11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3,
  ],
  // S6
  [
    12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
    10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
    9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
    4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13,
  ],
  // S7
  [
    4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
    13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
    1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
    6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12,
  ],
  // S8
  [
    13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
    1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
    7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
    2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11,
  ],
];

function getBit(bytes: Uint8Array, bitIndex: number): number {
  const byte = bytes[Math.floor((bitIndex - 1) / 8)];
  const bit = 7 - ((bitIndex - 1) % 8);
  return (byte >> bit) & 1;
}

function setBit(bytes: Uint8Array, bitIndex: number, val: number): void {
  const byteIdx = Math.floor((bitIndex - 1) / 8);
  const bit = 7 - ((bitIndex - 1) % 8);
  if (val) {
    bytes[byteIdx] |= 1 << bit;
  } else {
    bytes[byteIdx] &= ~(1 << bit);
  }
}

function permute(src: Uint8Array, table: number[], outLenBits: number): Uint8Array {
  const out = new Uint8Array(Math.ceil(outLenBits / 8));
  for (let i = 0; i < table.length; i++) {
    const bit = getBit(src, table[i]);
    setBit(out, i + 1, bit);
  }
  return out;
}

function generateSubkeys(key: Uint8Array): Uint8Array[] {
  const c = new Uint8Array(4);
  const d = new Uint8Array(4);

  for (let i = 0; i < 28; i++) {
    setBit(c, i + 1, getBit(key, PC1_C[i]));
    setBit(d, i + 1, getBit(key, PC1_D[i]));
  }

  let cVal = ((c[0] << 24) | (c[1] << 16) | (c[2] << 8) | c[3]) >>> 4;
  let dVal = ((d[0] << 24) | (d[1] << 16) | (d[2] << 8) | d[3]) >>> 4;

  const subkeys: Uint8Array[] = [];

  for (let r = 0; r < 16; r++) {
    const shift = SHIFTS[r];
    cVal = ((cVal << shift) | (cVal >>> (28 - shift))) & 0x0fffffff;
    dVal = ((dVal << shift) | (dVal >>> (28 - shift))) & 0x0fffffff;

    const cd = new Uint8Array(7);
    const combined = ((BigInt(cVal) << 28n) | BigInt(dVal));
    for (let b = 0; b < 7; b++) {
      cd[b] = Number((combined >> BigInt((6 - b) * 8)) & 0xffn);
    }

    subkeys.push(permute(cd, PC2, 48));
  }

  return subkeys;
}

function desBlock(block: Uint8Array, subkeys: Uint8Array[], isDecrypt: boolean): Uint8Array {
  const ip = permute(block, IP, 64);
  let l = (ip[0] << 24) | (ip[1] << 16) | (ip[2] << 8) | ip[3];
  let r = (ip[4] << 24) | (ip[5] << 16) | (ip[6] << 8) | ip[7];

  const keys = isDecrypt ? [...subkeys].reverse() : subkeys;

  for (let round = 0; round < 16; round++) {
    const rBytes = new Uint8Array([
      (r >>> 24) & 0xff,
      (r >>> 16) & 0xff,
      (r >>> 8) & 0xff,
      r & 0xff,
    ]);
    const expanded = permute(rBytes, E, 48);

    // XOR with subkey
    for (let i = 0; i < 6; i++) {
      expanded[i] ^= keys[round][i];
    }

    // S-Boxes
    const sOut = new Uint8Array(4);
    for (let s = 0; s < 8; s++) {
      const bitStart = s * 6 + 1;
      const row = (getBit(expanded, bitStart) << 1) | getBit(expanded, bitStart + 5);
      const col =
        (getBit(expanded, bitStart + 1) << 3) |
        (getBit(expanded, bitStart + 2) << 2) |
        (getBit(expanded, bitStart + 3) << 1) |
        getBit(expanded, bitStart + 4);

      const val = S_BOXES[s][row * 16 + col];
      const outByte = Math.floor(s / 2);
      if (s % 2 === 0) {
        sOut[outByte] |= val << 4;
      } else {
        sOut[outByte] |= val;
      }
    }

    const pOut = permute(sOut, P, 32);
    const fVal = (pOut[0] << 24) | (pOut[1] << 16) | (pOut[2] << 8) | pOut[3];

    const nextL = r;
    const nextR = l ^ fVal;
    l = nextL;
    r = nextR;
  }

  const preOut = new Uint8Array([
    (r >>> 24) & 0xff,
    (r >>> 16) & 0xff,
    (r >>> 8) & 0xff,
    r & 0xff,
    (l >>> 24) & 0xff,
    (l >>> 16) & 0xff,
    (l >>> 8) & 0xff,
    l & 0xff,
  ]);

  return permute(preOut, FP, 64);
}

/**
 * Triple-DES (EDE: Encrypt-Decrypt-Encrypt) for a single 8-byte block
 */
export function tdesBlock(block: Uint8Array, key: Uint8Array, isDecrypt: boolean): Uint8Array {
  let k1: Uint8Array, k2: Uint8Array, k3: Uint8Array;

  if (key.length === 8) {
    k1 = k2 = k3 = key;
  } else if (key.length === 16) {
    k1 = key.slice(0, 8);
    k2 = key.slice(8, 16);
    k3 = k1; // 2-Key 3DES: K1-K2-K1
  } else if (key.length === 24) {
    k1 = key.slice(0, 8);
    k2 = key.slice(8, 16);
    k3 = key.slice(16, 24);
  } else {
    throw new NodeError('INVALID_KEY_LENGTH', `Invalid 3DES key length: ${key.length} bytes`);
  }

  const subkeys1 = generateSubkeys(k1);
  const subkeys2 = generateSubkeys(k2);
  const subkeys3 = generateSubkeys(k3);

  if (!isDecrypt) {
    // EDE: Encrypt(K1) -> Decrypt(K2) -> Encrypt(K3)
    const step1 = desBlock(block, subkeys1, false);
    const step2 = desBlock(step1, subkeys2, true);
    return desBlock(step2, subkeys3, false);
  } else {
    // DED: Decrypt(K3) -> Encrypt(K2) -> Decrypt(K1)
    const step1 = desBlock(block, subkeys3, true);
    const step2 = desBlock(step1, subkeys2, false);
    return desBlock(step2, subkeys1, true);
  }
}

export type TdesMode = 'CBC' | 'ECB';
export type TdesPadding = BlockPaddingType;
export interface TdesResult {
  ciphertext: Uint8Array;
  iv: Uint8Array;
}

export function tdesEncrypt(
  plaintext: Uint8Array,
  key: Uint8Array,
  iv?: Uint8Array,
  mode: TdesMode = 'CBC',
  padding: TdesPadding = 'PKCS7'
): TdesResult {
  const data = applyBlockPadding(plaintext, padding, 8);
  if (data.length % 8 !== 0) {
    throw new NodeError('PLAINTEXT_NOT_BLOCK_ALIGNED', 'Data length must be multiple of 8 bytes for 3DES');
  }

  const ciphertext = new Uint8Array(data.length);
  const actualIv = iv || (mode === 'CBC' ? crypto.getRandomValues(new Uint8Array(8)) : new Uint8Array(0));
  let prevBlock = new Uint8Array(actualIv);

  for (let i = 0; i < data.length; i += 8) {
    const block = new Uint8Array(data.slice(i, i + 8));
    if (mode === 'CBC') {
      for (let b = 0; b < 8; b++) {
        block[b] ^= prevBlock[b];
      }
    }
    const encryptedBlock = tdesBlock(block, key, false);
    ciphertext.set(encryptedBlock, i);
    prevBlock = new Uint8Array(encryptedBlock);
  }

  return { ciphertext, iv: actualIv };
}

export function tdesDecrypt(
  ciphertext: Uint8Array,
  key: Uint8Array,
  iv?: Uint8Array,
  mode: 'CBC' | 'ECB' = 'CBC',
  padding: TdesPadding = 'PKCS7'
): Uint8Array {
  if (key.length !== 8 && key.length !== 16 && key.length !== 24) {
    throw new NodeError('INVALID_KEY_LENGTH', 'Key length must be 8 (DES), 16 (2-Key 3DES), or 24 (3-Key 3DES) bytes');
  }
  if (ciphertext.length % 8 !== 0) {
    throw new NodeError('CIPHERTEXT_NOT_BLOCK_ALIGNED', 'Ciphertext length must be multiple of 8 bytes for 3DES');
  }

  const plaintext = new Uint8Array(ciphertext.length);
  const actualIv = iv || new Uint8Array(8);
  let prevBlock = new Uint8Array(actualIv);

  for (let i = 0; i < ciphertext.length; i += 8) {
    const block = new Uint8Array(ciphertext.slice(i, i + 8));
    const decryptedBlock = tdesBlock(block, key, true);
    if (mode === 'CBC') {
      for (let b = 0; b < 8; b++) {
        decryptedBlock[b] ^= prevBlock[b];
      }
      prevBlock = block;
    }
    plaintext.set(decryptedBlock, i);
  }

  return removeBlockPadding(plaintext, padding, 8);
}
