/**
 * Pure TypeScript Camellia Block Cipher Implementation
 * Conforms strictly to RFC 3713 / ISO/IEC 18033-3
 * 128-bit block, 128/192/256-bit keys in ECB, CBC, CTR, and GCM modes
 */

import { applyBlockPadding, removeBlockPadding, BlockPaddingType } from '../padding/padding';
import { gcmModeEncrypt, gcmModeDecrypt, ctrMode } from './modes';
import { NodeError } from '../../dag/errors';

// Camellia S-Box 1 (S1) - RFC 3713 Section 2.4.1
const SBOX1 = new Uint8Array([
  112, 130,  44, 236, 179,  39, 192, 229, 228, 133,  87,  53, 234,  12, 174,  65,
   35, 239, 107, 147,  69,  25, 165,  33, 237,  14,  79,  78,  29, 101, 146, 189,
  134, 184, 175, 143, 124, 235,  31, 206,  62,  48, 220,  95,  94, 197,  11,  26,
  166, 225,  57, 202, 213,  71,  93,  61, 217,   1,  90, 214,  81,  86, 108,  77,
  139,  13, 154, 102, 251, 204, 176,  45, 116,  18,  43,  32, 240, 177, 132, 153,
  223,  76, 203, 194,  52, 126, 118,   5, 109, 183, 169,  49, 209,  23,   4, 215,
   20,  88,  58,  97, 222,  27,  17,  28,  50,  15, 156,  22,  83,  24, 242,  34,
  254,  68, 207, 178, 195, 181, 122, 145,  36,   8, 232, 168,  96, 252, 105,  80,
  170, 208, 160, 125, 161, 137,  98, 151,  84,  91,  30, 149, 224, 255, 100, 210,
   16, 196,   0,  72, 163, 247, 117, 219, 138,   3, 230, 218,   9,  63, 221, 148,
  135,  92, 131,   2, 205,  74, 144,  51, 115, 103, 246, 243, 157, 127, 191, 226,
   82, 155, 216,  38, 200,  55, 198,  59, 129, 150, 111,  75,  19, 190,  99,  46,
  233, 121, 167, 140, 159, 110, 188, 142,  41, 245, 249, 182,  47, 253, 180,  89,
  120, 152,   6, 106, 231,  70, 113, 186, 212,  37, 171,  66, 136, 162, 141, 250,
  114,   7, 185,  85, 248, 238, 172,  10,  54,  73,  42, 104,  60,  56, 241, 164,
   64,  40, 211, 123, 187, 201,  67, 193,  21, 227, 173, 244, 119, 199, 128, 158,
]);

function rotl8(x: number, n: number): number {
  return ((x << n) | (x >>> (8 - n))) & 0xff;
}

const SBOX2 = new Uint8Array(256);
const SBOX3 = new Uint8Array(256);
const SBOX4 = new Uint8Array(256);
for (let i = 0; i < 256; i++) {
  SBOX2[i] = rotl8(SBOX1[i], 1);
  SBOX3[i] = rotl8(SBOX1[i], 7);
  SBOX4[i] = SBOX1[rotl8(i, 1)];
}

// F-function (RFC 3713 Section 2.4.1)
function F(F_IN: bigint, KE: bigint): bigint {
  const x = F_IN ^ KE;
  const t1 = SBOX1[Number((x >> 56n) & 0xffn)];
  const t2 = SBOX2[Number((x >> 48n) & 0xffn)];
  const t3 = SBOX3[Number((x >> 40n) & 0xffn)];
  const t4 = SBOX4[Number((x >> 32n) & 0xffn)];
  const t5 = SBOX2[Number((x >> 24n) & 0xffn)];
  const t6 = SBOX3[Number((x >> 16n) & 0xffn)];
  const t7 = SBOX4[Number((x >> 8n) & 0xffn)];
  const t8 = SBOX1[Number(x & 0xffn)];

  const y1 = BigInt(t1 ^ t3 ^ t4 ^ t6 ^ t7 ^ t8);
  const y2 = BigInt(t1 ^ t2 ^ t4 ^ t5 ^ t7 ^ t8);
  const y3 = BigInt(t1 ^ t2 ^ t3 ^ t5 ^ t6 ^ t8);
  const y4 = BigInt(t2 ^ t3 ^ t4 ^ t5 ^ t6 ^ t7);
  const y5 = BigInt(t1 ^ t2 ^ t6 ^ t7 ^ t8);
  const y6 = BigInt(t2 ^ t3 ^ t5 ^ t7 ^ t8);
  const y7 = BigInt(t3 ^ t4 ^ t5 ^ t6 ^ t8);
  const y8 = BigInt(t1 ^ t4 ^ t5 ^ t6 ^ t7);

  return (
    (y1 << 56n) |
    (y2 << 48n) |
    (y3 << 40n) |
    (y4 << 32n) |
    (y5 << 24n) |
    (y6 << 16n) |
    (y7 << 8n) |
    y8
  );
}

// FL and FLINV functions (RFC 3713 Section 2.4.2)
function FL(FL_IN: bigint, KE: bigint): bigint {
  let y1 = FL_IN >> 32n;
  let y2 = FL_IN & 0xffffffffn;
  const k1 = KE >> 32n;
  const k2 = KE & 0xffffffffn;
  const rot = (((y1 & k1) << 1n) | ((y1 & k1) >> 31n)) & 0xffffffffn;
  y2 = y2 ^ rot;
  y1 = (y1 ^ (y2 | k2)) & 0xffffffffn;
  return (y1 << 32n) | y2;
}

function FLINV(FLINV_IN: bigint, KE: bigint): bigint {
  let y1 = FLINV_IN >> 32n;
  let y2 = FLINV_IN & 0xffffffffn;
  const k1 = KE >> 32n;
  const k2 = KE & 0xffffffffn;
  y1 = (y1 ^ (y2 | k2)) & 0xffffffffn;
  const rot = (((y1 & k1) << 1n) | ((y1 & k1) >> 31n)) & 0xffffffffn;
  y2 = y2 ^ rot;
  return (y1 << 32n) | y2;
}

// 128-bit circular left shift
function rotl128(x: bigint, n: bigint): bigint {
  const s = n % 128n;
  return ((x << s) | (x >> (128n - s))) & 0xffffffffffffffffffffffffffffffffn;
}

// Sigma constants (RFC 3713 Section 2.2)
const SIGMA = [
  0xa09e667f3bcc908bn,
  0xb67ae8584caa73b2n,
  0xc6ef372fe94f82ben,
  0x54ff53a5f1d36f1cn,
  0x10e527fde688d802n,
  0xb05688c2b3e6c1fdn,
];

// Key Schedule for 128-bit keys
function camelliaKeySchedule128(key: Uint8Array): bigint[] {
  const view = new DataView(key.buffer, key.byteOffset, 16);
  const klHigh = view.getBigUint64(0, false);
  const klLow = view.getBigUint64(8, false);
  const KL = (klHigh << 64n) | klLow;
  const KR = 0n;

  let D1 = (KL ^ KR) >> 64n;
  let D2 = (KL ^ KR) & 0xffffffffffffffffn;

  D2 = D2 ^ F(D1, SIGMA[0]);
  D1 = D1 ^ F(D2, SIGMA[1]);
  D1 = D1 ^ (KL >> 64n);
  D2 = D2 ^ (KL & 0xffffffffffffffffn);
  D2 = D2 ^ F(D1, SIGMA[2]);
  D1 = D1 ^ F(D2, SIGMA[3]);
  const KA = (D1 << 64n) | D2;

  const MASK64 = 0xffffffffffffffffn;

  return [
    (rotl128(KL, 0n) >> 64n) & MASK64,
    rotl128(KL, 0n) & MASK64,
    (rotl128(KA, 0n) >> 64n) & MASK64,
    rotl128(KA, 0n) & MASK64,
    (rotl128(KL, 15n) >> 64n) & MASK64,
    rotl128(KL, 15n) & MASK64,
    (rotl128(KA, 15n) >> 64n) & MASK64,
    rotl128(KA, 15n) & MASK64,
    (rotl128(KA, 30n) >> 64n) & MASK64,
    rotl128(KA, 30n) & MASK64,
    (rotl128(KL, 45n) >> 64n) & MASK64,
    rotl128(KL, 45n) & MASK64,
    (rotl128(KA, 45n) >> 64n) & MASK64,
    rotl128(KL, 60n) & MASK64,
    (rotl128(KA, 60n) >> 64n) & MASK64,
    rotl128(KA, 60n) & MASK64,
    (rotl128(KL, 77n) >> 64n) & MASK64,
    rotl128(KL, 77n) & MASK64,
    (rotl128(KL, 94n) >> 64n) & MASK64,
    rotl128(KL, 94n) & MASK64,
    (rotl128(KA, 94n) >> 64n) & MASK64,
    rotl128(KA, 94n) & MASK64,
    (rotl128(KL, 111n) >> 64n) & MASK64,
    rotl128(KL, 111n) & MASK64,
    (rotl128(KA, 111n) >> 64n) & MASK64,
    rotl128(KA, 111n) & MASK64,
  ];
}

// Key Schedule for 192/256-bit keys (RFC 3713 Section 2.2)
function camelliaKeySchedule192_256(key: Uint8Array): bigint[] {
  const buf = new Uint8Array(32);
  buf.set(key);
  if (key.length === 24) {
    // KR = KR_L || ~KR_L
    for (let i = 0; i < 8; i++) {
      buf[24 + i] = ~buf[16 + i];
    }
  }

  const view = new DataView(buf.buffer, buf.byteOffset, 32);
  const klHigh = view.getBigUint64(0, false);
  const klLow = view.getBigUint64(8, false);
  const krHigh = view.getBigUint64(16, false);
  const krLow = view.getBigUint64(24, false);

  const KL = (klHigh << 64n) | klLow;
  const KR = (krHigh << 64n) | krLow;

  let D1 = (KL ^ KR) >> 64n;
  let D2 = (KL ^ KR) & 0xffffffffffffffffn;
  D2 = D2 ^ F(D1, SIGMA[0]);
  D1 = D1 ^ F(D2, SIGMA[1]);
  D1 = D1 ^ (KL >> 64n);
  D2 = D2 ^ (KL & 0xffffffffffffffffn);
  D2 = D2 ^ F(D1, SIGMA[2]);
  D1 = D1 ^ F(D2, SIGMA[3]);
  const KA = (D1 << 64n) | D2;

  D1 = (KA ^ KR) >> 64n;
  D2 = (KA ^ KR) & 0xffffffffffffffffn;
  D2 = D2 ^ F(D1, SIGMA[4]);
  D1 = D1 ^ F(D2, SIGMA[5]);
  const KB = (D1 << 64n) | D2;

  const MASK64 = 0xffffffffffffffffn;

  return [
    // kw1, kw2
    (rotl128(KL, 0n) >> 64n) & MASK64,
    rotl128(KL, 0n) & MASK64,
    // k1..k6
    (rotl128(KB, 0n) >> 64n) & MASK64,
    rotl128(KB, 0n) & MASK64,
    (rotl128(KR, 15n) >> 64n) & MASK64,
    rotl128(KR, 15n) & MASK64,
    (rotl128(KA, 15n) >> 64n) & MASK64,
    rotl128(KA, 15n) & MASK64,
    // ke1, ke2
    (rotl128(KR, 30n) >> 64n) & MASK64,
    rotl128(KR, 30n) & MASK64,
    // k7..k12
    (rotl128(KB, 30n) >> 64n) & MASK64,
    rotl128(KB, 30n) & MASK64,
    (rotl128(KL, 45n) >> 64n) & MASK64,
    rotl128(KL, 45n) & MASK64,
    (rotl128(KA, 45n) >> 64n) & MASK64,
    rotl128(KA, 45n) & MASK64,
    // ke3, ke4
    (rotl128(KL, 60n) >> 64n) & MASK64,
    rotl128(KL, 60n) & MASK64,
    // k13..k18
    (rotl128(KR, 60n) >> 64n) & MASK64,
    rotl128(KR, 60n) & MASK64,
    (rotl128(KB, 60n) >> 64n) & MASK64,
    rotl128(KB, 60n) & MASK64,
    (rotl128(KL, 77n) >> 64n) & MASK64,
    rotl128(KL, 77n) & MASK64,
    // ke5, ke6
    (rotl128(KA, 77n) >> 64n) & MASK64,
    rotl128(KA, 77n) & MASK64,
    // k19..k24
    (rotl128(KR, 94n) >> 64n) & MASK64,
    rotl128(KR, 94n) & MASK64,
    (rotl128(KA, 94n) >> 64n) & MASK64,
    rotl128(KA, 94n) & MASK64,
    (rotl128(KL, 111n) >> 64n) & MASK64,
    rotl128(KL, 111n) & MASK64,
    // kw3, kw4
    (rotl128(KB, 111n) >> 64n) & MASK64,
    rotl128(KB, 111n) & MASK64,
  ];
}

function camelliaEncryptBlock(block: Uint8Array, subkeys: bigint[]): Uint8Array {
  const view = new DataView(block.buffer, block.byteOffset, 16);
  let D1 = view.getBigUint64(0, false);
  let D2 = view.getBigUint64(8, false);

  if (subkeys.length === 26) {
    // 128-bit (18 rounds)
    const [
      kw1, kw2,
      k1, k2, k3, k4, k5, k6,
      ke1, ke2,
      k7, k8, k9, k10, k11, k12,
      ke3, ke4,
      k13, k14, k15, k16, k17, k18,
      kw3, kw4,
    ] = subkeys;

    D1 ^= kw1; D2 ^= kw2;
    D2 ^= F(D1, k1); D1 ^= F(D2, k2);
    D2 ^= F(D1, k3); D1 ^= F(D2, k4);
    D2 ^= F(D1, k5); D1 ^= F(D2, k6);
    D1 = FL(D1, ke1); D2 = FLINV(D2, ke2);
    D2 ^= F(D1, k7); D1 ^= F(D2, k8);
    D2 ^= F(D1, k9); D1 ^= F(D2, k10);
    D2 ^= F(D1, k11); D1 ^= F(D2, k12);
    D1 = FL(D1, ke3); D2 = FLINV(D2, ke4);
    D2 ^= F(D1, k13); D1 ^= F(D2, k14);
    D2 ^= F(D1, k15); D1 ^= F(D2, k16);
    D2 ^= F(D1, k17); D1 ^= F(D2, k18);
    D2 ^= kw3; D1 ^= kw4;
  } else {
    // 192/256-bit (24 rounds)
    const [
      kw1, kw2,
      k1, k2, k3, k4, k5, k6,
      ke1, ke2,
      k7, k8, k9, k10, k11, k12,
      ke3, ke4,
      k13, k14, k15, k16, k17, k18,
      ke5, ke6,
      k19, k20, k21, k22, k23, k24,
      kw3, kw4,
    ] = subkeys;

    D1 ^= kw1; D2 ^= kw2;
    D2 ^= F(D1, k1); D1 ^= F(D2, k2);
    D2 ^= F(D1, k3); D1 ^= F(D2, k4);
    D2 ^= F(D1, k5); D1 ^= F(D2, k6);
    D1 = FL(D1, ke1); D2 = FLINV(D2, ke2);
    D2 ^= F(D1, k7); D1 ^= F(D2, k8);
    D2 ^= F(D1, k9); D1 ^= F(D2, k10);
    D2 ^= F(D1, k11); D1 ^= F(D2, k12);
    D1 = FL(D1, ke3); D2 = FLINV(D2, ke4);
    D2 ^= F(D1, k13); D1 ^= F(D2, k14);
    D2 ^= F(D1, k15); D1 ^= F(D2, k16);
    D2 ^= F(D1, k17); D1 ^= F(D2, k18);
    D1 = FL(D1, ke5); D2 = FLINV(D2, ke6);
    D2 ^= F(D1, k19); D1 ^= F(D2, k20);
    D2 ^= F(D1, k21); D1 ^= F(D2, k22);
    D2 ^= F(D1, k23); D1 ^= F(D2, k24);
    D2 ^= kw3; D1 ^= kw4;
  }

  const out = new Uint8Array(16);
  const outView = new DataView(out.buffer, out.byteOffset, 16);
  outView.setBigUint64(0, D2, false);
  outView.setBigUint64(8, D1, false);
  return out;
}

function getDecryptionSubkeys(subkeys: bigint[]): bigint[] {
  if (subkeys.length === 26) {
    const [
      kw1, kw2,
      k1, k2, k3, k4, k5, k6,
      ke1, ke2,
      k7, k8, k9, k10, k11, k12,
      ke3, ke4,
      k13, k14, k15, k16, k17, k18,
      kw3, kw4,
    ] = subkeys;

    return [
      kw3, kw4,
      k18, k17, k16, k15, k14, k13,
      ke4, ke3,
      k12, k11, k10, k9, k8, k7,
      ke2, ke1,
      k6, k5, k4, k3, k2, k1,
      kw1, kw2,
    ];
  } else {
    const [
      kw1, kw2,
      k1, k2, k3, k4, k5, k6,
      ke1, ke2,
      k7, k8, k9, k10, k11, k12,
      ke3, ke4,
      k13, k14, k15, k16, k17, k18,
      ke5, ke6,
      k19, k20, k21, k22, k23, k24,
      kw3, kw4,
    ] = subkeys;

    return [
      kw3, kw4,
      k24, k23, k22, k21, k20, k19,
      ke6, ke5,
      k18, k17, k16, k15, k14, k13,
      ke4, ke3,
      k12, k11, k10, k9, k8, k7,
      ke2, ke1,
      k6, k5, k4, k3, k2, k1,
      kw1, kw2,
    ];
  }
}

export type CamelliaMode = 'CBC' | 'ECB' | 'CTR' | 'GCM';
export type CamelliaPadding = BlockPaddingType;

export interface CamelliaEncryptParams {
  plaintext: Uint8Array;
  key: Uint8Array;
  iv?: Uint8Array;
  mode?: CamelliaMode;
  padding?: CamelliaPadding;
  aad?: Uint8Array;
}

export interface CamelliaEncryptResult {
  ciphertext: Uint8Array;
  tag?: Uint8Array;
  iv: Uint8Array;
}

export interface CamelliaDecryptParams {
  ciphertext: Uint8Array;
  key: Uint8Array;
  iv?: Uint8Array;
  mode?: CamelliaMode;
  padding?: CamelliaPadding;
  tag?: Uint8Array;
  aad?: Uint8Array;
}

export function camelliaEncrypt(params: CamelliaEncryptParams): CamelliaEncryptResult {
  const { plaintext, key, aad } = params;
  const mode = params.mode || 'CBC';
  const padding = params.padding || 'PKCS7';

  if (![16, 24, 32].includes(key.length)) {
    throw new NodeError('INVALID_KEY_LENGTH', `Camellia supports 128 (16B), 192 (24B), and 256 (32B) keys, got ${key.length} bytes`);
  }

  const subkeys = key.length === 16 ? camelliaKeySchedule128(key) : camelliaKeySchedule192_256(key);
  const blockEncrypt = (b: Uint8Array) => camelliaEncryptBlock(b, subkeys);

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
  const actualIv = params.iv || (mode === 'CBC' ? new Uint8Array(16) : new Uint8Array(0));
  const ciphertext = new Uint8Array(data.length);

  if (mode === 'ECB') {
    for (let i = 0; i < data.length; i += 16) {
      ciphertext.set(camelliaEncryptBlock(data.slice(i, i + 16), subkeys), i);
    }
  } else if (mode === 'CBC') {
    let prev = actualIv;
    for (let i = 0; i < data.length; i += 16) {
      const block = data.slice(i, i + 16);
      const xored = new Uint8Array(16);
      for (let j = 0; j < 16; j++) xored[j] = block[j] ^ prev[j];
      const enc = camelliaEncryptBlock(xored, subkeys);
      ciphertext.set(enc, i);
      prev = enc;
    }
  }

  return { ciphertext, iv: actualIv };
}

export function camelliaDecrypt(params: CamelliaDecryptParams): Uint8Array {
  const { ciphertext, key, iv, tag, aad } = params;
  const mode = params.mode || 'CBC';
  const padding = params.padding || 'PKCS7';

  if (![16, 24, 32].includes(key.length)) {
    throw new NodeError('INVALID_KEY_LENGTH', `Camellia supports 16, 24, or 32-byte keys, got ${key.length} bytes`);
  }

  const encSubkeys = key.length === 16 ? camelliaKeySchedule128(key) : camelliaKeySchedule192_256(key);
  const decSubkeys = getDecryptionSubkeys(encSubkeys);
  const blockEncrypt = (b: Uint8Array) => camelliaEncryptBlock(b, encSubkeys);

  if (mode === 'GCM') {
    const actualIv = iv ?? new Uint8Array(12);
    if (actualIv.length !== 12) throw new NodeError('INVALID_NONCE_LENGTH', 'Camellia-GCM decryption requires a 12-byte IV');
    if (!tag || tag.length !== 16) throw new NodeError('INVALID_TAG_LENGTH', 'Camellia-GCM decryption requires a 16-byte tag');
    return gcmModeDecrypt(blockEncrypt, ciphertext, actualIv, tag, aad);
  }

  if (mode === 'CTR') {
    const actualIv = iv ?? new Uint8Array(16);
    if (actualIv.length !== 16) throw new NodeError('INVALID_IV_LENGTH', 'Camellia-CTR decryption requires a 16-byte counter');
    return ctrMode(blockEncrypt, ciphertext, actualIv).ciphertext;
  }

  if (ciphertext.length % 16 !== 0) throw new NodeError('CIPHERTEXT_NOT_BLOCK_ALIGNED', 'Ciphertext must be a multiple of 16 bytes');

  const plaintext = new Uint8Array(ciphertext.length);
  if (mode === 'ECB') {
    for (let i = 0; i < ciphertext.length; i += 16) {
      plaintext.set(camelliaEncryptBlock(ciphertext.slice(i, i + 16), decSubkeys), i);
    }
  } else if (mode === 'CBC') {
    const actualIv = iv ?? new Uint8Array(16);
    if (actualIv.length !== 16) throw new NodeError('INVALID_IV_LENGTH', 'IV (16 bytes) is required for Camellia CBC decryption');
    let prev = new Uint8Array(actualIv);
    for (let i = 0; i < ciphertext.length; i += 16) {
      const block = ciphertext.slice(i, i + 16);
      const dec = camelliaEncryptBlock(block, decSubkeys);
      for (let j = 0; j < 16; j++) plaintext[i + j] = dec[j] ^ prev[j];
      prev = block;
    }
  }

  return removeBlockPadding(plaintext, padding, 16);
}
