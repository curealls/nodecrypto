/**
 * Generic 128-bit Block Cipher Modes of Operation
 * Conforms to NIST SP 800-38A (CBC, CTR, OFB, CFB),
 * NIST SP 800-38C (CCM), NIST SP 800-38D (GCM), and IEEE 1619 (XTS)
 */

import { GHASH } from '@noble/ciphers/_polyval.js';
import { NodeError } from '../../dag/errors';

export type BlockCipherFn = (block: Uint8Array) => Uint8Array;

// 1. Output Feedback Mode (OFB) - NIST SP 800-38A §6.4
export function ofbMode(
  encryptBlock: BlockCipherFn,
  data: Uint8Array,
  iv: Uint8Array
): { ciphertext: Uint8Array; iv: Uint8Array } {
  if (iv.length !== 16) {
    throw new NodeError('INVALID_IV_LENGTH', `OFB mode requires a 16-byte IV, got ${iv.length}`);
  }

  const out = new Uint8Array(data.length);
  let feedback: any = new Uint8Array(iv);

  for (let i = 0; i < data.length; i += 16) {
    feedback = encryptBlock(feedback);
    const chunkSize = Math.min(16, data.length - i);
    for (let j = 0; j < chunkSize; j++) {
      out[i + j] = data[i + j] ^ feedback[j];
    }
  }

  return { ciphertext: out, iv };
}

// 2. Cipher Feedback Mode (CFB-128) - NIST SP 800-38A §6.3
export function cfbModeEncrypt(
  encryptBlock: BlockCipherFn,
  plaintext: Uint8Array,
  iv: Uint8Array
): { ciphertext: Uint8Array; iv: Uint8Array } {
  if (iv.length !== 16) {
    throw new NodeError('INVALID_IV_LENGTH', `CFB mode requires a 16-byte IV, got ${iv.length}`);
  }

  const ciphertext = new Uint8Array(plaintext.length);
  let prevBlock = new Uint8Array(iv);

  for (let i = 0; i < plaintext.length; i += 16) {
    const stream = encryptBlock(prevBlock);
    const chunkSize = Math.min(16, plaintext.length - i);
    const nextFeedback = new Uint8Array(16);
    for (let j = 0; j < chunkSize; j++) {
      ciphertext[i + j] = plaintext[i + j] ^ stream[j];
      nextFeedback[j] = ciphertext[i + j];
    }
    prevBlock = nextFeedback;
  }

  return { ciphertext, iv };
}

export function cfbModeDecrypt(
  encryptBlock: BlockCipherFn,
  ciphertext: Uint8Array,
  iv: Uint8Array
): Uint8Array {
  if (iv.length !== 16) {
    throw new NodeError('INVALID_IV_LENGTH', `CFB mode requires a 16-byte IV, got ${iv.length}`);
  }

  const plaintext = new Uint8Array(ciphertext.length);
  let prevBlock = new Uint8Array(iv);

  for (let i = 0; i < ciphertext.length; i += 16) {
    const stream = encryptBlock(prevBlock);
    const chunkSize = Math.min(16, ciphertext.length - i);
    const nextFeedback = new Uint8Array(16);
    for (let j = 0; j < chunkSize; j++) {
      plaintext[i + j] = ciphertext[i + j] ^ stream[j];
      nextFeedback[j] = ciphertext[i + j];
    }
    prevBlock = nextFeedback;
  }

  return plaintext;
}

// 3. Counter Mode (CTR)
export function ctrMode(
  encryptBlock: BlockCipherFn,
  data: Uint8Array,
  iv: Uint8Array
): { ciphertext: Uint8Array; iv: Uint8Array } {
  if (iv.length !== 16) {
    throw new NodeError('INVALID_IV_LENGTH', `CTR mode requires a 16-byte initial counter, got ${iv.length}`);
  }

  const out = new Uint8Array(data.length);
  const counter = new Uint8Array(iv);

  for (let i = 0; i < data.length; i += 16) {
    const keystream = encryptBlock(counter);
    const chunkSize = Math.min(16, data.length - i);
    for (let j = 0; j < chunkSize; j++) {
      out[i + j] = data[i + j] ^ keystream[j];
    }
    // Increment 128-bit big-endian counter
    for (let c = 15; c >= 0; c--) {
      counter[c] = (counter[c] + 1) & 0xff;
      if (counter[c] !== 0) break;
    }
  }

  return { ciphertext: out, iv };
}

// 4. Galois/Counter Mode (GCM) - NIST SP 800-38D
export function gcmModeEncrypt(
  encryptBlock: BlockCipherFn,
  plaintext: Uint8Array,
  iv: Uint8Array,
  aad?: Uint8Array
): { ciphertext: Uint8Array; tag: Uint8Array; iv: Uint8Array } {
  if (iv.length !== 12) {
    throw new NodeError('INVALID_NONCE_LENGTH', `GCM requires a 12-byte IV/nonce, got ${iv.length}`);
  }

  // 1. Compute H = CIPH_K(0^128)
  const H = encryptBlock(new Uint8Array(16));

  // 2. Initial counter block J0 = IV || 0^31 || 1
  const J0 = new Uint8Array(16);
  J0.set(iv, 0);
  J0[15] = 1;

  // 3. Compute tag mask S0 = CIPH_K(J0)
  const S0 = encryptBlock(J0);

  // 4. Encrypt plaintext with CTR mode starting at J0 + 1
  const counter = new Uint8Array(J0);
  counter[15] = 2; // Increment LSB

  const ciphertext = new Uint8Array(plaintext.length);
  for (let i = 0; i < plaintext.length; i += 16) {
    const keystream = encryptBlock(counter);
    const chunkSize = Math.min(16, plaintext.length - i);
    for (let j = 0; j < chunkSize; j++) {
      ciphertext[i + j] = plaintext[i + j] ^ keystream[j];
    }
    for (let c = 15; c >= 12; c--) {
      counter[c] = (counter[c] + 1) & 0xff;
      if (counter[c] !== 0) break;
    }
  }

  // 5. GHASH authentication over AAD and Ciphertext
  const ghash = new GHASH(H);
  if (aad && aad.length > 0) {
    ghash.update(aad);
  }
  if (ciphertext.length > 0) {
    ghash.update(ciphertext);
  }

  // 6. Append bit length block: [len(AAD)_64 || len(C)_64]
  const lenBlock = new Uint8Array(16);
  const lenView = new DataView(lenBlock.buffer);
  const aadBits = BigInt((aad?.length || 0) * 8);
  const cipherBits = BigInt(ciphertext.length * 8);
  lenView.setBigUint64(0, aadBits, false);
  lenView.setBigUint64(8, cipherBits, false);
  ghash.update(lenBlock);

  const digest = ghash.digest();

  // 7. Tag = GHASH digest ^ S0
  const tag = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    tag[i] = digest[i] ^ S0[i];
  }

  return { ciphertext, tag, iv };
}

export function gcmModeDecrypt(
  encryptBlock: BlockCipherFn,
  ciphertext: Uint8Array,
  iv: Uint8Array,
  tag: Uint8Array,
  aad?: Uint8Array
): Uint8Array {
  if (iv.length !== 12) {
    throw new NodeError('INVALID_NONCE_LENGTH', `GCM requires a 12-byte IV, got ${iv.length}`);
  }
  if (!tag || tag.length !== 16) {
    throw new NodeError('INVALID_TAG_LENGTH', 'GCM requires a 16-byte authentication tag');
  }

  const H = encryptBlock(new Uint8Array(16));
  const J0 = new Uint8Array(16);
  J0.set(iv, 0);
  J0[15] = 1;
  const S0 = encryptBlock(J0);

  const ghash = new GHASH(H);
  if (aad && aad.length > 0) {
    ghash.update(aad);
  }
  if (ciphertext.length > 0) {
    ghash.update(ciphertext);
  }

  const lenBlock = new Uint8Array(16);
  const lenView = new DataView(lenBlock.buffer);
  lenView.setBigUint64(0, BigInt((aad?.length || 0) * 8), false);
  lenView.setBigUint64(8, BigInt(ciphertext.length * 8), false);
  ghash.update(lenBlock);

  const digest = ghash.digest();
  const expectedTag = new Uint8Array(16);
  let mismatch = 0;
  for (let i = 0; i < 16; i++) {
    expectedTag[i] = digest[i] ^ S0[i];
    mismatch |= expectedTag[i] ^ tag[i];
  }

  if (mismatch !== 0) {
    throw new NodeError('AUTH_TAG_MISMATCH', 'GCM authentication failed: invalid tag');
  }

  // Decrypt CTR
  const counter = new Uint8Array(J0);
  counter[15] = 2;
  const plaintext = new Uint8Array(ciphertext.length);
  for (let i = 0; i < ciphertext.length; i += 16) {
    const keystream = encryptBlock(counter);
    const chunkSize = Math.min(16, ciphertext.length - i);
    for (let j = 0; j < chunkSize; j++) {
      plaintext[i + j] = ciphertext[i + j] ^ keystream[j];
    }
    for (let c = 15; c >= 12; c--) {
      counter[c] = (counter[c] + 1) & 0xff;
      if (counter[c] !== 0) break;
    }
  }

  return plaintext;
}

// 5. Counter with CBC-MAC (CCM) - NIST SP 800-38C / RFC 3610
export function ccmModeEncrypt(
  encryptBlock: BlockCipherFn,
  plaintext: Uint8Array,
  nonce: Uint8Array,
  aad?: Uint8Array,
  tagLength: number = 16
): { ciphertext: Uint8Array; tag: Uint8Array; iv: Uint8Array } {
  if (nonce.length < 7 || nonce.length > 13) {
    throw new NodeError('INVALID_NONCE_LENGTH', `CCM nonce length must be between 7 and 13 bytes, got ${nonce.length}`);
  }
  if (![4, 6, 8, 10, 12, 14, 16].includes(tagLength)) {
    throw new NodeError('INVALID_TAG_LENGTH', `Invalid CCM tag length: ${tagLength}`);
  }

  const q = 15 - nonce.length; // Length field size
  const hasAdata = aad && aad.length > 0;
  const adataFlag = hasAdata ? 1 : 0;
  const tField = (tagLength - 2) / 2;

  // Format B0 (Formatting of control information and length)
  const b0 = new Uint8Array(16);
  b0[0] = (adataFlag << 6) | (tField << 3) | (q - 1);
  b0.set(nonce, 1);
  let pLen = plaintext.length;
  for (let i = 0; i < q; i++) {
    b0[15 - i] = pLen & 0xff;
    pLen >>>= 8;
  }

  // CBC-MAC
  let mac = encryptBlock(b0);

  // Format Associated Data (Adata)
  if (hasAdata) {
    const aLen = aad.length;
    let header: Uint8Array;
    if (aLen < 0xff00) {
      header = new Uint8Array([aLen >>> 8, aLen & 0xff]);
    } else {
      header = new Uint8Array([0xff, 0xfe, (aLen >>> 24) & 0xff, (aLen >>> 16) & 0xff, (aLen >>> 8) & 0xff, aLen & 0xff]);
    }
    const fullAdata = new Uint8Array(header.length + aLen);
    fullAdata.set(header);
    fullAdata.set(aad, header.length);

    for (let i = 0; i < fullAdata.length; i += 16) {
      const block = new Uint8Array(16);
      const chunk = fullAdata.slice(i, i + 16);
      block.set(chunk);
      for (let j = 0; j < 16; j++) block[j] ^= mac[j];
      mac = encryptBlock(block);
    }
  }

  // MAC over payload
  for (let i = 0; i < plaintext.length; i += 16) {
    const block = new Uint8Array(16);
    const chunk = plaintext.slice(i, i + 16);
    block.set(chunk);
    for (let j = 0; j < 16; j++) block[j] ^= mac[j];
    mac = encryptBlock(block);
  }

  // CTR Encryption
  // A0: Flags (q-1), Nonce, Counter=0
  const a0 = new Uint8Array(16);
  a0[0] = q - 1;
  a0.set(nonce, 1);
  const s0 = encryptBlock(a0);

  // Tag = MAC[0..M-1] ^ S0[0..M-1]
  const tag = new Uint8Array(tagLength);
  for (let i = 0; i < tagLength; i++) {
    tag[i] = mac[i] ^ s0[i];
  }

  // Encrypt payload with CTR starting at counter 1
  const ciphertext = new Uint8Array(plaintext.length);
  const aBlock = new Uint8Array(a0);
  let ctrVal = 1;

  for (let i = 0; i < plaintext.length; i += 16) {
    let temp = ctrVal;
    for (let k = 0; k < q; k++) {
      aBlock[15 - k] = temp & 0xff;
      temp >>>= 8;
    }
    const keystream = encryptBlock(aBlock);
    const chunkSize = Math.min(16, plaintext.length - i);
    for (let j = 0; j < chunkSize; j++) {
      ciphertext[i + j] = plaintext[i + j] ^ keystream[j];
    }
    ctrVal++;
  }

  return { ciphertext, tag, iv: nonce };
}

export function ccmModeDecrypt(
  encryptBlock: BlockCipherFn,
  ciphertext: Uint8Array,
  nonce: Uint8Array,
  tag: Uint8Array,
  aad?: Uint8Array
): Uint8Array {
  const tagLength = tag.length;
  const q = 15 - nonce.length;

  // Decrypt payload first with CTR
  const a0 = new Uint8Array(16);
  a0[0] = q - 1;
  a0.set(nonce, 1);

  const plaintext = new Uint8Array(ciphertext.length);
  const aBlock = new Uint8Array(a0);
  let ctrVal = 1;

  for (let i = 0; i < ciphertext.length; i += 16) {
    let temp = ctrVal;
    for (let k = 0; k < q; k++) {
      aBlock[15 - k] = temp & 0xff;
      temp >>>= 8;
    }
    const keystream = encryptBlock(aBlock);
    const chunkSize = Math.min(16, ciphertext.length - i);
    for (let j = 0; j < chunkSize; j++) {
      plaintext[i + j] = ciphertext[i + j] ^ keystream[j];
    }
    ctrVal++;
  }

  // Recompute expected tag using ccmModeEncrypt logic
  const reResult = ccmModeEncrypt(encryptBlock, plaintext, nonce, aad, tagLength);
  let mismatch = 0;
  for (let i = 0; i < tagLength; i++) {
    mismatch |= reResult.tag[i] ^ tag[i];
  }

  if (mismatch !== 0) {
    throw new NodeError('AUTH_TAG_MISMATCH', 'CCM authentication failed: invalid tag');
  }

  return plaintext;
}

// 6. XTS Mode (XEX TCB with Ciphertext Stealing) - IEEE 1619
export function xtsModeEncrypt(
  key1Encrypt: BlockCipherFn,
  key2Encrypt: BlockCipherFn,
  plaintext: Uint8Array,
  iTweak: Uint8Array
): { ciphertext: Uint8Array; iv: Uint8Array } {
  if (plaintext.length < 16) {
    throw new NodeError('DATA_TOO_SHORT', 'XTS mode requires at least 16 bytes of plaintext');
  }
  if (iTweak.length !== 16) {
    throw new NodeError('INVALID_IV_LENGTH', `XTS mode requires 16-byte sector/tweak IV, got ${iTweak.length}`);
  }

  let T = key2Encrypt(iTweak);
  const numBlocks = Math.floor(plaintext.length / 16);
  const remainder = plaintext.length % 16;
  const ciphertext = new Uint8Array(plaintext.length);

  for (let b = 0; b < numBlocks; b++) {
    const p = plaintext.slice(b * 16, (b + 1) * 16);
    const pp = new Uint8Array(16);
    for (let j = 0; j < 16; j++) pp[j] = p[j] ^ T[j];
    const cc = key1Encrypt(pp);
    for (let j = 0; j < 16; j++) cc[j] ^= T[j];
    ciphertext.set(cc, b * 16);

    // T = T * alpha in GF(2^128)
    T = xtsMulAlpha(T);
  }

  if (remainder > 0) {
    // Ciphertext stealing for last partial block
    const prevC = ciphertext.slice((numBlocks - 1) * 16, numBlocks * 16);
    const lastP = plaintext.slice(numBlocks * 16);
    const stolen = new Uint8Array(16);
    stolen.set(lastP);
    stolen.set(prevC.slice(remainder), remainder);

    const pp = new Uint8Array(16);
    for (let j = 0; j < 16; j++) pp[j] = stolen[j] ^ T[j];
    const cc = key1Encrypt(pp);
    for (let j = 0; j < 16; j++) cc[j] ^= T[j];

    ciphertext.set(cc, (numBlocks - 1) * 16);
    ciphertext.set(prevC.slice(0, remainder), numBlocks * 16);
  }

  return { ciphertext, iv: iTweak };
}

export function xtsModeDecrypt(
  key1Decrypt: BlockCipherFn,
  key2Encrypt: BlockCipherFn,
  ciphertext: Uint8Array,
  iTweak: Uint8Array
): Uint8Array {
  if (ciphertext.length < 16) {
    throw new NodeError('DATA_TOO_SHORT', 'XTS mode requires at least 16 bytes of ciphertext');
  }
  if (iTweak.length !== 16) {
    throw new NodeError('INVALID_IV_LENGTH', `XTS mode requires 16-byte sector/tweak IV, got ${iTweak.length}`);
  }

  let T = key2Encrypt(iTweak);
  const numBlocks = Math.floor(ciphertext.length / 16);
  const remainder = ciphertext.length % 16;
  const plaintext = new Uint8Array(ciphertext.length);

  const tweaks: Uint8Array[] = [];
  for (let b = 0; b <= numBlocks; b++) {
    tweaks.push(new Uint8Array(T));
    T = xtsMulAlpha(T);
  }

  for (let b = 0; b < (remainder > 0 ? numBlocks - 1 : numBlocks); b++) {
    const c = ciphertext.slice(b * 16, (b + 1) * 16);
    const cc = new Uint8Array(16);
    for (let j = 0; j < 16; j++) cc[j] = c[j] ^ tweaks[b][j];
    const pp = key1Decrypt(cc);
    for (let j = 0; j < 16; j++) pp[j] ^= tweaks[b][j];
    plaintext.set(pp, b * 16);
  }

  if (remainder > 0) {
    // Stealing inverse
    const m = numBlocks - 1;
    const cM = ciphertext.slice(m * 16, (m + 1) * 16);
    const ccM = new Uint8Array(16);
    for (let j = 0; j < 16; j++) ccM[j] = cM[j] ^ tweaks[m + 1][j];
    const ppM = key1Decrypt(ccM);
    for (let j = 0; j < 16; j++) ppM[j] ^= tweaks[m + 1][j];

    const cLast = ciphertext.slice((m + 1) * 16);
    const stolenC = new Uint8Array(16);
    stolenC.set(cLast);
    stolenC.set(ppM.slice(remainder), remainder);

    const ccStolen = new Uint8Array(16);
    for (let j = 0; j < 16; j++) ccStolen[j] = stolenC[j] ^ tweaks[m][j];
    const ppStolen = key1Decrypt(ccStolen);
    for (let j = 0; j < 16; j++) ppStolen[j] ^= tweaks[m][j];

    plaintext.set(ppStolen, m * 16);
    plaintext.set(ppM.slice(0, remainder), (m + 1) * 16);
  }

  return plaintext;
}

function xtsMulAlpha(t: Uint8Array): Uint8Array {
  const out = new Uint8Array(16);
  let carry = 0;
  for (let i = 0; i < 16; i++) {
    const nextCarry = (t[i] >>> 7) & 1;
    out[i] = ((t[i] << 1) | carry) & 0xff;
    carry = nextCarry;
  }
  if (carry !== 0) {
    out[0] ^= 0x87;
  }
  return out;
}
