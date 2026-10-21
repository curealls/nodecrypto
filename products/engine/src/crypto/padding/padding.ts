/**
 * Standard Cryptographic Block Padding Algorithms
 */

import { NodeError } from '../../dag/errors';

export function pkcs7Pad(data: Uint8Array, blockSize: number = 16): Uint8Array {
  const padLen = blockSize - (data.length % blockSize);
  const padded = new Uint8Array(data.length + padLen);
  padded.set(data);
  padded.fill(padLen, data.length);
  return padded;
}

export function pkcs7Unpad(data: Uint8Array, blockSize: number = 16): Uint8Array {
  if (data.length === 0 || data.length % blockSize !== 0) {
    throw new NodeError('INVALID_PADDING', 'Invalid PKCS#7 padded data length');
  }
  const padLen = data[data.length - 1];
  if (padLen === 0 || padLen > blockSize) {
    throw new NodeError('INVALID_PADDING', 'Invalid PKCS#7 padding bytes');
  }
  for (let i = data.length - padLen; i < data.length; i++) {
    if (data[i] !== padLen) {
      throw new NodeError('INVALID_PADDING', 'Invalid PKCS#7 padding byte mismatch');
    }
  }
  return new Uint8Array(data.slice(0, data.length - padLen));
}

/**
 * ISO/IEC 9797-1 Padding Method 2 (Add 0x80, then pad with 0x00 up to block boundary)
 */
export function iso9797M2Pad(data: Uint8Array, blockSize: number = 8): Uint8Array {
  const padLen = blockSize - ((data.length + 1) % blockSize);
  const actualPad = (data.length + 1) % blockSize === 0 ? 1 : padLen + 1;
  const padded = new Uint8Array(data.length + actualPad);
  padded.set(data);
  padded[data.length] = 0x80;
  padded.fill(0x00, data.length + 1);
  return padded;
}

export function iso9797M2Unpad(data: Uint8Array): Uint8Array {
  for (let i = data.length - 1; i >= 0; i--) {
    if (data[i] === 0x80) {
      return new Uint8Array(data.slice(0, i));
    }
    if (data[i] !== 0x00) {
      throw new NodeError('INVALID_PADDING', 'Invalid ISO 9797-1 M2 padding bytes');
    }
  }
  throw new NodeError('INVALID_PADDING', 'ISO 9797-1 M2 padding 0x80 delimiter not found');
}

export function zeroPad(data: Uint8Array, blockSize: number = 16): Uint8Array {
  const rem = data.length % blockSize;
  if (rem === 0) return data;
  const padLen = blockSize - rem;
  const padded = new Uint8Array(data.length + padLen);
  padded.set(data);
  return padded;
}

export function zeroUnpad(data: Uint8Array): Uint8Array {
  let end = data.length;
  while (end > 0 && data[end - 1] === 0) {
    end--;
  }
  return data.slice(0, end);
}

/**
 * ANSI X9.23 Padding (0x00...0x00 followed by pad length)
 */
export function ansiX923Pad(data: Uint8Array, blockSize: number = 16): Uint8Array {
  const padLen = blockSize - (data.length % blockSize);
  const padded = new Uint8Array(data.length + padLen);
  padded.set(data);
  padded.fill(0x00, data.length, data.length + padLen - 1);
  padded[data.length + padLen - 1] = padLen;
  return padded;
}

export function ansiX923Unpad(data: Uint8Array, blockSize: number = 16): Uint8Array {
  if (data.length === 0 || data.length % blockSize !== 0) {
    throw new NodeError('INVALID_PADDING', 'Invalid ANSI X9.23 padded data length');
  }
  const padLen = data[data.length - 1];
  if (padLen === 0 || padLen > blockSize) {
    throw new NodeError('INVALID_PADDING', 'Invalid ANSI X9.23 padding byte count');
  }
  for (let i = data.length - padLen; i < data.length - 1; i++) {
    if (data[i] !== 0x00) {
      throw new NodeError('INVALID_PADDING', 'Invalid ANSI X9.23 zero byte mismatch');
    }
  }
  return new Uint8Array(data.slice(0, data.length - padLen));
}

/**
 * ISO/IEC 7816-4 Padding (0x80 followed by 0x00 up to block boundary)
 */
export function iso7816Pad(data: Uint8Array, blockSize: number = 16): Uint8Array {
  return iso9797M2Pad(data, blockSize);
}

export function iso7816Unpad(data: Uint8Array): Uint8Array {
  return iso9797M2Unpad(data);
}

/**
 * ISO/IEC 9797-1 Padding Method 3 (length-prefix block, big-endian byte count of the
 * original data, sized to the block length) followed by Method 1 zero-padding.
 * Defined for MAC computation (e.g. ISO 9797-1 MAC Algorithm 3 / ANSI X9.19 Retail MAC);
 * reused here as a general block padding since the explicit length prefix makes it
 * unambiguously reversible.
 */
export function iso97971M3Pad(data: Uint8Array, blockSize: number = 16): Uint8Array {
  const lengthBlock = new Uint8Array(blockSize);
  let len = BigInt(data.length);
  for (let i = blockSize - 1; i >= 0 && len > 0n; i--) {
    lengthBlock[i] = Number(len & 0xffn);
    len >>= 8n;
  }
  const prefixed = new Uint8Array(blockSize + data.length);
  prefixed.set(lengthBlock);
  prefixed.set(data, blockSize);
  return zeroPad(prefixed, blockSize);
}

export function iso97971M3Unpad(data: Uint8Array, blockSize: number = 16): Uint8Array {
  if (data.length < blockSize) {
    throw new NodeError('INVALID_PADDING', 'Invalid ISO 9797-1 M3 padded data: shorter than the length-prefix block');
  }
  let originalLength = 0;
  for (let i = 0; i < blockSize; i++) {
    originalLength = originalLength * 256 + data[i];
  }
  if (originalLength < 0 || blockSize + originalLength > data.length) {
    throw new NodeError('INVALID_PADDING', 'Invalid ISO 9797-1 M3 padding: length prefix out of range');
  }
  return new Uint8Array(data.slice(blockSize, blockSize + originalLength));
}

/**
 * NIST SP 800-38B padding function (as used to derive the CMAC last-block subkey):
 * appends 0x80 then 0x00 up to the block boundary, but adds NOTHING when the data is
 * already a multiple of the block size. Unlike ISO/IEC 9797-1 Method 2, which always
 * inserts a marker, this makes the result ambiguous to reverse in general (an aligned
 * message is indistinguishable from a padded one), so no unpad counterpart is provided --
 * this scheme is intentionally pad-only (see BlockPaddingType/PADDING_OPTIONS_* split).
 */
export function nist80038bPad(data: Uint8Array, blockSize: number = 16): Uint8Array {
  if (data.length % blockSize === 0) {
    return data;
  }
  return iso9797M2Pad(data, blockSize);
}

export type BlockPaddingType =
  | 'PKCS7'
  | 'ANSIX923'
  | 'ISO7816'
  | 'Zero'
  | 'ISO97971M3'
  | 'NIST80038B'
  | 'None';

export function applyBlockPadding(data: Uint8Array, padding: BlockPaddingType = 'PKCS7', blockSize: number = 16): Uint8Array {
  switch (padding) {
    case 'PKCS7':
      return pkcs7Pad(data, blockSize);
    case 'ANSIX923':
      return ansiX923Pad(data, blockSize);
    case 'ISO7816':
      return iso7816Pad(data, blockSize);
    case 'Zero':
      return zeroPad(data, blockSize);
    case 'ISO97971M3':
      return iso97971M3Pad(data, blockSize);
    case 'NIST80038B':
      return nist80038bPad(data, blockSize);
    case 'None':
      if (data.length % blockSize !== 0) {
        throw new NodeError('PLAINTEXT_NOT_BLOCK_ALIGNED', `Data length (${data.length}) must be a multiple of block size (${blockSize}) when padding is None`);
      }
      return data;
    default:
      throw new NodeError('UNSUPPORTED_PADDING', `Unsupported padding type: ${padding}`);
  }
}

export function removeBlockPadding(data: Uint8Array, padding: BlockPaddingType = 'PKCS7', blockSize: number = 16): Uint8Array {
  switch (padding) {
    case 'PKCS7':
      return pkcs7Unpad(data, blockSize);
    case 'ANSIX923':
      return ansiX923Unpad(data, blockSize);
    case 'ISO7816':
      return iso7816Unpad(data);
    case 'Zero':
      return zeroUnpad(data);
    case 'ISO97971M3':
      return iso97971M3Unpad(data, blockSize);
    case 'NIST80038B':
      throw new NodeError('UNSUPPORTED_PADDING', 'NIST SP 800-38B padding is pad-only (MAC subkey derivation use); it cannot be reliably unpadded.');
    case 'None':
      return data;
    default:
      throw new NodeError('UNSUPPORTED_PADDING', `Unsupported padding type: ${padding}`);
  }
}

/**
 * MGF1 (Mask Generation Function 1) with SHA-256 (RFC 8017 Appendix B.2.1)
 */
import { sha256 } from '@noble/hashes/sha2.js';

export function mgf1Sha256(seed: Uint8Array, maskLen: number): Uint8Array {
  const mask = new Uint8Array(maskLen);
  let offset = 0;
  let counter = 0;
  while (offset < maskLen) {
    const c = new Uint8Array(4);
    new DataView(c.buffer).setUint32(0, counter, false);
    const combined = new Uint8Array(seed.length + 4);
    combined.set(seed);
    combined.set(c, seed.length);
    const hash = sha256(combined);
    const copyLen = Math.min(hash.length, maskLen - offset);
    mask.set(hash.subarray(0, copyLen), offset);
    offset += copyLen;
    counter++;
  }
  return mask;
}

/**
 * RSA-OAEP Encoding (RFC 8017 §7.1.1) with SHA-256
 */
export function rsaOaepEncode(
  message: Uint8Array,
  emLen: number,
  label: Uint8Array = new Uint8Array(0),
  seed?: Uint8Array
): Uint8Array {
  const hLen = 32; // SHA-256
  const mLen = message.length;
  if (mLen > emLen - 2 * hLen - 2) {
    throw new NodeError('OAEP_MESSAGE_TOO_LONG', 'Message too long for RSA-OAEP encoding');
  }

  const lHash = sha256(label);
  const psLen = emLen - mLen - 2 * hLen - 2;
  const db = new Uint8Array(hLen + psLen + 1 + mLen);
  db.set(lHash, 0);
  db.fill(0x00, hLen, hLen + psLen);
  db[hLen + psLen] = 0x01;
  db.set(message, hLen + psLen + 1);

  const actualSeed = seed && seed.length === hLen ? seed : crypto.getRandomValues(new Uint8Array(hLen));
  const dbMask = mgf1Sha256(actualSeed, emLen - hLen - 1);
  const maskedDb = new Uint8Array(db.length);
  for (let i = 0; i < db.length; i++) maskedDb[i] = db[i] ^ dbMask[i];

  const seedMask = mgf1Sha256(maskedDb, hLen);
  const maskedSeed = new Uint8Array(hLen);
  for (let i = 0; i < hLen; i++) maskedSeed[i] = actualSeed[i] ^ seedMask[i];

  const em = new Uint8Array(emLen);
  em[0] = 0x00;
  em.set(maskedSeed, 1);
  em.set(maskedDb, 1 + hLen);
  return em;
}

/**
 * RSA-OAEP Decoding (RFC 8017 §7.1.2) with SHA-256
 */
export function rsaOaepDecode(
  em: Uint8Array,
  label: Uint8Array = new Uint8Array(0)
): Uint8Array {
  const hLen = 32; // SHA-256
  const emLen = em.length;
  if (emLen < 2 * hLen + 2 || em[0] !== 0x00) {
    throw new NodeError('INVALID_OAEP_PADDING', 'Invalid RSA-OAEP encoded message');
  }

  const maskedSeed = em.slice(1, 1 + hLen);
  const maskedDb = em.slice(1 + hLen);

  const seedMask = mgf1Sha256(maskedDb, hLen);
  const seed = new Uint8Array(hLen);
  for (let i = 0; i < hLen; i++) seed[i] = maskedSeed[i] ^ seedMask[i];

  const dbMask = mgf1Sha256(seed, emLen - hLen - 1);
  const db = new Uint8Array(maskedDb.length);
  for (let i = 0; i < db.length; i++) db[i] = maskedDb[i] ^ dbMask[i];

  const lHash = sha256(label);
  for (let i = 0; i < hLen; i++) {
    if (db[i] !== lHash[i]) throw new NodeError('INVALID_OAEP_PADDING', 'RSA-OAEP label hash mismatch');
  }

  let separatorIndex = -1;
  for (let i = hLen; i < db.length; i++) {
    if (db[i] === 0x01) {
      separatorIndex = i;
      break;
    } else if (db[i] !== 0x00) {
      throw new NodeError('INVALID_OAEP_PADDING', 'Invalid RSA-OAEP padding structure');
    }
  }

  if (separatorIndex === -1) {
    throw new NodeError('INVALID_OAEP_PADDING', 'RSA-OAEP separator 0x01 not found');
  }

  return db.slice(separatorIndex + 1);
}

/**
 * RSA-PSS EMSA-PSS Encoding (RFC 8017 §9.1.1) with SHA-256
 */
export function rsaPssEncode(
  mHash: Uint8Array,
  emBits: number,
  saltLength: number = 32,
  saltInput?: Uint8Array
): Uint8Array {
  const hLen = 32;
  const emLen = Math.ceil(emBits / 8);
  const sLen = saltLength;

  if (mHash.length !== hLen) {
    throw new NodeError('INVALID_PSS_PARAMS', `Encoding error: message hash must be ${hLen} bytes, got ${mHash.length}`);
  }
  if (emLen < hLen + sLen + 2) {
    throw new NodeError('INVALID_PSS_PARAMS', 'Encoding error: emLen too small for PSS parameters');
  }

  if (saltInput && saltInput.length !== sLen) {
    throw new NodeError('INVALID_PSS_PARAMS', `Encoding error: salt must be ${sLen} bytes (Salt Length), got ${saltInput.length}`);
  }
  const salt = saltInput ?? crypto.getRandomValues(new Uint8Array(sLen));
  const mPrime = new Uint8Array(8 + hLen + sLen);
  mPrime.fill(0x00, 0, 8);
  mPrime.set(mHash, 8);
  mPrime.set(salt, 8 + hLen);
  const h = sha256(mPrime);

  const psLen = emLen - sLen - hLen - 2;
  const db = new Uint8Array(psLen + 1 + sLen);
  db.fill(0x00, 0, psLen);
  db[psLen] = 0x01;
  db.set(salt, psLen + 1);

  const dbMask = mgf1Sha256(h, emLen - hLen - 1);
  const maskedDb = new Uint8Array(db.length);
  for (let i = 0; i < db.length; i++) maskedDb[i] = db[i] ^ dbMask[i];

  // Clear leftmost unused bits
  const unusedBits = 8 * emLen - emBits;
  if (unusedBits > 0) {
    maskedDb[0] &= (0xff >>> unusedBits);
  }

  const em = new Uint8Array(emLen);
  em.set(maskedDb, 0);
  em.set(h, maskedDb.length);
  em[emLen - 1] = 0xbc;
  return em;
}
