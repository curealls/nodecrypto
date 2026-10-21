import { hmac } from '@noble/hashes/hmac.js';
import { sha256, sha512 } from '@noble/hashes/sha2.js';
import { sha3_256 } from '@noble/hashes/sha3.js';
import { aesEncrypt } from '../symmetric/aes';
import { tdesEncrypt } from '../symmetric/tdes';
import { NodeError } from '../../dag/errors';

export type HmacHash = 'SHA-256' | 'SHA-512' | 'SHA3-256';

export function computeHmac(key: Uint8Array, message: Uint8Array, hash: HmacHash = 'SHA-256'): Uint8Array {
  switch (hash) {
    case 'SHA-256':
      return hmac(sha256, key, message);
    case 'SHA-512':
      return hmac(sha512, key, message);
    case 'SHA3-256':
      return hmac(sha3_256, key, message);
    default:
      throw new NodeError('UNSUPPORTED_ALGORITHM', `Unsupported HMAC hash: ${hash}`);
  }
}

/**
 * NIST SP 800-38B CMAC (Cipher-based Message Authentication Code)
 * Supports AES-128/256 (16-byte block) and 3DES (8-byte block)
 */
export function computeCmac(key: Uint8Array, message: Uint8Array, cipher: 'AES' | '3DES' = 'AES'): Uint8Array {
  const blockSize = cipher === 'AES' ? 16 : 8;
  const zeroBlock = new Uint8Array(blockSize);

  // 1. Generate Subkeys K1, K2
  const l =
    cipher === 'AES'
      ? aesEncrypt({ key, plaintext: zeroBlock, mode: 'ECB', padding: 'None' }).ciphertext
      : tdesEncrypt(zeroBlock, key, undefined, 'ECB', 'None').ciphertext;

  const Rb = cipher === 'AES' ? 0x87 : 0x1b; // Polynomial constant

  // Shift left 1 bit
  const shiftLeft = (bytes: Uint8Array): { shifted: Uint8Array; carry: number } => {
    const out = new Uint8Array(bytes.length);
    let carry = 0;
    for (let i = bytes.length - 1; i >= 0; i--) {
      const nextCarry = (bytes[i] & 0x80) ? 1 : 0;
      out[i] = ((bytes[i] << 1) | carry) & 0xff;
      carry = nextCarry;
    }
    return { shifted: out, carry };
  };

  const { shifted: k1Shift, carry: c1 } = shiftLeft(l);
  const k1 = new Uint8Array(k1Shift);
  if (c1) k1[blockSize - 1] ^= Rb;

  const { shifted: k2Shift, carry: c2 } = shiftLeft(k1);
  const k2 = new Uint8Array(k2Shift);
  if (c2) k2[blockSize - 1] ^= Rb;

  // 2. Process message blocks
  const n = Math.ceil(message.length / blockSize) || 1;
  const isComplete = message.length > 0 && message.length % blockSize === 0;

  let y = new Uint8Array(blockSize);

  for (let i = 0; i < n - 1; i++) {
    const block = message.slice(i * blockSize, (i + 1) * blockSize);
    for (let b = 0; b < blockSize; b++) y[b] ^= block[b];
    y = new Uint8Array(
      cipher === 'AES'
        ? aesEncrypt({ key, plaintext: y, mode: 'ECB', padding: 'None' }).ciphertext
        : tdesEncrypt(y, key, undefined, 'ECB', 'None').ciphertext
    );
  }

  // Last block
  const lastBlock = new Uint8Array(blockSize);
  const rem = message.slice((n - 1) * blockSize);
  lastBlock.set(rem);

  if (isComplete) {
    for (let b = 0; b < blockSize; b++) lastBlock[b] ^= k1[b];
  } else {
    lastBlock[rem.length] = 0x80;
    for (let b = 0; b < blockSize; b++) lastBlock[b] ^= k2[b];
  }

  for (let b = 0; b < blockSize; b++) y[b] ^= lastBlock[b];

  const mac =
    cipher === 'AES'
      ? aesEncrypt({ key, plaintext: y, mode: 'ECB', padding: 'None' }).ciphertext
      : tdesEncrypt(y, key, undefined, 'ECB', 'None').ciphertext;

  return mac;
}
