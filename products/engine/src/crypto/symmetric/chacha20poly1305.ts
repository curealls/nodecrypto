import { chacha20poly1305, chacha20 } from '@noble/ciphers/chacha.js';
import { NodeError } from '../../dag/errors';

export interface ChaChaEncryptParams {
  key: Uint8Array;      // 32 bytes
  nonce?: Uint8Array;   // 12 bytes (96 bits)
  plaintext: Uint8Array;
  aad?: Uint8Array;
}

export interface ChaChaEncryptResult {
  ciphertext: Uint8Array;
  tag: Uint8Array;
  nonce: Uint8Array;
}

export function chacha20Poly1305Encrypt(params: ChaChaEncryptParams): ChaChaEncryptResult {
  const { key, plaintext, aad } = params;
  if (key.length !== 32) {
    throw new NodeError('INVALID_KEY_LENGTH', `ChaCha20-Poly1305 requires a 32-byte key, got ${key.length}`);
  }
  // Deterministic 0x00-fill default when the nonce is omitted (PRD §4.3 common rule) -- not a
  // random value, so the same inputs always produce the same output. Prototyping/debugging
  // convenience only; real deployments must always supply a random, non-reused nonce.
  const nonce = params.nonce || new Uint8Array(12);
  if (nonce.length !== 12) {
    throw new NodeError('INVALID_NONCE_LENGTH', `ChaCha20-Poly1305 requires a 12-byte nonce, got ${nonce.length}`);
  }

  const cipher = chacha20poly1305(key, nonce, aad);
  const combined = cipher.encrypt(plaintext);
  const ciphertext = combined.slice(0, -16);
  const tag = combined.slice(-16);

  return { ciphertext, tag, nonce };
}

export interface ChaChaDecryptParams {
  key: Uint8Array;
  nonce: Uint8Array;
  ciphertext: Uint8Array;
  tag: Uint8Array;
  aad?: Uint8Array;
}

export function chacha20Poly1305Decrypt(params: ChaChaDecryptParams): Uint8Array {
  const { key, nonce, ciphertext, tag, aad } = params;
  if (key.length !== 32) throw new NodeError('INVALID_KEY_LENGTH', 'ChaCha20-Poly1305 requires a 32-byte key');
  if (nonce.length !== 12) throw new NodeError('INVALID_NONCE_LENGTH', 'ChaCha20-Poly1305 requires a 12-byte nonce');
  if (tag.length !== 16) throw new NodeError('INVALID_TAG_LENGTH', 'ChaCha20-Poly1305 requires a 16-byte tag');

  const combined = new Uint8Array(ciphertext.length + tag.length);
  combined.set(ciphertext);
  combined.set(tag, ciphertext.length);

  const cipher = chacha20poly1305(key, nonce, aad);
  try {
    return cipher.decrypt(combined);
  } catch (err) {
    throw new NodeError('AUTH_TAG_MISMATCH', 'ChaCha20-Poly1305 authentication failed: invalid tag');
  }
}

// Pure ChaCha20 Stream Cipher (without Poly1305 AEAD)
export interface ChaCha20StreamParams {
  key: Uint8Array;       // 32 bytes
  nonce?: Uint8Array;    // 12 bytes (or 8/16/24 depending on variant, standard RFC 8439 is 12 bytes)
  data: Uint8Array;
}

export function chacha20StreamEncrypt(params: ChaCha20StreamParams): { ciphertext: Uint8Array; nonce: Uint8Array } {
  const { key, data } = params;
  if (key.length !== 32) throw new NodeError('INVALID_KEY_LENGTH', `ChaCha20 requires a 32-byte key, got ${key.length}`);
  // Deterministic 0x00-fill default when the nonce is omitted (PRD §4.3 common rule); see
  // chacha20Poly1305Encrypt above.
  const nonce = params.nonce || new Uint8Array(12);
  if (nonce.length !== 12) throw new NodeError('INVALID_NONCE_LENGTH', `ChaCha20 requires a 12-byte nonce, got ${nonce.length}`);

  const ciphertext = chacha20(key, nonce, data);
  return { ciphertext, nonce };
}

export function chacha20StreamDecrypt(params: { key: Uint8Array; nonce: Uint8Array; ciphertext: Uint8Array }): Uint8Array {
  const { key, nonce, ciphertext } = params;
  if (key.length !== 32) throw new NodeError('INVALID_KEY_LENGTH', `ChaCha20 requires a 32-byte key, got ${key.length}`);
  if (nonce.length !== 12) throw new NodeError('INVALID_NONCE_LENGTH', `ChaCha20 requires a 12-byte nonce, got ${nonce.length}`);

  // In stream ciphers, decryption is XOR with keystream, identical operation
  return chacha20(key, nonce, ciphertext);
}

