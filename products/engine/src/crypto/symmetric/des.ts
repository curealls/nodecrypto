/**
 * Single DES (56-bit effective, 8-byte key) Block Cipher Wrapper
 * Conforms to NIST FIPS 46-3 (Legacy)
 */

import { tdesEncrypt, tdesDecrypt, TdesMode, TdesPadding, TdesResult } from './tdes';
import { NodeError } from '../../dag/errors';

export function desEncrypt(
  plaintext: Uint8Array,
  key: Uint8Array,
  iv?: Uint8Array,
  mode: TdesMode = 'CBC',
  padding: TdesPadding = 'PKCS7'
): TdesResult {
  if (key.length !== 8) {
    throw new NodeError('INVALID_KEY_LENGTH', `Single DES requires an 8-byte key (64-bit with parity), got ${key.length} bytes`);
  }
  return tdesEncrypt(plaintext, key, iv, mode, padding);
}

export function desDecrypt(
  ciphertext: Uint8Array,
  key: Uint8Array,
  iv?: Uint8Array,
  mode: TdesMode = 'CBC',
  padding: TdesPadding = 'PKCS7'
): Uint8Array {
  if (key.length !== 8) {
    throw new NodeError('INVALID_KEY_LENGTH', `Single DES requires an 8-byte key (64-bit with parity), got ${key.length} bytes`);
  }
  return tdesDecrypt(ciphertext, key, iv, mode, padding);
}
