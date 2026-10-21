/**
 * Utility functions for data encoding, entropy calculation, and secure memory wipe.
 */

import { NodeError } from '../../dag/errors';
import { tmsg } from '../../messages';

export function hexToBytes(hex: string): Uint8Array {
  const cleanHex = hex.trim().replace(/^0x/i, '').replace(/[\s\-_:]/g, '');
  if (cleanHex.length % 2 !== 0) {
    throw new NodeError('INVALID_HEX_LENGTH', `Hex string must have an even length, got length ${cleanHex.length} (${cleanHex})`);
  }
  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < cleanHex.length; i += 2) {
    const val = parseInt(cleanHex.substring(i, i + 2), 16);
    if (isNaN(val)) {
      throw new NodeError('INVALID_HEX_CHAR', `Invalid hex character at position ${i}`);
    }
    bytes[i / 2] = val;
  }
  return bytes;
}

export interface HexFormatOptions {
  uppercase?: boolean;
  prefix0x?: boolean;
  separator?: 'none' | 'space' | 'colon';
}

export function bytesToHex(bytes: Uint8Array, options?: HexFormatOptions): string {
  const hexArr: string[] = [];
  for (let i = 0; i < bytes.length; i++) {
    let h = bytes[i].toString(16).padStart(2, '0');
    if (options?.uppercase) {
      h = h.toUpperCase();
    }
    hexArr.push(h);
  }

  let separator = '';
  if (options?.separator === 'space') separator = ' ';
  else if (options?.separator === 'colon') separator = ':';

  let res = hexArr.join(separator);
  if (options?.prefix0x) {
    res = '0x' + res;
  }
  return res;
}

export function utf8ToBytes(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

export function bytesToUtf8(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

/**
 * Converts an arbitrary value to bytes, auto-detecting the encoding:
 * - Uint8Array is passed through as-is
 * - Array is converted directly
 * - String is decoded as hex if it looks like an even-length hex string, otherwise as UTF-8
 * - Number is truncated to a single byte
 * - Anything else yields an empty Uint8Array
 */
export function toBytesAuto(val: any): Uint8Array {
  if (val instanceof Uint8Array) return val;
  if (Array.isArray(val)) return new Uint8Array(val);
  if (typeof val === 'string') {
    const clean = val.trim().replace(/^0x/i, '');
    if (/^[0-9a-fA-F]+$/.test(clean) && clean.length % 2 === 0) {
      return hexToBytes(clean);
    }
    return utf8ToBytes(val);
  }
  if (typeof val === 'number') {
    return new Uint8Array([val & 0xff]);
  }
  return new Uint8Array(0);
}

export function bytesToString(bytes: Uint8Array, encoding: 'utf-8' | 'ascii' | 'latin1' = 'utf-8'): string {
  if (encoding === 'utf-8') {
    return new TextDecoder('utf-8').decode(bytes);
  }
  let str = '';
  for (let i = 0; i < bytes.length; i++) {
    str += String.fromCharCode(bytes[i]);
  }
  return str;
}

export function stringToBytes(str: string, encoding: 'utf-8' | 'ascii' | 'latin1' = 'utf-8'): Uint8Array {
  if (encoding === 'utf-8') {
    return new TextEncoder().encode(str);
  }
  const bytes = new Uint8Array(str.length);
  for (let i = 0; i < str.length; i++) {
    bytes[i] = str.charCodeAt(i) & (encoding === 'ascii' ? 0x7f : 0xff);
  }
  return bytes;
}

export interface Base64FormatOptions {
  urlSafe?: boolean;
  padding?: boolean;
}

export function bytesToBase64(bytes: Uint8Array, options?: Base64FormatOptions): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  let b64 = btoa(binary);
  if (options?.urlSafe) {
    b64 = b64.replace(/\+/g, '-').replace(/\//g, '_');
  }
  if (options?.padding === false) {
    b64 = b64.replace(/=+$/, '');
  }
  return b64;
}

export function base64ToBytes(b64: string): Uint8Array {
  let clean = b64.trim().replace(/\s+/g, '');
  clean = clean.replace(/-/g, '+').replace(/_/g, '/');
  while (clean.length % 4 !== 0) {
    clean += '=';
  }
  let binary: string;
  try {
    binary = atob(clean);
  } catch (err) {
    throw new NodeError('INVALID_BASE64_INPUT', tmsg('errors:crypto.base64', { detail: err instanceof Error ? err.message : String(err) }));
  }
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export const BASE58_ALPHABETS = {
  btc: '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz',
  flickr: '123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ',
};

export function bytesToBase58(bytes: Uint8Array, alphabetType: 'btc' | 'flickr' = 'btc'): string {
  const alphabet = BASE58_ALPHABETS[alphabetType] || BASE58_ALPHABETS.btc;
  if (bytes.length === 0) return '';

  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) {
    zeros++;
  }

  const digits = [0];
  for (let i = zeros; i < bytes.length; i++) {
    let carry = bytes[i];
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j] << 8;
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }

  let str = alphabet[0].repeat(zeros);
  for (let i = digits.length - 1; i >= 0; i--) {
    str += alphabet[digits[i]];
  }
  return str;
}

export function base58ToBytes(str: string, alphabetType: 'btc' | 'flickr' = 'btc'): Uint8Array {
  const alphabet = BASE58_ALPHABETS[alphabetType] || BASE58_ALPHABETS.btc;
  const clean = str.trim();
  if (clean.length === 0) return new Uint8Array(0);

  let zeros = 0;
  while (zeros < clean.length && clean[zeros] === alphabet[0]) {
    zeros++;
  }

  const bytes = [0];
  for (let i = zeros; i < clean.length; i++) {
    const charIndex = alphabet.indexOf(clean[i]);
    if (charIndex === -1) {
      throw new NodeError('INVALID_BASE58_CHAR', `Invalid Base58 character '${clean[i]}' at index ${i}`);
    }
    let carry = charIndex;
    for (let j = 0; j < bytes.length; j++) {
      carry += bytes[j] * 58;
      bytes[j] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }

  const result = new Uint8Array(zeros + bytes.length);
  for (let i = 0; i < zeros; i++) {
    result[i] = 0;
  }
  for (let i = 0; i < bytes.length; i++) {
    result[zeros + i] = bytes[bytes.length - 1 - i];
  }
  return result;
}

export type MultibaseType = 'base16' | 'base16_upper' | 'base58btc' | 'base64' | 'base64url';

export function bytesToMultibase(bytes: Uint8Array, base: MultibaseType = 'base58btc'): string {
  switch (base) {
    case 'base16':
      return 'f' + bytesToHex(bytes).toLowerCase();
    case 'base16_upper':
      return 'F' + bytesToHex(bytes).toUpperCase();
    case 'base58btc':
      return 'z' + bytesToBase58(bytes, 'btc');
    case 'base64':
      return 'm' + bytesToBase64(bytes, { urlSafe: false, padding: true });
    case 'base64url':
      return 'u' + bytesToBase64(bytes, { urlSafe: true, padding: false });
    default:
      throw new NodeError('UNSUPPORTED_ALGORITHM', `Unsupported multibase format: ${base}`);
  }
}

export function multibaseToBytes(str: string): { bytes: Uint8Array; base: string } {
  const clean = str.trim();
  if (clean.length < 2) {
    throw new NodeError('INVALID_MULTIBASE_STRING', 'Multibase string must be at least 2 characters long');
  }
  const prefix = clean[0];
  const data = clean.slice(1);

  switch (prefix) {
    case 'f':
      return { bytes: hexToBytes(data), base: 'base16' };
    case 'F':
      return { bytes: hexToBytes(data), base: 'base16_upper' };
    case 'z':
      return { bytes: base58ToBytes(data, 'btc'), base: 'base58btc' };
    case 'Z':
      return { bytes: base58ToBytes(data, 'flickr'), base: 'base58flickr' };
    case 'm':
    case 'M':
      return { bytes: base64ToBytes(data), base: 'base64' };
    case 'u':
    case 'U':
      return { bytes: base64ToBytes(data), base: 'base64url' };
    default:
      throw new NodeError('UNSUPPORTED_MULTIBASE_PREFIX', `Unsupported multibase prefix '${prefix}'`);
  }
}

/**
 * Calculates Shannon Entropy of byte array (0.000 to 8.000)
 */
export function calculateShannonEntropy(bytes: Uint8Array): number {
  if (!bytes || bytes.length === 0) return 0;
  const frequencies = new Array(256).fill(0);
  for (let i = 0; i < bytes.length; i++) {
    frequencies[bytes[i]]++;
  }
  let entropy = 0;
  const len = bytes.length;
  for (let i = 0; i < 256; i++) {
    if (frequencies[i] > 0) {
      const p = frequencies[i] / len;
      entropy -= p * Math.log2(p);
    }
  }
  return Math.min(8, Math.max(0, entropy));
}

/**
 * Constant-time byte array equality comparison to prevent timing attacks
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

/**
 * Securely zero out a byte buffer to prevent secrets staying in memory
 */
export function zeroize(bytes: Uint8Array): void {
  bytes.fill(0);
}
