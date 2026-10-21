import { pbkdf2 } from '@noble/hashes/pbkdf2.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256, sha512 } from '@noble/hashes/sha2.js';
import { NodeError } from '../../dag/errors';
import { tmsg } from '../../messages';

export interface Pbkdf2Params {
  password: string | Uint8Array;
  salt: Uint8Array;
  iterations: number;
  keyLength: number;
  hash?: 'SHA-256' | 'SHA-512';
}

export function computePbkdf2(params: Pbkdf2Params): Uint8Array {
  const { password, salt, iterations, keyLength, hash = 'SHA-256' } = params;
  const hashFn = hash === 'SHA-512' ? sha512 : sha256;
  try {
    return pbkdf2(hashFn, password, salt, { c: iterations, dkLen: keyLength });
  } catch (err) {
    throw new NodeError('INVALID_KDF_PARAMS', tmsg('errors:crypto.pbkdf2', { detail: err instanceof Error ? err.message : String(err) }));
  }
}

export interface HkdfParams {
  ikm: Uint8Array;      // Input Keying Material
  salt?: Uint8Array;
  info?: Uint8Array;
  keyLength: number;
  hash?: 'SHA-256' | 'SHA-512';
}

export function computeHkdf(params: HkdfParams): Uint8Array {
  const { ikm, salt, info, keyLength, hash = 'SHA-256' } = params;
  const hashFn = hash === 'SHA-512' ? sha512 : sha256;
  try {
    return hkdf(hashFn, ikm, salt, info, keyLength);
  } catch (err) {
    throw new NodeError('INVALID_KDF_PARAMS', tmsg('errors:crypto.hkdf', { detail: err instanceof Error ? err.message : String(err) }));
  }
}
