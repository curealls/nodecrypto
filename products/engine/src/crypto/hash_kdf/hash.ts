import { sha1, md5, ripemd160 } from '@noble/hashes/legacy.js';
import { sha224, sha256, sha384, sha512, sha512_224, sha512_256 } from '@noble/hashes/sha2.js';
import { sha3_224, sha3_256, sha3_384, sha3_512, keccak_256, keccak_512, shake128, shake256 } from '@noble/hashes/sha3.js';
import { blake2b, blake2s } from '@noble/hashes/blake2.js';
import { blake3 } from '@noble/hashes/blake3.js';
import { NodeError } from '../../dag/errors';

export type HashAlgorithm =
  | 'SHA-1'
  | 'SHA-224'
  | 'SHA-256'
  | 'SHA-384'
  | 'SHA-512'
  | 'SHA-512/224'
  | 'SHA-512/256'
  | 'SHA3-224'
  | 'SHA3-256'
  | 'SHA3-384'
  | 'SHA3-512'
  | 'Keccak-256'
  | 'Keccak-512'
  | 'SHAKE128'
  | 'SHAKE256'
  | 'BLAKE2b'
  | 'BLAKE2s'
  | 'BLAKE3'
  | 'RIPEMD-160'
  | 'MD5';

export function computeHash(data: Uint8Array, algorithm: HashAlgorithm = 'SHA-256', outputLenBytes?: number): Uint8Array {
  switch (algorithm) {
    case 'SHA-1':
      return sha1(data);
    case 'SHA-224':
      return sha224(data);
    case 'SHA-256':
      return sha256(data);
    case 'SHA-384':
      return sha384(data);
    case 'SHA-512':
      return sha512(data);
    case 'SHA-512/224':
      return sha512_224(data);
    case 'SHA-512/256':
      return sha512_256(data);
    case 'SHA3-224':
      return sha3_224(data);
    case 'SHA3-256':
      return sha3_256(data);
    case 'SHA3-384':
      return sha3_384(data);
    case 'SHA3-512':
      return sha3_512(data);
    case 'Keccak-256':
      return keccak_256(data);
    case 'Keccak-512':
      return keccak_512(data);
    case 'SHAKE128':
      return shake128(data, { dkLen: outputLenBytes || 32 });
    case 'SHAKE256':
      return shake256(data, { dkLen: outputLenBytes || 64 });
    case 'BLAKE2b':
      return blake2b(data, { dkLen: outputLenBytes || 64 });
    case 'BLAKE2s':
      return blake2s(data, { dkLen: outputLenBytes || 32 });
    case 'BLAKE3':
      return blake3(data, { dkLen: outputLenBytes || 32 });
    case 'RIPEMD-160':
      return ripemd160(data);
    case 'MD5':
      return md5(data);
    default:
      throw new NodeError('UNSUPPORTED_ALGORITHM', `Unsupported hash algorithm: ${algorithm}`);
  }
}
