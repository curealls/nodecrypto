import { ml_kem512, ml_kem768, ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import { NodeError } from '../../dag/errors';
import { tmsg } from '../../messages';

// @noble/post-quantum throws plain Error for invalid key/ciphertext material (wrong length).
// Reclassify into NodeError so asymmetricPqcNodes.ts's `fixed` errorProfile reflects what can
// actually be thrown.
function classifyLibraryError(err: unknown): NodeError {
  if (err instanceof NodeError) return err;
  const msg = err instanceof Error ? err.message : String(err);
  return new NodeError('INVALID_KEY_MATERIAL', tmsg('errors:crypto.keyOrCiphertext', { detail: msg }));
}

export type MlKemSecurityLevel = 512 | 768 | 1024;

export interface MlKemKeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

export interface MlKemEncapsulation {
  ciphertext: Uint8Array;
  sharedSecret: Uint8Array;
}

function getMlKemInstance(level: MlKemSecurityLevel) {
  switch (level) {
    case 512:
      return ml_kem512;
    case 768:
      return ml_kem768;
    case 1024:
      return ml_kem1024;
    default:
      throw new NodeError('UNSUPPORTED_ALGORITHM', `Unsupported ML-KEM level: ${level}`);
  }
}

/**
 * FIPS 203 ML-KEM Key Generation
 */
export function mlKemGenerateKeyPair(level: MlKemSecurityLevel = 768, seed?: Uint8Array): MlKemKeyPair {
  const instance = getMlKemInstance(level);
  const keys = instance.keygen(seed);
  return {
    publicKey: keys.publicKey,
    secretKey: keys.secretKey,
  };
}

/**
 * FIPS 203 ML-KEM Encapsulation (Generates ciphertext + shared secret)
 */
export function mlKemEncapsulate(
  publicKey: Uint8Array,
  level: MlKemSecurityLevel = 768,
  seed?: Uint8Array
): MlKemEncapsulation {
  try {
    const instance = getMlKemInstance(level);
    const result = instance.encapsulate(publicKey, seed);
    return {
      ciphertext: result.cipherText,
      sharedSecret: result.sharedSecret,
    };
  } catch (err) {
    throw classifyLibraryError(err);
  }
}

/**
 * FIPS 203 ML-KEM Decapsulation (Recovers shared secret from ciphertext)
 */
export function mlKemDecapsulate(
  ciphertext: Uint8Array,
  secretKey: Uint8Array,
  level: MlKemSecurityLevel = 768
): Uint8Array {
  try {
    const instance = getMlKemInstance(level);
    return instance.decapsulate(ciphertext, secretKey);
  } catch (err) {
    throw classifyLibraryError(err);
  }
}
