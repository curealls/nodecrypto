import { ml_kem768_x25519 } from '@noble/post-quantum/hybrid.js';
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

export interface HybridKemKeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

export interface HybridKemEncapsulationResult {
  sharedSecret: Uint8Array;
  ciphertext: Uint8Array;
}

/**
 * X25519 + ML-KEM-768 Post-Quantum Hybrid Key Encapsulation (ND-4.7)
 */
export function hybridKemGenerateKeyPair(seed?: Uint8Array): HybridKemKeyPair {
  const keys = ml_kem768_x25519.keygen(seed);
  return {
    publicKey: keys.publicKey,
    secretKey: keys.secretKey,
  };
}

export function hybridKemEncapsulate(publicKey: Uint8Array): HybridKemEncapsulationResult {
  try {
    const res = ml_kem768_x25519.encapsulate(publicKey);
    return {
      sharedSecret: res.sharedSecret,
      ciphertext: res.cipherText,
    };
  } catch (err) {
    throw classifyLibraryError(err);
  }
}

export function hybridKemDecapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Uint8Array {
  try {
    return ml_kem768_x25519.decapsulate(ciphertext, secretKey);
  } catch (err) {
    throw classifyLibraryError(err);
  }
}
