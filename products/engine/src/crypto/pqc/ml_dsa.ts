import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { NodeError } from '../../dag/errors';
import { tmsg } from '../../messages';

// @noble/post-quantum throws plain Error for invalid key material (wrong length). Reclassify into
// NodeError so asymmetricPqcNodes.ts's `fixed` errorProfile reflects what can actually be thrown.
function classifyLibraryError(err: unknown): NodeError {
  if (err instanceof NodeError) return err;
  const msg = err instanceof Error ? err.message : String(err);
  return new NodeError('INVALID_KEY_MATERIAL', tmsg('errors:crypto.keyLength', { detail: msg }));
}

export type MlDsaSecurityLevel = 44 | 65 | 87;

export interface MlDsaKeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

function getMlDsaInstance(level: MlDsaSecurityLevel) {
  switch (level) {
    case 44:
      return ml_dsa44;
    case 65:
      return ml_dsa65;
    case 87:
      return ml_dsa87;
    default:
      throw new NodeError('UNSUPPORTED_ALGORITHM', `Unsupported ML-DSA level: ${level}`);
  }
}

/**
 * FIPS 204 ML-DSA Key Generation
 */
export function mlDsaGenerateKeyPair(level: MlDsaSecurityLevel = 65, seed?: Uint8Array): MlDsaKeyPair {
  const instance = getMlDsaInstance(level);
  const keys = instance.keygen(seed);
  return {
    publicKey: keys.publicKey,
    secretKey: keys.secretKey,
  };
}

/**
 * FIPS 204 ML-DSA Digital Signature Generation
 */
export function mlDsaSign(
  message: Uint8Array,
  secretKey: Uint8Array,
  level: MlDsaSecurityLevel = 65,
  context?: Uint8Array
): Uint8Array {
  try {
    const instance = getMlDsaInstance(level);
    return instance.sign(message, secretKey, { context });
  } catch (err) {
    throw classifyLibraryError(err);
  }
}

/**
 * FIPS 204 ML-DSA Digital Signature Verification
 */
export function mlDsaVerify(
  signature: Uint8Array,
  message: Uint8Array,
  publicKey: Uint8Array,
  level: MlDsaSecurityLevel = 65,
  context?: Uint8Array
): boolean {
  try {
    const instance = getMlDsaInstance(level);
    return instance.verify(signature, message, publicKey, { context });
  } catch {
    return false;
  }
}
