import {
  slh_dsa_sha2_128s,
  slh_dsa_sha2_128f,
  slh_dsa_sha2_192s,
  slh_dsa_sha2_192f,
  slh_dsa_sha2_256s,
  slh_dsa_sha2_256f,
  slh_dsa_shake_128s,
  slh_dsa_shake_128f,
  slh_dsa_shake_192s,
  slh_dsa_shake_192f,
  slh_dsa_shake_256s,
  slh_dsa_shake_256f,
} from '@noble/post-quantum/slh-dsa.js';
import { NodeError } from '../../dag/errors';
import { tmsg } from '../../messages';

// @noble/post-quantum throws plain Error for invalid key material (wrong length). Reclassify into
// NodeError so asymmetricPqcNodes.ts's `fixed` errorProfile reflects what can actually be thrown.
function classifyLibraryError(err: unknown): NodeError {
  if (err instanceof NodeError) return err;
  const msg = err instanceof Error ? err.message : String(err);
  return new NodeError('INVALID_KEY_MATERIAL', tmsg('errors:crypto.keyLength', { detail: msg }));
}

export type SlhDsaVariant =
  | 'slh_dsa_sha2_128s'
  | 'slh_dsa_sha2_128f'
  | 'slh_dsa_sha2_192s'
  | 'slh_dsa_sha2_192f'
  | 'slh_dsa_sha2_256s'
  | 'slh_dsa_sha2_256f'
  | 'slh_dsa_shake_128s'
  | 'slh_dsa_shake_128f'
  | 'slh_dsa_shake_192s'
  | 'slh_dsa_shake_192f'
  | 'slh_dsa_shake_256s'
  | 'slh_dsa_shake_256f';

export interface SlhDsaKeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

const instances: Record<SlhDsaVariant, any> = {
  slh_dsa_sha2_128s,
  slh_dsa_sha2_128f,
  slh_dsa_sha2_192s,
  slh_dsa_sha2_192f,
  slh_dsa_sha2_256s,
  slh_dsa_sha2_256f,
  slh_dsa_shake_128s,
  slh_dsa_shake_128f,
  slh_dsa_shake_192s,
  slh_dsa_shake_192f,
  slh_dsa_shake_256s,
  slh_dsa_shake_256f,
};

function getSlhDsaInstance(variant: SlhDsaVariant) {
  const inst = instances[variant];
  if (!inst) {
    throw new NodeError('UNSUPPORTED_ALGORITHM', `Unsupported SLH-DSA variant: ${variant}`);
  }
  return inst;
}

/**
 * FIPS 205 SLH-DSA Key Generation
 */
export function slhDsaGenerateKeyPair(variant: SlhDsaVariant = 'slh_dsa_sha2_128s', seed?: Uint8Array): SlhDsaKeyPair {
  const instance = getSlhDsaInstance(variant);
  const keys = instance.keygen(seed);
  return {
    publicKey: keys.publicKey,
    secretKey: keys.secretKey,
  };
}

/**
 * FIPS 205 SLH-DSA Digital Signature Generation
 */
export function slhDsaSign(
  message: Uint8Array,
  secretKey: Uint8Array,
  variant: SlhDsaVariant = 'slh_dsa_sha2_128s',
  context?: Uint8Array
): Uint8Array {
  try {
    const instance = getSlhDsaInstance(variant);
    return instance.sign(message, secretKey, { context });
  } catch (err) {
    throw classifyLibraryError(err);
  }
}

/**
 * FIPS 205 SLH-DSA Digital Signature Verification
 */
export function slhDsaVerify(
  signature: Uint8Array,
  message: Uint8Array,
  publicKey: Uint8Array,
  variant: SlhDsaVariant = 'slh_dsa_sha2_128s',
  context?: Uint8Array
): boolean {
  try {
    const instance = getSlhDsaInstance(variant);
    return instance.verify(signature, message, publicKey, { context });
  } catch {
    return false;
  }
}
