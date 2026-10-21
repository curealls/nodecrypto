import { x25519 } from '@noble/curves/ed25519.js';
import { NodeError } from '../../dag/errors';
import { tmsg } from '../../messages';

// @noble/curves throws plain Error for invalid key material (wrong length). Reclassify into
// NodeError so asymmetricPqcNodes.ts's `fixed` errorProfile reflects what can actually be thrown.
function classifyLibraryError(err: unknown): NodeError {
  if (err instanceof NodeError) return err;
  const msg = err instanceof Error ? err.message : String(err);
  return new NodeError('INVALID_KEY_MATERIAL', tmsg('errors:crypto.keyMaterial', { detail: msg }));
}

export interface X25519KeyPair {
  privateKey: Uint8Array; // 32 bytes
  publicKey: Uint8Array;  // 32 bytes
}

export function x25519GenerateKeyPair(): X25519KeyPair {
  const priv = crypto.getRandomValues(new Uint8Array(32));
  const pub = x25519.getPublicKey(priv);
  return { privateKey: priv, publicKey: pub };
}

export function x25519GetPublicKey(privateKey: Uint8Array): Uint8Array {
  return x25519.getPublicKey(privateKey);
}

export function x25519SharedSecret(privateKey: Uint8Array, peerPublicKey: Uint8Array): Uint8Array {
  try {
    return x25519.getSharedSecret(privateKey, peerPublicKey);
  } catch (err) {
    throw classifyLibraryError(err);
  }
}
