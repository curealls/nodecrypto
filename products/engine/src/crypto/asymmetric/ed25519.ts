import { ed25519 } from '@noble/curves/ed25519.js';
import { NodeError } from '../../dag/errors';
import { tmsg } from '../../messages';

// @noble/curves throws plain Error for invalid key material (wrong length). Reclassify into
// NodeError so asymmetricPqcNodes.ts's `fixed` errorProfile reflects what can actually be thrown.
function classifyLibraryError(err: unknown): NodeError {
  if (err instanceof NodeError) return err;
  const msg = err instanceof Error ? err.message : String(err);
  return new NodeError('INVALID_KEY_MATERIAL', tmsg('errors:crypto.keyMaterial', { detail: msg }));
}

export interface Ed25519KeyPair {
  privateKey: Uint8Array; // 32 bytes seed
  publicKey: Uint8Array;  // 32 bytes
}

export function ed25519GenerateKeyPair(): Ed25519KeyPair {
  const priv = crypto.getRandomValues(new Uint8Array(32));
  const pub = ed25519.getPublicKey(priv);
  return { privateKey: priv, publicKey: pub };
}

export function ed25519Sign(message: Uint8Array, privateKey: Uint8Array): Uint8Array {
  try {
    return ed25519.sign(message, privateKey);
  } catch (err) {
    throw classifyLibraryError(err);
  }
}

export function ed25519Verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean {
  try {
    return ed25519.verify(signature, message, publicKey);
  } catch {
    return false;
  }
}
