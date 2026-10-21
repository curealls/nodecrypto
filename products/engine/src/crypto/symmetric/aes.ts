import { gcm, cbc, ctr, ecb, cfb, aeskw } from '@noble/ciphers/aes.js';
import { ofbMode, ccmModeEncrypt, ccmModeDecrypt, xtsModeEncrypt, xtsModeDecrypt } from './modes';
import { applyBlockPadding, removeBlockPadding, BlockPaddingType } from '../padding/padding';
import { NodeError } from '../../dag/errors';

export type AesMode = 'GCM' | 'CBC' | 'CTR' | 'ECB' | 'CCM' | 'OFB' | 'CFB' | 'XTS' | 'KW';
export type AesPadding = BlockPaddingType;

export interface AesEncryptParams {
  key: Uint8Array;
  iv?: Uint8Array;
  plaintext: Uint8Array;
  mode: AesMode;
  padding?: AesPadding;
  aad?: Uint8Array;
}

export interface AesEncryptResult {
  ciphertext: Uint8Array;
  tag?: Uint8Array;
  iv: Uint8Array;
}

export interface AesDecryptParams {
  key: Uint8Array;
  iv?: Uint8Array;
  ciphertext: Uint8Array;
  mode: AesMode;
  padding?: AesPadding;
  tag?: Uint8Array;
  aad?: Uint8Array;
}

// @noble/ciphers throws plain Error for failures inside its own encrypt/decrypt calls (padding
// validation, block alignment, AEAD/KW integrity). Reclassify those into the same NodeError codes
// used for our own up-front validation, based on the small fixed set of messages it's known to throw.
function classifyLibraryError(err: unknown): NodeError {
  const msg = err instanceof Error ? err.message : String(err);
  if (/invalid tag|integrity check failed/i.test(msg)) {
    return new NodeError('AUTH_TAG_MISMATCH', 'AES authentication failed: invalid tag');
  }
  if (/bad decrypt|pkcs7/i.test(msg)) {
    return new NodeError('INVALID_PADDING', `AES padding is invalid: ${msg}`);
  }
  if (/must be multiple of/i.test(msg)) {
    return new NodeError('CIPHERTEXT_NOT_BLOCK_ALIGNED', `AES data length must be a multiple of the block size: ${msg}`);
  }
  return new NodeError('UNKNOWN_ERROR', msg);
}

function runLibraryOp<T>(fn: () => T): T {
  try {
    return fn();
  } catch (err) {
    if (err instanceof NodeError) throw err;
    throw classifyLibraryError(err);
  }
}

export function aesEncrypt(params: AesEncryptParams): AesEncryptResult {
  const { key, plaintext, mode, padding = 'PKCS7', aad } = params;

  if (mode === 'XTS') {
    if (![32, 64].includes(key.length)) {
      throw new NodeError('INVALID_KEY_LENGTH', `AES-XTS requires a 32-byte (XTS-128) or 64-byte (XTS-256) double key, got ${key.length} bytes`);
    }
  } else {
    if (![16, 24, 32].includes(key.length)) {
      throw new NodeError('INVALID_KEY_LENGTH', `Invalid AES key length: ${key.length} bytes (expected 16, 24, or 32 bytes)`);
    }
  }

  // IV/Nonce default: a deterministic 0x00-filled buffer sized for the mode, not a random value,
  // so omitting it produces the same ciphertext every run (PRD §4.3 common AEAD block cipher rule).
  // This is a prototyping/debugging convenience, not real key/IV management -- real deployments
  // must always supply a properly random, non-reused IV/nonce for CBC/CTR/OFB/CFB/GCM/CCM.
  let iv = params.iv;
  if (!iv && mode !== 'KW' && mode !== 'ECB') {
    const ivLen = (mode === 'GCM' || mode === 'CCM') ? 12 : 16;
    iv = new Uint8Array(ivLen);
  } else if (!iv) {
    iv = new Uint8Array(0);
  }

  if (mode === 'GCM') {
    if (iv.length !== 12) {
      throw new NodeError('INVALID_NONCE_LENGTH', `AES-GCM requires a 12-byte (96-bit) IV/nonce, got ${iv.length} bytes`);
    }
    const cipher = gcm(key, iv, aad);
    const combined = cipher.encrypt(plaintext);
    const ciphertext = combined.slice(0, -16);
    const tag = combined.slice(-16);
    return { ciphertext, tag, iv };
  }

  if (mode === 'CCM') {
    const nonce = iv.length >= 7 && iv.length <= 13 ? iv : iv.slice(0, 12);
    const blockEncrypt = (b: Uint8Array) => ecb(key, { disablePadding: true }).encrypt(b);
    return ccmModeEncrypt(blockEncrypt, plaintext, nonce, aad, 16);
  }

  if (mode === 'CBC') {
    if (iv.length !== 16) {
      throw new NodeError('INVALID_IV_LENGTH', `AES-CBC requires a 16-byte IV, got ${iv.length} bytes`);
    }
    if (padding === 'ANSIX923' || padding === 'ISO7816' || padding === 'Zero') {
      const padded = applyBlockPadding(plaintext, padding as BlockPaddingType, 16);
      const cipher = cbc(key, iv, { disablePadding: true });
      const ciphertext = cipher.encrypt(padded);
      return { ciphertext, iv };
    }
    const disablePadding = padding === 'None';
    const cipher = cbc(key, iv, { disablePadding });
    const ciphertext = runLibraryOp(() => cipher.encrypt(plaintext));
    return { ciphertext, iv };
  }

  if (mode === 'CTR') {
    if (iv.length !== 16) {
      throw new NodeError('INVALID_IV_LENGTH', `AES-CTR requires a 16-byte initial counter, got ${iv.length} bytes`);
    }
    const cipher = ctr(key, iv);
    const ciphertext = cipher.encrypt(plaintext);
    return { ciphertext, iv };
  }

  if (mode === 'CFB') {
    if (iv.length !== 16) {
      throw new NodeError('INVALID_IV_LENGTH', `AES-CFB requires a 16-byte IV, got ${iv.length} bytes`);
    }
    const cipher = cfb(key, iv);
    const ciphertext = cipher.encrypt(plaintext);
    return { ciphertext, iv };
  }

  if (mode === 'OFB') {
    if (iv.length !== 16) {
      throw new NodeError('INVALID_IV_LENGTH', `AES-OFB requires a 16-byte IV, got ${iv.length} bytes`);
    }
    const blockEncrypt = (b: Uint8Array) => ecb(key, { disablePadding: true }).encrypt(b);
    return ofbMode(blockEncrypt, plaintext, iv);
  }

  if (mode === 'XTS') {
    if (iv.length !== 16) {
      throw new NodeError('INVALID_IV_LENGTH', `AES-XTS requires a 16-byte sector/tweak IV, got ${iv.length} bytes`);
    }
    const half = key.length / 2;
    const k1 = key.slice(0, half);
    const k2 = key.slice(half);
    const k1Enc = (b: Uint8Array) => ecb(k1, { disablePadding: true }).encrypt(b);
    const k2Enc = (b: Uint8Array) => ecb(k2, { disablePadding: true }).encrypt(b);
    return xtsModeEncrypt(k1Enc, k2Enc, plaintext, iv);
  }

  if (mode === 'KW') {
    const wrap = aeskw(key);
    const ciphertext = runLibraryOp(() => wrap.encrypt(plaintext));
    return { ciphertext, iv: new Uint8Array(0) };
  }

  if (mode === 'ECB') {
    if (padding === 'ANSIX923' || padding === 'ISO7816' || padding === 'Zero') {
      const padded = applyBlockPadding(plaintext, padding as BlockPaddingType, 16);
      const cipher = ecb(key, { disablePadding: true });
      const ciphertext = cipher.encrypt(padded);
      return { ciphertext, iv: new Uint8Array(0) };
    }
    const disablePadding = padding === 'None';
    const cipher = ecb(key, { disablePadding });
    const ciphertext = runLibraryOp(() => cipher.encrypt(plaintext));
    return { ciphertext, iv: new Uint8Array(0) };
  }

  throw new NodeError('UNSUPPORTED_MODE', `Unsupported AES mode: ${mode}`);
}

export function aesDecrypt(params: AesDecryptParams): Uint8Array {
  const { key, ciphertext, mode, padding = 'PKCS7', tag, aad } = params;

  if (mode === 'XTS') {
    if (![32, 64].includes(key.length)) {
      throw new NodeError('INVALID_KEY_LENGTH', `AES-XTS requires a 32-byte or 64-byte key, got ${key.length} bytes`);
    }
  } else {
    if (![16, 24, 32].includes(key.length)) {
      throw new NodeError('INVALID_KEY_LENGTH', `Invalid AES key length: ${key.length} bytes`);
    }
  }

  // Same deterministic 0x00-fill default as aesEncrypt when the IV/nonce is omitted; a value
  // that was actually supplied but has the wrong length is still a hard error.
  const ivLenByMode: Partial<Record<AesMode, number>> = {
    GCM: 12, CCM: 12, CBC: 16, CTR: 16, CFB: 16, OFB: 16, XTS: 16,
  };
  const expectedIvLen = ivLenByMode[mode];
  const iv = params.iv ?? (expectedIvLen !== undefined ? new Uint8Array(expectedIvLen) : undefined);

  if (mode === 'GCM') {
    if (!iv || iv.length !== 12) {
      throw new NodeError('INVALID_NONCE_LENGTH', 'AES-GCM decryption requires a 12-byte IV');
    }
    if (!tag || tag.length !== 16) {
      throw new NodeError('INVALID_TAG_LENGTH', 'AES-GCM decryption requires a 16-byte authentication tag');
    }
    const combined = new Uint8Array(ciphertext.length + tag.length);
    combined.set(ciphertext);
    combined.set(tag, ciphertext.length);

    const cipher = gcm(key, iv, aad);
    return runLibraryOp(() => cipher.decrypt(combined));
  }

  if (mode === 'CCM') {
    if (!tag) throw new NodeError('INVALID_TAG_LENGTH', 'AES-CCM decryption requires an authentication tag');
    const nonce = iv!.length >= 7 && iv!.length <= 13 ? iv! : iv!.slice(0, 12);
    const blockEncrypt = (b: Uint8Array) => ecb(key, { disablePadding: true }).encrypt(b);
    return ccmModeDecrypt(blockEncrypt, ciphertext, nonce, tag, aad);
  }

  if (mode === 'CBC') {
    if (!iv || iv.length !== 16) {
      throw new NodeError('INVALID_IV_LENGTH', 'AES-CBC decryption requires a 16-byte IV');
    }
    if (padding === 'ANSIX923' || padding === 'ISO7816' || padding === 'Zero') {
      const cipher = cbc(key, iv, { disablePadding: true });
      const decrypted = runLibraryOp(() => cipher.decrypt(ciphertext));
      return removeBlockPadding(decrypted, padding as BlockPaddingType, 16);
    }
    const disablePadding = padding === 'None';
    const cipher = cbc(key, iv, { disablePadding });
    return runLibraryOp(() => cipher.decrypt(ciphertext));
  }

  if (mode === 'CTR') {
    if (!iv || iv.length !== 16) {
      throw new NodeError('INVALID_IV_LENGTH', 'AES-CTR decryption requires a 16-byte initial counter');
    }
    const cipher = ctr(key, iv);
    return cipher.decrypt(ciphertext);
  }

  if (mode === 'CFB') {
    if (!iv || iv.length !== 16) {
      throw new NodeError('INVALID_IV_LENGTH', 'AES-CFB decryption requires a 16-byte IV');
    }
    const cipher = cfb(key, iv);
    return cipher.decrypt(ciphertext);
  }

  if (mode === 'OFB') {
    if (!iv || iv.length !== 16) {
      throw new NodeError('INVALID_IV_LENGTH', 'AES-OFB decryption requires a 16-byte IV');
    }
    const blockEncrypt = (b: Uint8Array) => ecb(key, { disablePadding: true }).encrypt(b);
    return ofbMode(blockEncrypt, ciphertext, iv).ciphertext;
  }

  if (mode === 'XTS') {
    if (!iv || iv.length !== 16) {
      throw new NodeError('INVALID_IV_LENGTH', 'AES-XTS requires a 16-byte sector/tweak IV');
    }
    const half = key.length / 2;
    const k1 = key.slice(0, half);
    const k2 = key.slice(half);
    const k1Dec = (b: Uint8Array) => ecb(k1, { disablePadding: true }).decrypt(b);
    const k2Enc = (b: Uint8Array) => ecb(k2, { disablePadding: true }).encrypt(b);
    return xtsModeDecrypt(k1Dec, k2Enc, ciphertext, iv);
  }

  if (mode === 'KW') {
    const wrap = aeskw(key);
    return runLibraryOp(() => wrap.decrypt(ciphertext));
  }

  if (mode === 'ECB') {
    if (padding === 'ANSIX923' || padding === 'ISO7816' || padding === 'Zero') {
      const cipher = ecb(key, { disablePadding: true });
      const decrypted = runLibraryOp(() => cipher.decrypt(ciphertext));
      return removeBlockPadding(decrypted, padding as BlockPaddingType, 16);
    }
    const disablePadding = padding === 'None';
    const cipher = ecb(key, { disablePadding });
    return runLibraryOp(() => cipher.decrypt(ciphertext));
  }

  throw new NodeError('UNSUPPORTED_MODE', `Unsupported AES mode: ${mode}`);
}
