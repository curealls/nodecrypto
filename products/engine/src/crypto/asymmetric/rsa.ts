/**
 * High-Assurance RSA Operations using WebCrypto API
 * Supports RSA-OAEP (Encryption/Decryption) and RSA-PSS / RSASSA-PKCS1-v1_5 (Signing/Verification)
 */

import { bytesToBase64, base64ToBytes } from '../utils/encoding';
import { NodeError } from '../../dag/errors';
import { tmsg, type Msg } from '../../messages';

// WebCrypto throws a plain DOMException for RSA failures (bad key encoding, OAEP/PSS operation
// failure). Reclassify those into NodeError so the asymmetricPqcNodes.ts `fixed` errorProfile
// cases reflect what can actually be thrown. `operationErrorCode` disambiguates encrypt/decrypt/
// sign, since WebCrypto's own message is identical ("operation failed for an operation-specific
// reason") across all three.
function classifyRsaError(err: unknown, operationErrorCode: string, operationMessage: Msg): NodeError {
  if (err instanceof NodeError) return err;
  const name = (err as DOMException)?.name;
  if (name === 'DataError') {
    return new NodeError('INVALID_KEY_FORMAT', tmsg('errors:crypto.rsaKeyFormat', { detail: (err as Error)?.message || String(err) }));
  }
  if (name === 'OperationError') {
    return new NodeError(operationErrorCode, operationMessage);
  }
  return new NodeError('UNKNOWN_ERROR', (err as Error)?.message || String(err));
}

export interface RsaKeyPair {
  publicKeyPem: string;
  privateKeyPem: string;
  publicKeyDer: Uint8Array;
  privateKeyDer: Uint8Array;
}

export type RsaHashAlgorithm = 'SHA-1' | 'SHA-256' | 'SHA-384' | 'SHA-512';
export type RsaAlgorithmScheme = 'RSA-OAEP' | 'RSA-PSS' | 'RSASSA-PKCS1-v1_5';

function arrayBufferToPem(buffer: ArrayBuffer, type: 'PUBLIC KEY' | 'PRIVATE KEY'): string {
  const base64 = bytesToBase64(new Uint8Array(buffer));
  const lines = base64.match(/.{1,64}/g)?.join('\n') || '';
  return `-----BEGIN ${type}-----\n${lines}\n-----END ${type}-----`;
}

function pemOrDerToArrayBuffer(input: Uint8Array | string): ArrayBuffer {
  if (typeof input === 'string') {
    const clean = input.replace(/-----BEGIN [^-]+-----|-----END [^-]+-----|\s+/g, '');
    return base64ToBytes(clean).buffer as ArrayBuffer;
  }
  // Convert Uint8Array to clean ArrayBuffer copy safely
  const copy = new Uint8Array(input.length);
  copy.set(input);
  return copy.buffer;
}

export interface RsaKeyGenOptions {
  modulusLength?: 1024 | 2048 | 3072 | 4096;
  publicExponent?: 65537 | 3;
  usage?: 'encrypt' | 'sign';
  algorithm?: RsaAlgorithmScheme;
  hash?: RsaHashAlgorithm;
}

export async function rsaGenerateKeyPair(
  opts: RsaKeyGenOptions = {}
): Promise<RsaKeyPair> {
  const modulusLength = opts.modulusLength || 2048;
  const usage = opts.usage || 'encrypt';
  const publicExponent = opts.publicExponent === 3 ? new Uint8Array([3]) : new Uint8Array([1, 0, 1]);
  const hash = opts.hash || 'SHA-256';

  let algorithmName: string = opts.algorithm || (usage === 'encrypt' ? 'RSA-OAEP' : 'RSA-PSS');
  let keyUsages: KeyUsage[] = usage === 'encrypt' ? ['encrypt', 'decrypt'] : ['sign', 'verify'];

  const algorithm = {
    name: algorithmName,
    modulusLength,
    publicExponent,
    hash,
  };

  const keyPair = await crypto.subtle.generateKey(algorithm, true, keyUsages);

  const pubDer = await crypto.subtle.exportKey('spki', keyPair.publicKey);
  const privDer = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);

  return {
    publicKeyDer: new Uint8Array(pubDer),
    privateKeyDer: new Uint8Array(privDer),
    publicKeyPem: arrayBufferToPem(pubDer, 'PUBLIC KEY'),
    privateKeyPem: arrayBufferToPem(privDer, 'PRIVATE KEY'),
  };
}

export async function rsaOaepEncrypt(
  plaintext: Uint8Array,
  publicKeyDerOrPem: Uint8Array | string,
  hash: RsaHashAlgorithm = 'SHA-256',
  label?: Uint8Array
): Promise<Uint8Array> {
  try {
    const der = pemOrDerToArrayBuffer(publicKeyDerOrPem);

    const cryptoKey = await crypto.subtle.importKey(
      'spki',
      der,
      { name: 'RSA-OAEP', hash },
      false,
      ['encrypt']
    );

    const algorithm: RsaOaepParams = { name: 'RSA-OAEP' };
    if (label && label.length > 0) {
      const copy = new Uint8Array(label.length);
      copy.set(label);
      algorithm.label = copy.buffer;
    }

    const encrypted = await crypto.subtle.encrypt(
      algorithm,
      cryptoKey,
      plaintext as any
    );
    return new Uint8Array(encrypted);
  } catch (err) {
    throw classifyRsaError(err, 'OAEP_MESSAGE_TOO_LONG', tmsg('errors:crypto.rsaOaepTooLong'));
  }
}

export async function rsaOaepDecrypt(
  ciphertext: Uint8Array,
  privateKeyDerOrPem: Uint8Array | string,
  hash: RsaHashAlgorithm = 'SHA-256',
  label?: Uint8Array
): Promise<Uint8Array> {
  try {
    const der = pemOrDerToArrayBuffer(privateKeyDerOrPem);

    const cryptoKey = await crypto.subtle.importKey(
      'pkcs8',
      der,
      { name: 'RSA-OAEP', hash },
      false,
      ['decrypt']
    );

    const algorithm: RsaOaepParams = { name: 'RSA-OAEP' };
    if (label && label.length > 0) {
      const copy = new Uint8Array(label.length);
      copy.set(label);
      algorithm.label = copy.buffer;
    }

    const decrypted = await crypto.subtle.decrypt(
      algorithm,
      cryptoKey,
      ciphertext as any
    );
    return new Uint8Array(decrypted);
  } catch (err) {
    throw classifyRsaError(err, 'RSA_DECRYPTION_FAILED', tmsg('errors:crypto.rsaDecryptFailed'));
  }
}

export async function rsaPssSign(
  message: Uint8Array,
  privateKeyDerOrPem: Uint8Array | string,
  saltLength: number = 32,
  hash: RsaHashAlgorithm = 'SHA-256'
): Promise<Uint8Array> {
  try {
    const der = pemOrDerToArrayBuffer(privateKeyDerOrPem);

    const cryptoKey = await crypto.subtle.importKey(
      'pkcs8',
      der,
      { name: 'RSA-PSS', hash },
      false,
      ['sign']
    );

    const signature = await crypto.subtle.sign(
      { name: 'RSA-PSS', saltLength },
      cryptoKey,
      message as any
    );
    return new Uint8Array(signature);
  } catch (err) {
    throw classifyRsaError(err, 'RSA_SIGN_FAILED', tmsg('errors:crypto.rsaSignFailed'));
  }
}

export async function rsaPssVerify(
  signature: Uint8Array,
  message: Uint8Array,
  publicKeyDerOrPem: Uint8Array | string,
  saltLength: number = 32,
  hash: RsaHashAlgorithm = 'SHA-256'
): Promise<boolean> {
  try {
    const der = pemOrDerToArrayBuffer(publicKeyDerOrPem);

    const cryptoKey = await crypto.subtle.importKey(
      'spki',
      der,
      { name: 'RSA-PSS', hash },
      false,
      ['verify']
    );

    return await crypto.subtle.verify(
      { name: 'RSA-PSS', saltLength },
      cryptoKey,
      signature as any,
      message as any
    );
  } catch {
    return false;
  }
}

export async function rsaPkcs1Sign(
  message: Uint8Array,
  privateKeyDerOrPem: Uint8Array | string,
  hash: RsaHashAlgorithm = 'SHA-256'
): Promise<Uint8Array> {
  try {
    const der = pemOrDerToArrayBuffer(privateKeyDerOrPem);

    const cryptoKey = await crypto.subtle.importKey(
      'pkcs8',
      der,
      { name: 'RSASSA-PKCS1-v1_5', hash },
      false,
      ['sign']
    );

    const signature = await crypto.subtle.sign(
      { name: 'RSASSA-PKCS1-v1_5' },
      cryptoKey,
      message as any
    );
    return new Uint8Array(signature);
  } catch (err) {
    throw classifyRsaError(err, 'RSA_SIGN_FAILED', tmsg('errors:crypto.rsaSignFailed'));
  }
}

export async function rsaPkcs1Verify(
  signature: Uint8Array,
  message: Uint8Array,
  publicKeyDerOrPem: Uint8Array | string,
  hash: RsaHashAlgorithm = 'SHA-256'
): Promise<boolean> {
  try {
    const der = pemOrDerToArrayBuffer(publicKeyDerOrPem);

    const cryptoKey = await crypto.subtle.importKey(
      'spki',
      der,
      { name: 'RSASSA-PKCS1-v1_5', hash },
      false,
      ['verify']
    );

    return await crypto.subtle.verify(
      { name: 'RSASSA-PKCS1-v1_5' },
      cryptoKey,
      signature as any,
      message as any
    );
  } catch {
    return false;
  }
}
