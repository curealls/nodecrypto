/**
 * Asymmetric (RSA, ECC, Ed25519, X25519) and Post-Quantum (ML-KEM, ML-DSA, SLH-DSA, Hybrid KEM) Node Definitions
 */

import { NodeDefinition, PropertyFieldDefinition } from '../../dag/types';
import { eccGenerateKeyPair, eccSign, eccVerify, eccSharedSecret, EccCurve, EcdhFormat } from '../../crypto/asymmetric/ecc';
import { ed25519GenerateKeyPair, ed25519Sign, ed25519Verify } from '../../crypto/asymmetric/ed25519';
import { x25519GenerateKeyPair, x25519SharedSecret } from '../../crypto/asymmetric/x25519';
import { toBytesAuto } from '../../crypto/utils/encoding';
import {
  rsaGenerateKeyPair,
  rsaOaepEncrypt,
  rsaOaepDecrypt,
  rsaPssSign,
  rsaPssVerify,
  rsaPkcs1Sign,
  rsaPkcs1Verify,
  RsaHashAlgorithm,
} from '../../crypto/asymmetric/rsa';
import { mlKemGenerateKeyPair, mlKemEncapsulate, mlKemDecapsulate, MlKemSecurityLevel } from '../../crypto/pqc/ml_kem';
import { mlDsaGenerateKeyPair, mlDsaSign, mlDsaVerify, MlDsaSecurityLevel } from '../../crypto/pqc/ml_dsa';
import { slhDsaGenerateKeyPair, slhDsaSign, slhDsaVerify, SlhDsaVariant } from '../../crypto/pqc/slh_dsa';
import {
  hybridKemGenerateKeyPair,
  hybridKemEncapsulate,
  hybridKemDecapsulate,
} from '../../crypto/pqc/hybrid_kem';
import { sha256 } from '@noble/hashes/sha2.js';
import { fixedErrorProfile } from '../errorProfile';

// errorProfile: judgement (T05, execution-semantics.md §3.2). Shared by every
// true/false verify node: pick a value to treat as an error, and code/message for the reinterpreted
// ERROR state (blank falls back to runner.ts's '<NODE_TYPE>_JUDGEMENT_FAILED' default).
const JUDGEMENT_ERROR_FIELDS: PropertyFieldDefinition[] = [
  {
    id: 'errorOnValue',
    label: 'Treat As Error',
    type: 'select',
    options: [
      { label: '없음 (기본, 결과는 순수 데이터)', value: '' },
      { label: 'true', value: 'true' },
      { label: 'false', value: 'false' },
    ],
    defaultValue: '',
    description: 'When the verdict equals this value, the node status is reinterpreted as ERROR.',
  },
  {
    id: 'errorCode',
    label: 'Error Code',
    type: 'text',
    defaultValue: '',
    showWhen: (p) => p.errorOnValue === 'true' || p.errorOnValue === 'false',
    description: 'Code of the reinterpreted error. If empty, a default based on the node type is used.',
  },
  {
    id: 'errorMessage',
    label: 'Error Message',
    type: 'text',
    defaultValue: '',
    showWhen: (p) => p.errorOnValue === 'true' || p.errorOnValue === 'false',
    description: 'Message of the reinterpreted error. If empty, a default based on the node name is used.',
  },
];

// errorProfile: fixed (T06, execution-semantics.md §3.1). RSA nodes get their
// own codes (rsa.ts classifies WebCrypto's DOMException by operation); every ECC/Ed25519/X25519/
// PQC node shares INVALID_KEY_MATERIAL since @noble/curves and @noble/post-quantum only ever
// reject malformed key/ciphertext bytes, never anything more specific.
const NONE_PROFILE = { kind: 'none' as const };

const ECC_CURVE_OPTIONS = [
  { label: 'secp256k1 (Bitcoin / Ethereum)', value: 'secp256k1' },
  { label: 'NIST P-256 (secp256r1 / prime256v1)', value: 'p256' },
  { label: 'NIST P-384 (secp384r1)', value: 'p384' },
  { label: 'NIST P-521 (secp521r1)', value: 'p521' },
  { label: 'Brainpool P256r1 (RFC 5639)', value: 'brainpoolP256r1' },
  { label: 'Brainpool P384r1 (RFC 5639)', value: 'brainpoolP384r1' },
  { label: 'Brainpool P512r1 (RFC 5639)', value: 'brainpoolP512r1' },
];

// Shared for RSA Encrypt/Decrypt (RSA-OAEP + MGF1), which additionally support legacy SHA-1
const RSA_OAEP_HASH_OPTIONS = [
  { label: 'SHA-256 (Standard)', value: 'SHA-256' },
  { label: 'SHA-512 (High Security)', value: 'SHA-512' },
  { label: 'SHA-384', value: 'SHA-384' },
  { label: 'SHA-1 (Legacy)', value: 'SHA-1' },
];

// Shared for RSA Sign/Verify (RSA-PSS / PKCS#1 v1.5)
const RSA_SIGN_HASH_OPTIONS = [
  { label: 'SHA-256', value: 'SHA-256' },
  { label: 'SHA-384', value: 'SHA-384' },
  { label: 'SHA-512', value: 'SHA-512' },
];

// Shared for ML-KEM Encapsulate/Decapsulate (KeyGen uses its own NIST-level-annotated labels)
const MLKEM_VARIANT_OPTIONS = [
  { label: 'ML-KEM-512', value: 512 },
  { label: 'ML-KEM-768', value: 768 },
  { label: 'ML-KEM-1024', value: 1024 },
];

// Shared for ML-DSA Sign/Verify (KeyGen uses its own NIST-level-annotated labels)
const MLDSA_VARIANT_OPTIONS = [
  { label: 'ML-DSA-44', value: 44 },
  { label: 'ML-DSA-65', value: 65 },
  { label: 'ML-DSA-87', value: 87 },
];

// Shared for SLH-DSA Sign/Verify (KeyGen uses its own annotated labels)
const SLHDSA_VARIANT_OPTIONS = [
  { label: 'SLH-DSA-SHA2-128s', value: 'slh_dsa_sha2_128s' },
  { label: 'SLH-DSA-SHA2-128f', value: 'slh_dsa_sha2_128f' },
  { label: 'SLH-DSA-SHAKE-128s', value: 'slh_dsa_shake_128s' },
  { label: 'SLH-DSA-SHAKE-128f', value: 'slh_dsa_shake_128f' },
  { label: 'SLH-DSA-SHA2-256s', value: 'slh_dsa_sha2_256s' },
  { label: 'SLH-DSA-SHAKE-256s', value: 'slh_dsa_shake_256s' },
];

export const asymmetricPqcNodes: NodeDefinition[] = [
  // 1. RSA Keypair Generator (ND-3.1)
  {
    type: 'asymmetric-rsa-keygen',
    label: 'RSA Key Generator',
    category: 'asymmetric',
    description: 'Generates RSA public/private keypair (1024, 2048, 3072, 4096-bit, PEM & DER)',
    inputs: [],
    outputs: [
      { id: 'publicKeyPem', name: 'Public Key', spec: 'PEM', dataType: 'string', description: 'RSA public key encoded as PEM (Base64 text).' },
      { id: 'privateKeyPem', name: 'Private Key', spec: 'PEM', dataType: 'string', description: 'RSA private key encoded as PEM (Base64 text). Handle with care.' },
      { id: 'publicKeyDer', name: 'Public Key', spec: 'DER', dataType: 'bytes', description: 'RSA public key encoded as binary DER.' },
      { id: 'privateKeyDer', name: 'Private Key', spec: 'DER', dataType: 'bytes', description: 'RSA private key encoded as binary DER. Handle with care.' },
    ],
    propertySchema: [
      {
        id: 'modulusLength',
        label: 'Key Size (Modulus Bits)',
        type: 'select',
        options: [
          { label: '1024-bit (Legacy / Test)', value: 1024 },
          { label: '2048-bit (Standard)', value: 2048 },
          { label: '3072-bit (High Security)', value: 3072 },
          { label: '4096-bit (Ultra Security)', value: 4096 },
        ],
        defaultValue: 2048,
      },
      {
        id: 'publicExponent',
        label: 'Public Exponent (e)',
        type: 'select',
        options: [
          { label: '65537 (0x10001 - Standard F4)', value: 65537 },
          { label: '3 (0x03 - Fast Verification)', value: 3 },
        ],
        defaultValue: 65537,
      },
      {
        id: 'usage',
        label: 'Intended Primary Usage',
        type: 'select',
        options: [
          { label: 'Encryption / Decryption (RSA-OAEP)', value: 'encrypt' },
          { label: 'Digital Signatures (RSA-PSS / PKCS#1)', value: 'sign' },
        ],
        defaultValue: 'encrypt',
      },
    ],
    errorProfile: NONE_PROFILE,
    execute: async ({ properties, log }) => {
      const modulusLength = Number(properties.modulusLength) || 2048;
      const publicExponent = Number(properties.publicExponent) === 3 ? 3 : 65537;
      const usage = (properties.usage || 'encrypt') as 'encrypt' | 'sign';
      log(`Generating RSA-${modulusLength} keypair (e=${publicExponent}, usage=${usage})`);

      const keypair = await rsaGenerateKeyPair({
        modulusLength: modulusLength as any,
        publicExponent: publicExponent as any,
        usage,
      });

      return keypair;
    },
  },

  // 2. RSA Encrypt (ND-3.2)
  {
    type: 'asymmetric-rsa-encrypt',
    label: 'RSA Encrypt',
    category: 'asymmetric',
    description: 'Encrypts message using RSA-OAEP with recipient public key (RFC 8017)',
    inputs: [
      { id: 'publicKey', name: 'Public Key', spec: 'PEM/DER', dataType: 'any', required: true, description: 'Recipient RSA public key; accepts either PEM text or DER bytes.' },
      { id: 'plaintext', name: 'Plaintext Data', dataType: 'bytes', required: true },
      { id: 'label', name: 'OAEP Label', dataType: 'bytes', required: false, description: 'Optional OAEP label parameter (rarely used, defaults to empty).' },
    ],
    outputs: [
      { id: 'ciphertext', name: 'Ciphertext', dataType: 'bytes' },
    ],
    propertySchema: [
      {
        id: 'hash',
        label: 'Hash Algorithm (OAEP & MGF1)',
        type: 'select',
        options: RSA_OAEP_HASH_OPTIONS,
        defaultValue: 'SHA-256',
      },
    ],
    errorProfile: fixedErrorProfile(['INVALID_KEY_FORMAT', 'OAEP_MESSAGE_TOO_LONG']),
    execute: async ({ inputs, properties, log }) => {
      const hash = (properties.hash || 'SHA-256') as RsaHashAlgorithm;
      log(`Running RSA-OAEP Encrypt with ${hash}`);
      const ciphertext = await rsaOaepEncrypt(inputs.plaintext, inputs.publicKey, hash, inputs.label);
      return { ciphertext };
    },
  },

  // 3. RSA Decrypt (ND-3.2)
  {
    type: 'asymmetric-rsa-decrypt',
    label: 'RSA Decrypt',
    category: 'asymmetric',
    description: 'Decrypts ciphertext using RSA-OAEP with private key (RFC 8017)',
    inputs: [
      { id: 'privateKey', name: 'Private Key', spec: 'PEM/DER', dataType: 'any', required: true, description: 'RSA private key; accepts either PEM text or DER bytes.' },
      { id: 'ciphertext', name: 'Ciphertext Data', dataType: 'bytes', required: true },
      { id: 'label', name: 'OAEP Label', dataType: 'bytes', required: false, description: 'Optional OAEP label parameter (rarely used, defaults to empty).' },
    ],
    outputs: [
      { id: 'plaintext', name: 'Plaintext', dataType: 'bytes' },
    ],
    propertySchema: [
      {
        id: 'hash',
        label: 'Hash Algorithm (OAEP & MGF1)',
        type: 'select',
        options: RSA_OAEP_HASH_OPTIONS,
        defaultValue: 'SHA-256',
      },
    ],
    errorProfile: fixedErrorProfile(['INVALID_KEY_FORMAT', 'RSA_DECRYPTION_FAILED']),
    execute: async ({ inputs, properties, log }) => {
      const hash = (properties.hash || 'SHA-256') as RsaHashAlgorithm;
      log(`Running RSA-OAEP Decrypt with ${hash}`);
      const plaintext = await rsaOaepDecrypt(inputs.ciphertext, inputs.privateKey, hash, inputs.label);
      return { plaintext };
    },
  },

  // 4. RSA Sign (ND-3.3)
  {
    type: 'asymmetric-rsa-sign',
    label: 'RSA Sign',
    category: 'asymmetric',
    description: 'Creates digital signature using RSA-PSS or PKCS#1 v1.5 with private key',
    inputs: [
      { id: 'privateKey', name: 'Private Key', spec: 'PEM/DER', dataType: 'any', required: true, description: 'RSA private key; accepts either PEM text or DER bytes.' },
      { id: 'data', name: 'Message', dataType: 'bytes', required: true, description: 'Original message. It is hashed with the selected Hash Algorithm before signing.' },
    ],
    outputs: [
      { id: 'signature', name: 'Signature', dataType: 'bytes' },
    ],
    propertySchema: [
      {
        id: 'scheme',
        label: 'Signature Scheme',
        type: 'select',
        options: [
          { label: 'RSA-PSS (Probabilistic Signature Scheme - RFC 8017)', value: 'PSS' },
          { label: 'RSASSA-PKCS1-v1_5 (Deterministic - PKCS#1 v1.5)', value: 'PKCS1-v1_5' },
        ],
        defaultValue: 'PSS',
      },
      {
        id: 'hash',
        label: 'Hash Algorithm',
        type: 'select',
        options: RSA_SIGN_HASH_OPTIONS,
        defaultValue: 'SHA-256',
      },
      {
        id: 'saltLength',
        label: 'PSS Salt Length (Bytes)',
        type: 'number',
        defaultValue: 32,
        showWhen: (p) => (p.scheme || 'PSS') === 'PSS',
      },
    ],
    errorProfile: fixedErrorProfile(['INVALID_KEY_FORMAT', 'RSA_SIGN_FAILED']),
    execute: async ({ inputs, properties, log }) => {
      const scheme = properties.scheme || 'PSS';
      const hash = (properties.hash || 'SHA-256') as RsaHashAlgorithm;
      const saltLength = Number(properties.saltLength) || 32;
      log(`Signing with RSA [${scheme}] (${hash})`);

      const signature =
        scheme === 'PKCS1-v1_5'
          ? await rsaPkcs1Sign(inputs.data, inputs.privateKey, hash)
          : await rsaPssSign(inputs.data, inputs.privateKey, saltLength, hash);

      return { signature };
    },
  },

  // 5. RSA Verify (ND-3.3)
  {
    type: 'asymmetric-rsa-verify',
    label: 'RSA Verify',
    category: 'asymmetric',
    description: 'Verifies digital signature using RSA-PSS or PKCS#1 v1.5 with public key',
    inputs: [
      { id: 'publicKey', name: 'Public Key', spec: 'PEM/DER', dataType: 'any', required: true, description: 'Signer RSA public key; accepts either PEM text or DER bytes.' },
      { id: 'data', name: 'Message', dataType: 'bytes', required: true, description: 'Original message. It is hashed with the selected Hash Algorithm before verification.' },
      { id: 'signature', name: 'Signature', dataType: 'bytes', required: true },
    ],
    outputs: [
      { id: 'isValid', name: 'Valid', dataType: 'bool', description: 'True if the signature verification succeeded.' },
    ],
    propertySchema: [
      {
        id: 'scheme',
        label: 'Signature Scheme',
        type: 'select',
        options: [
          { label: 'RSA-PSS (Probabilistic Signature Scheme - RFC 8017)', value: 'PSS' },
          { label: 'RSASSA-PKCS1-v1_5 (Deterministic - PKCS#1 v1.5)', value: 'PKCS1-v1_5' },
        ],
        defaultValue: 'PSS',
      },
      {
        id: 'hash',
        label: 'Hash Algorithm',
        type: 'select',
        options: RSA_SIGN_HASH_OPTIONS,
        defaultValue: 'SHA-256',
      },
      {
        id: 'saltLength',
        label: 'PSS Salt Length (Bytes)',
        type: 'number',
        defaultValue: 32,
        showWhen: (p) => (p.scheme || 'PSS') === 'PSS',
      },
      ...JUDGEMENT_ERROR_FIELDS,
    ],
    errorProfile: { kind: 'judgement', port: 'isValid' },
    execute: async ({ inputs, properties, log }) => {
      const scheme = properties.scheme || 'PSS';
      const hash = (properties.hash || 'SHA-256') as RsaHashAlgorithm;
      const saltLength = Number(properties.saltLength) || 32;
      log(`Verifying RSA [${scheme}] signature (${hash})`);

      const isValid =
        scheme === 'PKCS1-v1_5'
          ? await rsaPkcs1Verify(inputs.signature, inputs.data, inputs.publicKey, hash)
          : await rsaPssVerify(inputs.signature, inputs.data, inputs.publicKey, saltLength, hash);

      log(`Verification result: ${isValid ? 'VALID' : 'INVALID'}`);
      return { isValid };
    },
  },

  // 6. ECC Keypair Generator (ND-3.4)
  {
    type: 'asymmetric-ecc-keygen',
    label: 'ECC Keypair Generator',
    category: 'asymmetric',
    description: 'Generates Elliptic Curve keypair (NIST P-256/384/521, secp256k1, Brainpool)',
    inputs: [],
    outputs: [
      { id: 'privateKey', name: 'Private Key', dataType: 'bytes' },
      { id: 'publicKey', name: 'Public Key', spec: 'Uncompressed', dataType: 'bytes', description: 'Uncompressed EC point (0x04 prefix + X + Y coordinates).' },
    ],
    propertySchema: [
      {
        id: 'curve',
        label: 'Elliptic Curve',
        type: 'select',
        options: ECC_CURVE_OPTIONS,
        defaultValue: 'p256',
      },
    ],
    errorProfile: NONE_PROFILE,
    execute: async ({ properties, log }) => {
      const curve = (properties.curve || 'p256') as EccCurve;
      log(`Generating ${curve} keypair`);
      const keypair = eccGenerateKeyPair(curve);
      return keypair;
    },
  },

  // 7. ECC Sign (ECDSA)
  {
    type: 'asymmetric-ecc-sign',
    label: 'ECC Sign (ECDSA)',
    category: 'asymmetric',
    description: 'Signs message or hash using private key on specified curve',
    inputs: [
      { id: 'privateKey', name: 'Private Key', dataType: 'bytes', required: true },
      { id: 'data', name: 'Message', dataType: 'bytes', required: true, description: 'Original message. If Pre-hash with SHA-256 is turned off, pass an already computed hash instead.' },
    ],
    outputs: [
      { id: 'signature', name: 'Signature', dataType: 'bytes' },
    ],
    propertySchema: [
      {
        id: 'curve',
        label: 'Curve',
        type: 'select',
        options: ECC_CURVE_OPTIONS,
        defaultValue: 'p256',
      },
      {
        id: 'autoHash',
        label: 'Pre-hash with SHA-256',
        type: 'boolean',
        defaultValue: true,
      },
    ],
    errorProfile: fixedErrorProfile(['INVALID_KEY_MATERIAL']),
    execute: async ({ inputs, properties, log }) => {
      const curve = (properties.curve || 'p256') as EccCurve;
      const autoHash = properties.autoHash !== false;
      const msg = autoHash ? sha256(inputs.data) : inputs.data;
      log(`Signing with ${curve} (${autoHash ? 'auto SHA-256' : 'raw data/hash'})`);
      const signature = eccSign(msg, inputs.privateKey, curve);
      return { signature };
    },
  },

  // 8. ECC Verify (ECDSA)
  {
    type: 'asymmetric-ecc-verify',
    label: 'ECC Verify (ECDSA)',
    category: 'asymmetric',
    description: 'Verifies ECDSA signature against public key on specified curve',
    inputs: [
      { id: 'publicKey', name: 'Public Key', dataType: 'bytes', required: true },
      { id: 'data', name: 'Message', dataType: 'bytes', required: true, description: 'Original message. If Pre-hash with SHA-256 is turned off, pass an already computed hash instead.' },
      { id: 'signature', name: 'Signature', dataType: 'bytes', required: true },
    ],
    outputs: [
      { id: 'isValid', name: 'Valid', dataType: 'bool', description: 'True if the ECDSA signature verification succeeded.' },
    ],
    propertySchema: [
      {
        id: 'curve',
        label: 'Curve',
        type: 'select',
        options: ECC_CURVE_OPTIONS,
        defaultValue: 'p256',
      },
      {
        id: 'autoHash',
        label: 'Pre-hash with SHA-256',
        type: 'boolean',
        defaultValue: true,
      },
      ...JUDGEMENT_ERROR_FIELDS,
    ],
    errorProfile: { kind: 'judgement', port: 'isValid' },
    execute: async ({ inputs, properties, log }) => {
      const curve = (properties.curve || 'p256') as EccCurve;
      const msg = properties.autoHash !== false ? sha256(inputs.data) : inputs.data;
      log(`Verifying ECDSA signature on ${curve}`);
      const isValid = eccVerify(inputs.signature, msg, inputs.publicKey, curve);
      log(`Signature verification result: ${isValid ? 'VALID' : 'INVALID'}`);
      return { isValid };
    },
  },

  // 9. ECC ECDH Key Agreement (ND-3.6)
  {
    type: 'asymmetric-ecc-ecdh',
    label: 'ECDH Key Agreement',
    category: 'asymmetric',
    description: 'Computes Elliptic Curve Diffie-Hellman shared secret on Weierstrass curves (NIST SP 800-56A / RFC 5903)',
    inputs: [
      { id: 'privateKey', name: 'My Private Key', dataType: 'bytes', required: true },
      { id: 'peerPublicKey', name: 'Peer Public Key', dataType: 'bytes', required: true },
    ],
    outputs: [
      { id: 'sharedSecret', name: 'Shared Secret', dataType: 'bytes' },
      { id: 'rawSecretX', name: 'Raw Secret X', spec: '32B', dataType: 'bytes', description: 'Raw X-coordinate of the ECDH shared point, before any KDF (NIST SP 800-56A raw format).' },
    ],
    propertySchema: [
      {
        id: 'curve',
        label: 'Elliptic Curve',
        type: 'select',
        options: ECC_CURVE_OPTIONS,
        defaultValue: 'p256',
      },
      {
        id: 'format',
        label: 'Output Secret Format',
        type: 'select',
        options: [
          { label: 'Raw X-Coordinate (NIST SP 800-56A Standard)', value: 'raw_x' },
          { label: 'SHA-256 KDF (32-byte Symmetric Key)', value: 'sha256_kdf' },
          { label: 'Compressed Point (02/03 + X)', value: 'compressed' },
          { label: 'Uncompressed Point (04 + X + Y)', value: 'uncompressed' },
        ],
        defaultValue: 'raw_x',
      },
    ],
    errorProfile: fixedErrorProfile(['INVALID_KEY_MATERIAL']),
    execute: async ({ inputs, properties, log }) => {
      const curve = (properties.curve || 'p256') as EccCurve;
      const format = (properties.format || 'raw_x') as EcdhFormat;
      log(`Computing ECDH shared secret on curve ${curve} (format: ${format})`);
      const priv = toBytesAuto(inputs.privateKey);
      const peerPub = toBytesAuto(inputs.peerPublicKey);
      const sharedSecret = eccSharedSecret(priv, peerPub, curve, format);
      const rawSecretX = eccSharedSecret(priv, peerPub, curve, 'raw_x');
      log(`ECDH shared secret computed successfully (${sharedSecret.length} bytes)`);
      return { sharedSecret, rawSecretX };
    },
  },

  // 10. Ed25519 KeyGen
  {
    type: 'asymmetric-ed25519-keygen',
    label: 'Ed25519 KeyGen',
    category: 'asymmetric',
    description: 'Generates Ed25519 32-byte keypair',
    inputs: [],
    outputs: [
      { id: 'privateKey', name: 'Private Key', spec: '32B', dataType: 'bytes' },
      { id: 'publicKey', name: 'Public Key', spec: '32B', dataType: 'bytes' },
    ],
    propertySchema: [],
    errorProfile: NONE_PROFILE,
    execute: async ({ log }) => {
      log('Generating Ed25519 keypair');
      return ed25519GenerateKeyPair();
    },
  },

  // 11. Ed25519 Sign
  {
    type: 'asymmetric-ed25519-sign',
    label: 'Ed25519 Sign',
    category: 'asymmetric',
    description: 'High-speed Edwards-curve digital signature (RFC 8032)',
    inputs: [
      { id: 'privateKey', name: 'Private Key', spec: '32B', dataType: 'bytes', required: true },
      { id: 'message', name: 'Message', dataType: 'bytes', required: true },
    ],
    outputs: [
      { id: 'signature', name: 'Signature', spec: '64B', dataType: 'bytes', description: 'Ed25519 signature (R || S).' },
    ],
    propertySchema: [],
    errorProfile: fixedErrorProfile(['INVALID_KEY_MATERIAL']),
    execute: async ({ inputs, log }) => {
      log('Signing message with Ed25519');
      const signature = ed25519Sign(inputs.message, inputs.privateKey);
      return { signature };
    },
  },

  // 12. Ed25519 Verify
  {
    type: 'asymmetric-ed25519-verify',
    label: 'Ed25519 Verify',
    category: 'asymmetric',
    description: 'Verifies Ed25519 signature (RFC 8032)',
    inputs: [
      { id: 'publicKey', name: 'Public Key', spec: '32B', dataType: 'bytes', required: true },
      { id: 'message', name: 'Message', dataType: 'bytes', required: true },
      { id: 'signature', name: 'Signature', spec: '64B', dataType: 'bytes', required: true, description: 'Ed25519 signature (R || S).' },
    ],
    outputs: [
      { id: 'isValid', name: 'Valid', dataType: 'bool', description: 'True if the Ed25519 signature verification succeeded.' },
    ],
    propertySchema: [...JUDGEMENT_ERROR_FIELDS],
    errorProfile: { kind: 'judgement', port: 'isValid' },
    execute: async ({ inputs, log }) => {
      log('Verifying Ed25519 signature');
      const isValid = ed25519Verify(inputs.signature, inputs.message, inputs.publicKey);
      return { isValid };
    },
  },

  // 13. X25519 KeyGen
  {
    type: 'asymmetric-x25519-keygen',
    label: 'X25519 KeyGen',
    category: 'asymmetric',
    description: 'Generates X25519 keypair for ECDH',
    inputs: [],
    outputs: [
      { id: 'privateKey', name: 'Private Key', spec: '32B', dataType: 'bytes' },
      { id: 'publicKey', name: 'Public Key', spec: '32B', dataType: 'bytes' },
    ],
    propertySchema: [],
    errorProfile: NONE_PROFILE,
    execute: async ({ log }) => {
      log('Generating X25519 keypair');
      return x25519GenerateKeyPair();
    },
  },

  // 14. X25519 ECDH Key Exchange
  {
    type: 'asymmetric-x25519-ecdh',
    label: 'X25519 Key Exchange (ECDH)',
    category: 'asymmetric',
    description: 'Montgomery-curve Diffie-Hellman shared secret (RFC 7748)',
    inputs: [
      { id: 'privateKey', name: 'My Private Key', spec: '32B', dataType: 'bytes', required: true },
      { id: 'peerPublicKey', name: 'Peer Public Key', spec: '32B', dataType: 'bytes', required: true },
    ],
    outputs: [
      { id: 'sharedSecret', name: 'Shared Secret', spec: '32B', dataType: 'bytes' },
    ],
    propertySchema: [],
    errorProfile: fixedErrorProfile(['INVALID_KEY_MATERIAL']),
    execute: async ({ inputs, log }) => {
      log('Computing X25519 ECDH shared secret');
      const priv = toBytesAuto(inputs.privateKey);
      const peerPub = toBytesAuto(inputs.peerPublicKey);
      const sharedSecret = x25519SharedSecret(priv, peerPub);
      log(`X25519 ECDH shared secret computed (${sharedSecret.length} bytes)`);
      return { sharedSecret };
    },
  },

  // 15. PQC ML-KEM KeyGen (FIPS 203)
  {
    type: 'pqc-mlkem-keygen',
    label: 'ML-KEM KeyGen (FIPS 203)',
    category: 'pqc',
    description: 'Post-Quantum Lattice-based Key Encapsulation Mechanism keypair generator',
    inputs: [],
    outputs: [
      { id: 'publicKey', name: 'Public Key', spec: 'Encaps', dataType: 'bytes', description: 'Public key used by the sender to encapsulate a shared secret.' },
      { id: 'secretKey', name: 'Secret Key', spec: 'Decaps', dataType: 'bytes', description: 'Secret key used by the recipient to decapsulate the shared secret.' },
    ],
    propertySchema: [
      {
        id: 'variant',
        label: 'Security Level',
        type: 'select',
        options: [
          { label: 'ML-KEM-512 (NIST Level 1)', value: 512 },
          { label: 'ML-KEM-768 (NIST Level 3)', value: 768 },
          { label: 'ML-KEM-1024 (NIST Level 5)', value: 1024 },
        ],
        defaultValue: 768,
      },
    ],
    errorProfile: NONE_PROFILE,
    execute: async ({ properties, log }) => {
      const level = (Number(properties.variant) || 768) as MlKemSecurityLevel;
      log(`Generating PQC ML-KEM-${level} keypair`);
      return mlKemGenerateKeyPair(level);
    },
  },

  // 16. PQC ML-KEM Encapsulation
  {
    type: 'pqc-mlkem-encaps',
    label: 'ML-KEM Encapsulate',
    category: 'pqc',
    description: 'Encapsulates a shared key against recipient public key',
    inputs: [
      { id: 'publicKey', name: 'Recipient Public Key', dataType: 'bytes', required: true },
    ],
    outputs: [
      { id: 'sharedSecret', name: 'Shared Key', spec: '32B', dataType: 'bytes' },
      { id: 'ciphertext', name: 'Ciphertext', dataType: 'bytes' },
    ],
    propertySchema: [
      {
        id: 'variant',
        label: 'Variant',
        type: 'select',
        options: MLKEM_VARIANT_OPTIONS,
        defaultValue: 768,
      },
    ],
    errorProfile: fixedErrorProfile(['INVALID_KEY_MATERIAL']),
    execute: async ({ inputs, properties, log }) => {
      const level = (Number(properties.variant) || 768) as MlKemSecurityLevel;
      log(`Encapsulating with ML-KEM-${level}`);
      return mlKemEncapsulate(inputs.publicKey, level);
    },
  },

  // 17. PQC ML-KEM Decapsulation
  {
    type: 'pqc-mlkem-decaps',
    label: 'ML-KEM Decapsulate',
    category: 'pqc',
    description: 'Decapsulates shared key using secret key and ciphertext',
    inputs: [
      { id: 'secretKey', name: 'Secret Key', dataType: 'bytes', required: true },
      { id: 'ciphertext', name: 'Ciphertext', dataType: 'bytes', required: true },
    ],
    outputs: [
      { id: 'sharedSecret', name: 'Recovered Shared Key', spec: '32B', dataType: 'bytes' },
    ],
    propertySchema: [
      {
        id: 'variant',
        label: 'Variant',
        type: 'select',
        options: MLKEM_VARIANT_OPTIONS,
        defaultValue: 768,
      },
    ],
    errorProfile: fixedErrorProfile(['INVALID_KEY_MATERIAL']),
    execute: async ({ inputs, properties, log }) => {
      const level = (Number(properties.variant) || 768) as MlKemSecurityLevel;
      log(`Decapsulating with ML-KEM-${level}`);
      const sharedSecret = mlKemDecapsulate(inputs.ciphertext, inputs.secretKey, level);
      return { sharedSecret };
    },
  },

  // 18. PQC ML-DSA KeyGen (FIPS 204)
  {
    type: 'pqc-mldsa-keygen',
    label: 'ML-DSA KeyGen (FIPS 204)',
    category: 'pqc',
    description: 'Post-Quantum Lattice-based Digital Signature Algorithm keypair generator',
    inputs: [],
    outputs: [
      { id: 'publicKey', name: 'Public Key', dataType: 'bytes' },
      { id: 'secretKey', name: 'Secret Key', dataType: 'bytes' },
    ],
    propertySchema: [
      {
        id: 'variant',
        label: 'Security Level',
        type: 'select',
        options: [
          { label: 'ML-DSA-44 (NIST Level 2)', value: 44 },
          { label: 'ML-DSA-65 (NIST Level 3)', value: 65 },
          { label: 'ML-DSA-87 (NIST Level 5)', value: 87 },
        ],
        defaultValue: 65,
      },
    ],
    errorProfile: NONE_PROFILE,
    execute: async ({ properties, log }) => {
      const level = (Number(properties.variant) || 65) as MlDsaSecurityLevel;
      log(`Generating PQC ML-DSA-${level} keypair`);
      return mlDsaGenerateKeyPair(level);
    },
  },

  // 19. PQC ML-DSA Sign
  {
    type: 'pqc-mldsa-sign',
    label: 'ML-DSA Sign',
    category: 'pqc',
    description: 'Creates post-quantum digital signature (FIPS 204)',
    inputs: [
      { id: 'secretKey', name: 'Secret Key', dataType: 'bytes', required: true },
      { id: 'message', name: 'Message', dataType: 'bytes', required: true },
    ],
    outputs: [
      { id: 'signature', name: 'Signature', dataType: 'bytes' },
    ],
    propertySchema: [
      {
        id: 'variant',
        label: 'Variant',
        type: 'select',
        options: MLDSA_VARIANT_OPTIONS,
        defaultValue: 65,
      },
    ],
    errorProfile: fixedErrorProfile(['INVALID_KEY_MATERIAL']),
    execute: async ({ inputs, properties, log }) => {
      const level = (Number(properties.variant) || 65) as MlDsaSecurityLevel;
      log(`Signing with ML-DSA-${level}`);
      const signature = mlDsaSign(inputs.message, inputs.secretKey, level);
      return { signature };
    },
  },

  // 20. PQC ML-DSA Verify
  {
    type: 'pqc-mldsa-verify',
    label: 'ML-DSA Verify',
    category: 'pqc',
    description: 'Verifies post-quantum digital signature (FIPS 204)',
    inputs: [
      { id: 'publicKey', name: 'Public Key', dataType: 'bytes', required: true },
      { id: 'message', name: 'Message', dataType: 'bytes', required: true },
      { id: 'signature', name: 'Signature', dataType: 'bytes', required: true },
    ],
    outputs: [
      { id: 'isValid', name: 'Valid', dataType: 'bool', description: 'True if the ML-DSA signature verification succeeded.' },
    ],
    propertySchema: [
      {
        id: 'variant',
        label: 'Variant',
        type: 'select',
        options: MLDSA_VARIANT_OPTIONS,
        defaultValue: 65,
      },
      ...JUDGEMENT_ERROR_FIELDS,
    ],
    errorProfile: { kind: 'judgement', port: 'isValid' },
    execute: async ({ inputs, properties, log }) => {
      const level = (Number(properties.variant) || 65) as MlDsaSecurityLevel;
      log(`Verifying ML-DSA-${level} signature`);
      const isValid = mlDsaVerify(inputs.signature, inputs.message, inputs.publicKey, level);
      return { isValid };
    },
  },

  // 21. PQC SLH-DSA KeyGen (FIPS 205 / ND-4.6)
  {
    type: 'pqc-slhdsa-keygen',
    label: 'SLH-DSA KeyGen (FIPS 205)',
    category: 'pqc',
    description: 'Stateless Hash-Based Digital Signature Algorithm keypair generator (FIPS 205)',
    inputs: [],
    outputs: [
      { id: 'publicKey', name: 'Public Key', dataType: 'bytes' },
      { id: 'secretKey', name: 'Secret Key', dataType: 'bytes' },
    ],
    propertySchema: [
      {
        id: 'variant',
        label: 'Parameter Set',
        type: 'select',
        options: [
          { label: 'SLH-DSA-SHA2-128s (Small Signature)', value: 'slh_dsa_sha2_128s' },
          { label: 'SLH-DSA-SHA2-128f (Fast)', value: 'slh_dsa_sha2_128f' },
          { label: 'SLH-DSA-SHAKE-128s', value: 'slh_dsa_shake_128s' },
          { label: 'SLH-DSA-SHAKE-128f', value: 'slh_dsa_shake_128f' },
          { label: 'SLH-DSA-SHA2-256s', value: 'slh_dsa_sha2_256s' },
          { label: 'SLH-DSA-SHAKE-256s', value: 'slh_dsa_shake_256s' },
        ],
        defaultValue: 'slh_dsa_sha2_128s',
      },
    ],
    errorProfile: NONE_PROFILE,
    execute: async ({ properties, log }) => {
      const variant = (properties.variant || 'slh_dsa_sha2_128s') as SlhDsaVariant;
      log(`Generating PQC SLH-DSA keypair (${variant})`);
      return slhDsaGenerateKeyPair(variant);
    },
  },

  // 22. PQC SLH-DSA Sign (ND-4.6)
  {
    type: 'pqc-slhdsa-sign',
    label: 'SLH-DSA Sign (FIPS 205)',
    category: 'pqc',
    description: 'Signs message using stateless hash-based signature scheme (FIPS 205)',
    inputs: [
      { id: 'secretKey', name: 'Secret Key', dataType: 'bytes', required: true },
      { id: 'message', name: 'Message Data', dataType: 'bytes', required: true },
    ],
    outputs: [
      { id: 'signature', name: 'Signature', dataType: 'bytes' },
    ],
    propertySchema: [
      {
        id: 'variant',
        label: 'Parameter Set',
        type: 'select',
        options: SLHDSA_VARIANT_OPTIONS,
        defaultValue: 'slh_dsa_sha2_128s',
      },
    ],
    errorProfile: fixedErrorProfile(['INVALID_KEY_MATERIAL']),
    execute: async ({ inputs, properties, log }) => {
      const variant = (properties.variant || 'slh_dsa_sha2_128s') as SlhDsaVariant;
      log(`Signing message with SLH-DSA (${variant})`);
      const signature = slhDsaSign(inputs.message, inputs.secretKey, variant);
      return { signature };
    },
  },

  // 23. PQC SLH-DSA Verify (ND-4.6)
  {
    type: 'pqc-slhdsa-verify',
    label: 'SLH-DSA Verify (FIPS 205)',
    category: 'pqc',
    description: 'Verifies stateless hash-based digital signature (FIPS 205)',
    inputs: [
      { id: 'publicKey', name: 'Public Key', dataType: 'bytes', required: true },
      { id: 'message', name: 'Message Data', dataType: 'bytes', required: true },
      { id: 'signature', name: 'Signature', dataType: 'bytes', required: true },
    ],
    outputs: [
      { id: 'isValid', name: 'Valid', dataType: 'bool', description: 'True if the SLH-DSA signature verification succeeded.' },
    ],
    propertySchema: [
      {
        id: 'variant',
        label: 'Parameter Set',
        type: 'select',
        options: SLHDSA_VARIANT_OPTIONS,
        defaultValue: 'slh_dsa_sha2_128s',
      },
      ...JUDGEMENT_ERROR_FIELDS,
    ],
    errorProfile: { kind: 'judgement', port: 'isValid' },
    execute: async ({ inputs, properties, log }) => {
      const variant = (properties.variant || 'slh_dsa_sha2_128s') as SlhDsaVariant;
      log(`Verifying SLH-DSA (${variant}) signature`);
      const isValid = slhDsaVerify(inputs.signature, inputs.message, inputs.publicKey, variant);
      log(`Verification result: ${isValid ? 'VALID' : 'INVALID'}`);
      return { isValid };
    },
  },

  // 24. PQC Hybrid KEM KeyGen (ND-4.7)
  {
    type: 'pqc-hybridkem-keygen',
    label: 'Hybrid KEM KeyGen',
    category: 'pqc',
    description: 'Generates Post-Quantum Hybrid Keypair (X25519 + ML-KEM-768)',
    inputs: [],
    outputs: [
      { id: 'publicKey', name: 'Hybrid Public Key', dataType: 'bytes' },
      { id: 'secretKey', name: 'Hybrid Secret Key', dataType: 'bytes' },
    ],
    propertySchema: [],
    errorProfile: NONE_PROFILE,
    execute: async ({ log }) => {
      log('Generating X25519 + ML-KEM-768 Hybrid KEM keypair');
      return hybridKemGenerateKeyPair();
    },
  },

  // 25. PQC Hybrid KEM Encapsulate (ND-4.7)
  {
    type: 'pqc-hybridkem-encaps',
    label: 'Hybrid KEM Encapsulate',
    category: 'pqc',
    description: 'Encapsulates shared secret using hybrid X25519 + ML-KEM-768 recipient public key',
    inputs: [
      { id: 'publicKey', name: 'Recipient Public Key', dataType: 'bytes', required: true },
    ],
    outputs: [
      { id: 'sharedSecret', name: 'Shared Secret', spec: 'Combined', dataType: 'bytes', description: 'Combined shared secret derived from both the X25519 and ML-KEM-768 components.' },
      { id: 'ciphertext', name: 'Hybrid Ciphertext', dataType: 'bytes' },
    ],
    propertySchema: [],
    errorProfile: fixedErrorProfile(['INVALID_KEY_MATERIAL']),
    execute: async ({ inputs, log }) => {
      log('Encapsulating hybrid key with X25519 + ML-KEM-768');
      return hybridKemEncapsulate(inputs.publicKey);
    },
  },

  // 26. PQC Hybrid KEM Decapsulate (ND-4.7)
  {
    type: 'pqc-hybridkem-decaps',
    label: 'Hybrid KEM Decapsulate',
    category: 'pqc',
    description: 'Decapsulates shared secret using hybrid secret key and ciphertext',
    inputs: [
      { id: 'secretKey', name: 'Hybrid Secret Key', dataType: 'bytes', required: true },
      { id: 'ciphertext', name: 'Hybrid Ciphertext', dataType: 'bytes', required: true },
    ],
    outputs: [
      { id: 'sharedSecret', name: 'Recovered Shared Secret', dataType: 'bytes' },
    ],
    propertySchema: [],
    errorProfile: fixedErrorProfile(['INVALID_KEY_MATERIAL']),
    execute: async ({ inputs, log }) => {
      log('Decapsulating hybrid key with X25519 + ML-KEM-768');
      const sharedSecret = hybridKemDecapsulate(inputs.ciphertext, inputs.secretKey);
      return { sharedSecret };
    },
  },
];
