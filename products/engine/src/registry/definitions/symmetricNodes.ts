/**
 * Symmetric Cipher Node Definitions (AES, TDES, DES, SEED, ARIA, ChaCha20, Camellia, SM4)
 */

import { NodeDefinition, PropertyFieldDefinition } from '../../dag/types';
import { NodeError } from '../../dag/errors';
import { aesEncrypt, aesDecrypt, AesMode, AesPadding } from '../../crypto/symmetric/aes';
import {
  chacha20Poly1305Encrypt,
  chacha20Poly1305Decrypt,
  chacha20StreamEncrypt,
} from '../../crypto/symmetric/chacha20poly1305';
import { tdesEncrypt, tdesDecrypt } from '../../crypto/symmetric/tdes';
import { seedEncrypt, seedDecrypt } from '../../crypto/symmetric/seed';
import { ariaEncrypt, ariaDecrypt } from '../../crypto/symmetric/aria';
import { sm4Encrypt, sm4Decrypt } from '../../crypto/symmetric/sm4';
import { camelliaEncrypt, camelliaDecrypt } from '../../crypto/symmetric/camellia';
import { fixedErrorProfile } from '../errorProfile';
import {
  applyBlockPadding,
  removeBlockPadding,
  BlockPaddingType,
  rsaOaepEncode,
  rsaOaepDecode,
  rsaPssEncode,
} from '../../crypto/padding/padding';
import {
  PADDING_OPTIONS_ENCRYPT_16B,
  PADDING_OPTIONS_DECRYPT_16B,
  PADDING_OPTIONS_ENCRYPT_8B,
  PADDING_OPTIONS_DECRYPT_8B,
} from '../../crypto/padding/paddingOptions';
import {
  AES_MODE_OPTIONS,
  SEED_MODE_OPTIONS,
  ARIA_MODE_OPTIONS,
  CBC_ECB_CTR_GCM_MODE_OPTIONS,
  DES_MODE_OPTIONS,
} from '../../crypto/symmetric/cipherModeOptions';

// Common AEAD block cipher port-visibility rules (PRD §4.3), shared by AES and every
// makeBlockCipherAeadPair-based cipher (SEED/ARIA/Camellia/SM4): GCM/CCM are the only AEAD
// modes across all of these ciphers' modeOptions, and ECB/KW are the only modes with no IV
// concept at all -- so these predicates need no per-cipher parameterization.
const isAeadMode = (mode: string) => mode === 'GCM' || mode === 'CCM';
const NO_IV_MODES = new Set(['ECB', 'KW']);
const showIvPort = (p: Record<string, any>) => !isAeadMode(p.mode) && !NO_IV_MODES.has(p.mode);
const showNoncePort = (p: Record<string, any>) => isAeadMode(p.mode);
const showAeadPort = (p: Record<string, any>) => isAeadMode(p.mode);

// errorProfile: fixed (T04, execution-semantics.md §3.1). Reusable code/message
// catalog for the built-in failures every symmetric/padding node in this file can throw as
// NodeError, and the "unify" property fields every fixed-profile node exposes so the user can
// replace all of a node's built-in errors with one custom code/message (runner.ts applies the
// override; nodes don't need their own unify logic).

export const ERROR_UNIFY_FIELDS:PropertyFieldDefinition[] = [
  { id: 'errorUnify', label: 'Unify Errors', type: 'boolean', defaultValue: false, description: 'Replaces every built-in error of this node with the single custom code/message below.' },
  { id: 'errorUnifyCode', label: 'Unified Error Code', type: 'text', defaultValue: '', showWhen: (p) => !!p.errorUnify, description: 'Error code to use when unifying.' },
  { id: 'errorUnifyMessage', label: 'Unified Error Message', type: 'text', defaultValue: '', showWhen: (p) => !!p.errorUnify, description: 'Error message to use when unifying.' },
];

interface BlockCipherAeadEncryptArgs {
  plaintext: Uint8Array;
  key: Uint8Array;
  iv?: Uint8Array;
  mode?: any;
  padding?: any;
  aad?: Uint8Array;
}
interface BlockCipherAeadEncryptResult {
  ciphertext: Uint8Array;
  iv: Uint8Array;
  tag?: Uint8Array;
}
interface BlockCipherAeadDecryptArgs {
  ciphertext: Uint8Array;
  key: Uint8Array;
  iv?: Uint8Array;
  tag?: Uint8Array;
  aad?: Uint8Array;
  mode?: any;
  padding?: any;
}

interface BlockCipherAeadConfig {
  /** Node type / display name segment, e.g. 'seed' -> 'symmetric-seed-encrypt' */
  id: string;
  /** Display name used in labels and log messages, e.g. 'SEED' */
  name: string;
  /** Whether log messages include the key bit-length (e.g. "SEED-256"); false for fixed-key-size ciphers like SM4 */
  includeKeyLengthInLog: boolean;
  encryptDescription: string;
  decryptDescription: string;
  keySpec: string;
  aadSpec: string;
  tagSpec: string;
  modeOptions: { label: string; value: string }[];
  defaultMode: string;
  encryptFn: (args: BlockCipherAeadEncryptArgs) => BlockCipherAeadEncryptResult;
  decryptFn: (args: BlockCipherAeadDecryptArgs) => Uint8Array;
}

/**
 * Generates the matching Encrypt/Decrypt NodeDefinition pair for a block cipher whose
 * encrypt/decrypt functions take a single {plaintext|ciphertext, key, iv, mode, padding, aad}
 * params object and an encrypt result of {ciphertext, iv, tag?} (AES, SEED, ARIA, Camellia, SM4
 * all share this exact shape). Ciphers with a different calling convention (e.g. (T)DES, which
 * takes positional args and has no AEAD tag/aad) are left hand-written instead of forced through
 * this factory.
 */
function makeBlockCipherAeadPair(cfg: BlockCipherAeadConfig): [NodeDefinition, NodeDefinition] {
  const hasAead = cfg.modeOptions.some((o) => o.value === 'GCM' || o.value === 'CCM');
  const encryptCases = ['INVALID_KEY_LENGTH', 'INVALID_IV_LENGTH', 'PLAINTEXT_NOT_BLOCK_ALIGNED', ...(hasAead ? ['INVALID_NONCE_LENGTH'] : [])];
  const decryptCases = ['INVALID_KEY_LENGTH', 'INVALID_IV_LENGTH', 'CIPHERTEXT_NOT_BLOCK_ALIGNED', 'INVALID_PADDING', ...(hasAead ? ['INVALID_NONCE_LENGTH', 'INVALID_TAG_LENGTH', 'AUTH_TAG_MISMATCH'] : [])];

  const encrypt: NodeDefinition = {
    type: `symmetric-${cfg.id}-encrypt`,
    label: `${cfg.name} Encrypt`,
    category: 'symmetric',
    description: cfg.encryptDescription,
    inputs: [
      { id: 'key', name: 'Key', spec: cfg.keySpec, dataType: 'bytes', required: true, description: `${cfg.name} symmetric key (${cfg.keySpec}).` },
      { id: 'plaintext', name: 'Plaintext', dataType: 'bytes', required: true },
      { id: 'iv', name: 'IV', spec: '16B', dataType: 'bytes', required: false, showWhen: showIvPort, description: 'Initialization vector/counter (16B). Defaults to 16 zero bytes if omitted.' },
      { id: 'nonce', name: 'Nonce', spec: '12B', dataType: 'bytes', required: false, showWhen: showNoncePort, description: `AEAD nonce (12B), used only in ${cfg.aadSpec} mode. Defaults to 12 zero bytes if omitted.` },
      { id: 'aad', name: 'AAD', spec: cfg.aadSpec, dataType: 'bytes', required: false, showWhen: showAeadPort, description: `Additional Authenticated Data, used only in ${cfg.aadSpec} mode.` },
    ],
    outputs: [
      { id: 'ciphertext', name: 'Ciphertext', dataType: 'bytes' },
      { id: 'tag', name: 'Auth Tag', spec: cfg.tagSpec, dataType: 'bytes', showWhen: showAeadPort, description: `Authentication tag produced in ${cfg.tagSpec} mode.` },
    ],
    propertySchema: [
      { id: 'mode', label: 'Cipher Mode', type: 'select', options: cfg.modeOptions, defaultValue: cfg.defaultMode, helpTopic: 'cipherMode' },
      { id: 'padding', label: 'Padding', type: 'select', options: PADDING_OPTIONS_ENCRYPT_16B, defaultValue: 'None', helpTopic: 'padding' },
      ...ERROR_UNIFY_FIELDS,
    ],
    errorProfile: fixedErrorProfile(encryptCases),
    execute: async ({ inputs, properties, log }) => {
      const mode = properties.mode || cfg.defaultMode;
      const padding = properties.padding || 'None';
      log(
        cfg.includeKeyLengthInLog
          ? `Running ${cfg.name}-${inputs.key.length * 8} Encrypt (${mode})`
          : `Running ${cfg.name} Encrypt (${mode})`
      );
      const res = cfg.encryptFn({
        plaintext: inputs.plaintext,
        key: inputs.key,
        iv: inputs.iv ?? inputs.nonce,
        mode,
        padding,
        aad: inputs.aad,
      });
      return {
        ciphertext: res.ciphertext,
        tag: res.tag || new Uint8Array(0),
      };
    },
  };

  const decrypt: NodeDefinition = {
    type: `symmetric-${cfg.id}-decrypt`,
    label: `${cfg.name} Decrypt`,
    category: 'symmetric',
    description: cfg.decryptDescription,
    inputs: [
      { id: 'key', name: 'Key', spec: cfg.keySpec, dataType: 'bytes', required: true, description: `${cfg.name} symmetric key (${cfg.keySpec}).` },
      { id: 'ciphertext', name: 'Ciphertext', dataType: 'bytes', required: true },
      { id: 'iv', name: 'IV', spec: '16B', dataType: 'bytes', required: false, showWhen: showIvPort, description: 'Initialization vector/counter (16B) used during encryption. Defaults to 16 zero bytes if omitted.' },
      { id: 'nonce', name: 'Nonce', spec: '12B', dataType: 'bytes', required: false, showWhen: showNoncePort, description: `AEAD nonce (12B) used during encryption, required in ${cfg.aadSpec} mode. Defaults to 12 zero bytes if omitted.` },
      { id: 'tag', name: 'Auth Tag', spec: cfg.tagSpec, dataType: 'bytes', required: false, showWhen: showAeadPort, description: `Authentication tag to verify, required in ${cfg.tagSpec} mode.` },
      { id: 'aad', name: 'AAD', spec: cfg.aadSpec, dataType: 'bytes', required: false, showWhen: showAeadPort, description: `Additional Authenticated Data, used only in ${cfg.aadSpec} mode.` },
    ],
    outputs: [
      { id: 'plaintext', name: 'Plaintext', dataType: 'bytes' },
    ],
    propertySchema: [
      { id: 'mode', label: 'Cipher Mode', type: 'select', options: cfg.modeOptions, defaultValue: cfg.defaultMode, helpTopic: 'cipherMode' },
      { id: 'padding', label: 'Padding', type: 'select', options: PADDING_OPTIONS_DECRYPT_16B, defaultValue: 'None', helpTopic: 'padding' },
      ...ERROR_UNIFY_FIELDS,
    ],
    errorProfile: fixedErrorProfile(decryptCases),
    execute: async ({ inputs, properties, log }) => {
      const mode = properties.mode || cfg.defaultMode;
      const padding = properties.padding || 'None';
      log(
        cfg.includeKeyLengthInLog
          ? `Running ${cfg.name}-${inputs.key.length * 8} Decrypt (${mode})`
          : `Running ${cfg.name} Decrypt (${mode})`
      );
      const plaintext = cfg.decryptFn({
        ciphertext: inputs.ciphertext,
        key: inputs.key,
        iv: inputs.iv ?? inputs.nonce,
        tag: inputs.tag,
        aad: inputs.aad,
        mode,
        padding,
      });
      return { plaintext };
    },
  };

  return [encrypt, decrypt];
}

const BLOCK_CIPHER_AEAD_CONFIGS: BlockCipherAeadConfig[] = [
  {
    id: 'seed',
    name: 'SEED',
    includeKeyLengthInLog: true,
    encryptDescription: 'KISA National Standard SEED 128/256-bit Block Cipher (RFC 4269)',
    decryptDescription: 'KISA National Standard SEED 128/256-bit Block Cipher Decryption',
    keySpec: '16/32B',
    aadSpec: 'GCM/CCM',
    tagSpec: 'GCM/CCM',
    modeOptions: SEED_MODE_OPTIONS,
    defaultMode: 'ECB',
    encryptFn: seedEncrypt,
    decryptFn: seedDecrypt,
  },
  {
    id: 'aria',
    name: 'ARIA',
    includeKeyLengthInLog: true,
    encryptDescription: 'KISA Standard ARIA (128/192/256-bit) Block Cipher (RFC 5794)',
    decryptDescription: 'KISA Standard ARIA Block Cipher Decryption',
    keySpec: '16/24/32B',
    aadSpec: 'GCM/CCM',
    tagSpec: 'GCM/CCM',
    modeOptions: ARIA_MODE_OPTIONS,
    defaultMode: 'ECB',
    encryptFn: ariaEncrypt,
    decryptFn: ariaDecrypt,
  },
  {
    id: 'camellia',
    name: 'Camellia',
    includeKeyLengthInLog: true,
    encryptDescription: 'NTT & Mitsubishi Standard Camellia (128/192/256-bit) Block Cipher (RFC 3713)',
    decryptDescription: 'NTT & Mitsubishi Standard Camellia Block Cipher Decryption',
    keySpec: '16/24/32B',
    aadSpec: 'GCM only',
    tagSpec: 'GCM',
    modeOptions: CBC_ECB_CTR_GCM_MODE_OPTIONS,
    defaultMode: 'ECB',
    encryptFn: camelliaEncrypt,
    decryptFn: camelliaDecrypt,
  },
  {
    id: 'sm4',
    name: 'SM4',
    includeKeyLengthInLog: false,
    encryptDescription: 'Chinese National Standard SM4 128-bit Block Cipher (GB/T 32907 / GM/T 0002)',
    decryptDescription: 'Chinese National Standard SM4 128-bit Block Cipher Decryption',
    keySpec: '16B',
    aadSpec: 'GCM only',
    tagSpec: 'GCM',
    modeOptions: CBC_ECB_CTR_GCM_MODE_OPTIONS,
    defaultMode: 'ECB',
    encryptFn: sm4Encrypt,
    decryptFn: sm4Decrypt,
  },
];

const [
  seedEncryptNode, seedDecryptNode,
  ariaEncryptNode, ariaDecryptNode,
  camelliaEncryptNode, camelliaDecryptNode,
  sm4EncryptNode, sm4DecryptNode,
] = BLOCK_CIPHER_AEAD_CONFIGS.flatMap(makeBlockCipherAeadPair);

export const symmetricNodes: NodeDefinition[] = [
  // 1. AES Encrypt
  {
    type: 'symmetric-aes-encrypt',
    label: 'AES Encrypt',
    category: 'symmetric',
    description: 'Encrypts plaintext using NIST AES (128/192/256-bit)',
    inputs: [
      { id: 'key', name: 'Key', spec: '16/24/32B', dataType: 'bytes', required: true, description: 'AES symmetric key. Length selects AES-128/192/256.' },
      { id: 'plaintext', name: 'Plaintext', dataType: 'bytes', required: true },
      { id: 'iv', name: 'IV', spec: '16B', dataType: 'bytes', required: false, showWhen: showIvPort, description: 'Initialization vector/counter/tweak (16B). Defaults to 16 zero bytes if omitted.' },
      { id: 'nonce', name: 'Nonce', spec: '12B', dataType: 'bytes', required: false, showWhen: showNoncePort, description: 'AEAD nonce (12B), used only in GCM/CCM mode. Defaults to 12 zero bytes if omitted.' },
      { id: 'aad', name: 'AAD', spec: 'GCM/CCM only', dataType: 'bytes', required: false, showWhen: showAeadPort, description: 'Additional Authenticated Data, used only in GCM/CCM mode.' },
    ],
    outputs: [
      { id: 'ciphertext', name: 'Ciphertext', dataType: 'bytes' },
      { id: 'tag', name: 'Auth Tag', spec: 'GCM/CCM', dataType: 'bytes', showWhen: showAeadPort, description: 'Authentication tag produced in GCM/CCM mode.' },
    ],
    propertySchema: [
      {
        id: 'mode',
        label: 'Cipher Mode',
        type: 'select',
        options: AES_MODE_OPTIONS,
        defaultValue: 'ECB',
        helpTopic: 'cipherMode',
      },
      {
        id: 'padding',
        label: 'Padding (CBC/ECB)',
        type: 'select',
        options: PADDING_OPTIONS_ENCRYPT_16B,
        defaultValue: 'None',
        helpTopic: 'padding',
      },
      ...ERROR_UNIFY_FIELDS,
    ],
    errorProfile: fixedErrorProfile(['INVALID_KEY_LENGTH', 'INVALID_IV_LENGTH', 'INVALID_NONCE_LENGTH', 'PLAINTEXT_NOT_BLOCK_ALIGNED', 'DATA_TOO_SHORT']),
    execute: async ({ inputs, properties, log }) => {
      const mode = (properties.mode || 'ECB') as AesMode;
      const padding = (properties.padding || 'None') as AesPadding;
      log(`Running AES-${inputs.key.length * 8} Encrypt (${mode}, ${padding})`);

      const res = aesEncrypt({
        plaintext: inputs.plaintext,
        key: inputs.key,
        iv: inputs.iv ?? inputs.nonce,
        mode,
        padding,
        aad: inputs.aad,
      });

      return {
        ciphertext: res.ciphertext,
        tag: res.tag || new Uint8Array(0),
      };
    },
  },

  // 2. AES Decrypt
  {
    type: 'symmetric-aes-decrypt',
    label: 'AES Decrypt',
    category: 'symmetric',
    description: 'Decrypts ciphertext using NIST AES (128/192/256-bit)',
    inputs: [
      { id: 'key', name: 'Key', spec: '16/24/32B', dataType: 'bytes', required: true, description: 'AES symmetric key. Length selects AES-128/192/256.' },
      { id: 'ciphertext', name: 'Ciphertext', dataType: 'bytes', required: true },
      { id: 'iv', name: 'IV', spec: '16B', dataType: 'bytes', required: false, showWhen: showIvPort, description: 'Initialization vector/counter/tweak (16B) used during encryption. Defaults to 16 zero bytes if omitted.' },
      { id: 'nonce', name: 'Nonce', spec: '12B', dataType: 'bytes', required: false, showWhen: showNoncePort, description: 'AEAD nonce (12B) used during encryption, required in GCM/CCM mode. Defaults to 12 zero bytes if omitted.' },
      { id: 'tag', name: 'Auth Tag', spec: 'GCM/CCM', dataType: 'bytes', required: false, showWhen: showAeadPort, description: 'Authentication tag to verify, required in GCM/CCM mode.' },
      { id: 'aad', name: 'AAD', spec: 'GCM/CCM', dataType: 'bytes', required: false, showWhen: showAeadPort, description: 'Additional Authenticated Data, used only in GCM/CCM mode.' },
    ],
    outputs: [
      { id: 'plaintext', name: 'Plaintext', dataType: 'bytes' },
    ],
    propertySchema: [
      {
        id: 'mode',
        label: 'Cipher Mode',
        type: 'select',
        options: AES_MODE_OPTIONS,
        defaultValue: 'ECB',
        helpTopic: 'cipherMode',
      },
      {
        id: 'padding',
        label: 'Padding (CBC/ECB)',
        type: 'select',
        options: PADDING_OPTIONS_DECRYPT_16B,
        defaultValue: 'None',
        helpTopic: 'padding',
      },
      ...ERROR_UNIFY_FIELDS,
    ],
    errorProfile: fixedErrorProfile(['INVALID_KEY_LENGTH', 'INVALID_IV_LENGTH', 'INVALID_NONCE_LENGTH', 'INVALID_TAG_LENGTH', 'AUTH_TAG_MISMATCH', 'CIPHERTEXT_NOT_BLOCK_ALIGNED', 'INVALID_PADDING', 'DATA_TOO_SHORT']),
    execute: async ({ inputs, properties, log }) => {
      const mode = (properties.mode || 'ECB') as AesMode;
      const padding = (properties.padding || 'None') as AesPadding;
      log(`Running AES-${inputs.key.length * 8} Decrypt (${mode}, ${padding})`);

      const plaintext = aesDecrypt({
        ciphertext: inputs.ciphertext,
        key: inputs.key,
        iv: inputs.iv ?? inputs.nonce,
        tag: inputs.tag,
        aad: inputs.aad,
        mode,
        padding,
      });

      return { plaintext };
    },
  },

  // 3. TDES Encrypt
  {
    type: 'symmetric-tdes-encrypt',
    label: 'TDES Encrypt',
    category: 'symmetric',
    description: 'Triple-DES (112 or 168-bit Key) Encryption (NIST SP 800-67)',
    inputs: [
      { id: 'key', name: 'Key', spec: '16/24B', dataType: 'bytes', required: true, description: '16 bytes for two-key (112-bit) or 24 bytes for three-key (168-bit) 3DES.' },
      { id: 'plaintext', name: 'Plaintext', dataType: 'bytes', required: true },
      { id: 'iv', name: 'IV', spec: '8B', dataType: 'bytes', required: false, showWhen: showIvPort, description: 'Initialization vector for CBC mode (DES block size).' },
    ],
    outputs: [
      { id: 'ciphertext', name: 'Ciphertext', dataType: 'bytes' },
    ],
    propertySchema: [
      {
        id: 'mode',
        label: 'Cipher Mode',
        type: 'select',
        options: DES_MODE_OPTIONS,
        defaultValue: 'ECB',
        helpTopic: 'cipherMode',
      },
      {
        id: 'padding',
        label: 'Padding',
        type: 'select',
        options: PADDING_OPTIONS_ENCRYPT_8B,
        defaultValue: 'None',
        helpTopic: 'padding',
      },
      ...ERROR_UNIFY_FIELDS,
    ],
    errorProfile: fixedErrorProfile(['INVALID_KEY_LENGTH', 'PLAINTEXT_NOT_BLOCK_ALIGNED']),
    execute: async ({ inputs, properties, log }) => {
      log('Running Triple-DES Encrypt');
      const res = tdesEncrypt(
        inputs.plaintext,
        inputs.key,
        inputs.iv,
        properties.mode || 'ECB',
        properties.padding || 'None'
      );
      return res;
    },
  },

  // 4. TDES Decrypt
  {
    type: 'symmetric-tdes-decrypt',
    label: 'TDES Decrypt',
    category: 'symmetric',
    description: 'Triple-DES (112 or 168-bit Key) Decryption',
    inputs: [
      { id: 'key', name: 'Key', spec: '16/24B', dataType: 'bytes', required: true, description: '16 bytes for two-key (112-bit) or 24 bytes for three-key (168-bit) 3DES.' },
      { id: 'ciphertext', name: 'Ciphertext', dataType: 'bytes', required: true },
      { id: 'iv', name: 'IV', spec: '8B', dataType: 'bytes', required: false, showWhen: showIvPort, description: 'Initialization vector for CBC mode (DES block size).' },
    ],
    outputs: [
      { id: 'plaintext', name: 'Plaintext', dataType: 'bytes' },
    ],
    propertySchema: [
      {
        id: 'mode',
        label: 'Cipher Mode',
        type: 'select',
        options: DES_MODE_OPTIONS,
        defaultValue: 'ECB',
        helpTopic: 'cipherMode',
      },
      {
        id: 'padding',
        label: 'Padding',
        type: 'select',
        options: PADDING_OPTIONS_DECRYPT_8B,
        defaultValue: 'None',
        helpTopic: 'padding',
      },
      ...ERROR_UNIFY_FIELDS,
    ],
    errorProfile: fixedErrorProfile(['INVALID_KEY_LENGTH', 'CIPHERTEXT_NOT_BLOCK_ALIGNED', 'INVALID_PADDING']),
    execute: async ({ inputs, properties, log }) => {
      log('Running Triple-DES Decrypt');
      const plaintext = tdesDecrypt(
        inputs.ciphertext,
        inputs.key,
        inputs.iv,
        properties.mode || 'ECB',
        properties.padding || 'None'
      );
      return { plaintext };
    },
  },

  // 5. Single DES Encrypt
  {
    type: 'symmetric-des-encrypt',
    label: 'DES Encrypt',
    category: 'symmetric',
    description: 'Single DES (56-bit effective, 8-byte key) Encryption (FIPS 46-3 Legacy)',
    inputs: [
      { id: 'key', name: 'Key', spec: '8B', dataType: 'bytes', required: true, description: 'Single DES key (56-bit effective).' },
      { id: 'plaintext', name: 'Plaintext', dataType: 'bytes', required: true },
      { id: 'iv', name: 'IV', spec: '8B', dataType: 'bytes', required: false, showWhen: showIvPort, description: 'Initialization vector for CBC mode.' },
    ],
    outputs: [
      { id: 'ciphertext', name: 'Ciphertext', dataType: 'bytes' },
    ],
    propertySchema: [
      {
        id: 'mode',
        label: 'Cipher Mode',
        type: 'select',
        options: DES_MODE_OPTIONS,
        defaultValue: 'ECB',
        helpTopic: 'cipherMode',
      },
      {
        id: 'padding',
        label: 'Padding',
        type: 'select',
        options: PADDING_OPTIONS_ENCRYPT_8B,
        defaultValue: 'None',
        helpTopic: 'padding',
      },
      ...ERROR_UNIFY_FIELDS,
    ],
    errorProfile: fixedErrorProfile(['INVALID_KEY_LENGTH', 'PLAINTEXT_NOT_BLOCK_ALIGNED']),
    execute: async ({ inputs, properties, log }) => {
      if (inputs.key.length !== 8) {
        throw new NodeError('INVALID_KEY_LENGTH', `Single DES requires an 8-byte key, got ${inputs.key.length}`);
      }
      log('Running Single DES Encrypt');
      const res = tdesEncrypt(
        inputs.plaintext,
        inputs.key,
        inputs.iv,
        properties.mode || 'ECB',
        properties.padding || 'None'
      );
      return res;
    },
  },

  // 6. Single DES Decrypt
  {
    type: 'symmetric-des-decrypt',
    label: 'DES Decrypt',
    category: 'symmetric',
    description: 'Single DES (56-bit effective, 8-byte key) Decryption',
    inputs: [
      { id: 'key', name: 'Key', spec: '8B', dataType: 'bytes', required: true, description: 'Single DES key (56-bit effective).' },
      { id: 'ciphertext', name: 'Ciphertext', dataType: 'bytes', required: true },
      { id: 'iv', name: 'IV', spec: '8B', dataType: 'bytes', required: false, showWhen: showIvPort, description: 'Initialization vector for CBC mode.' },
    ],
    outputs: [
      { id: 'plaintext', name: 'Plaintext', dataType: 'bytes' },
    ],
    propertySchema: [
      {
        id: 'mode',
        label: 'Cipher Mode',
        type: 'select',
        options: DES_MODE_OPTIONS,
        defaultValue: 'ECB',
        helpTopic: 'cipherMode',
      },
      {
        id: 'padding',
        label: 'Padding',
        type: 'select',
        options: PADDING_OPTIONS_DECRYPT_8B,
        defaultValue: 'None',
        helpTopic: 'padding',
      },
      ...ERROR_UNIFY_FIELDS,
    ],
    errorProfile: fixedErrorProfile(['INVALID_KEY_LENGTH', 'CIPHERTEXT_NOT_BLOCK_ALIGNED', 'INVALID_PADDING']),
    execute: async ({ inputs, properties, log }) => {
      if (inputs.key.length !== 8) {
        throw new NodeError('INVALID_KEY_LENGTH', `Single DES requires an 8-byte key, got ${inputs.key.length}`);
      }
      log('Running Single DES Decrypt');
      const plaintext = tdesDecrypt(
        inputs.ciphertext,
        inputs.key,
        inputs.iv,
        properties.mode || 'ECB',
        properties.padding || 'None'
      );
      return { plaintext };
    },
  },

  // 7-14. SEED, ARIA, Camellia, SM4 Encrypt/Decrypt (generated via makeBlockCipherAeadPair, see
  // BLOCK_CIPHER_AEAD_CONFIGS above -- they all share the {plaintext/ciphertext,key,iv,mode,padding,aad}
  // cipherFn shape, unlike AES (asymmetric encrypt/decrypt labels) and (T)DES (positional args, no AEAD).
  seedEncryptNode,
  seedDecryptNode,
  ariaEncryptNode,
  ariaDecryptNode,
  camelliaEncryptNode,
  camelliaDecryptNode,
  sm4EncryptNode,
  sm4DecryptNode,

  // 15. ChaCha20-Poly1305 AEAD Encrypt
  {
    type: 'symmetric-chacha20-poly1305-encrypt',
    label: 'ChaCha20-Poly1305 Encrypt',
    category: 'symmetric',
    description: 'RFC 8439 Authenticated Encryption with Additional Data (AEAD)',
    inputs: [
      { id: 'key', name: 'Key', spec: '32B', dataType: 'bytes', required: true, description: 'ChaCha20 256-bit symmetric key.' },
      { id: 'plaintext', name: 'Plaintext', dataType: 'bytes', required: true },
      { id: 'nonce', name: 'Nonce', spec: '12B', dataType: 'bytes', required: false, description: 'Defaults to 12 zero bytes if omitted.' },
      { id: 'aad', name: 'AAD', dataType: 'bytes', required: false, description: 'Additional Authenticated Data covered by the Poly1305 tag.' },
    ],
    outputs: [
      { id: 'ciphertext', name: 'Ciphertext', dataType: 'bytes' },
      { id: 'tag', name: 'Auth Tag', spec: '16B', dataType: 'bytes', description: 'Poly1305 authentication tag.' },
    ],
    propertySchema: [...ERROR_UNIFY_FIELDS],
    errorProfile: fixedErrorProfile(['INVALID_KEY_LENGTH', 'INVALID_NONCE_LENGTH']),
    execute: async ({ inputs, log }) => {
      log('Running ChaCha20-Poly1305 Encrypt');
      const res = chacha20Poly1305Encrypt({
        key: inputs.key,
        nonce: inputs.nonce,
        plaintext: inputs.plaintext,
        aad: inputs.aad,
      });
      return res;
    },
  },

  // 16. ChaCha20-Poly1305 AEAD Decrypt
  {
    type: 'symmetric-chacha20-poly1305-decrypt',
    label: 'ChaCha20-Poly1305 Decrypt',
    category: 'symmetric',
    description: 'RFC 8439 Authenticated Decryption with Additional Data (AEAD)',
    inputs: [
      { id: 'key', name: 'Key', spec: '32B', dataType: 'bytes', required: true, description: 'ChaCha20 256-bit symmetric key.' },
      { id: 'ciphertext', name: 'Ciphertext', dataType: 'bytes', required: true },
      { id: 'nonce', name: 'Nonce', spec: '12B', dataType: 'bytes', required: true, description: 'Nonce used during encryption.' },
      { id: 'tag', name: 'Auth Tag', spec: '16B', dataType: 'bytes', required: true, description: 'Poly1305 authentication tag to verify.' },
      { id: 'aad', name: 'AAD', dataType: 'bytes', required: false, description: 'Additional Authenticated Data covered by the Poly1305 tag.' },
    ],
    outputs: [
      { id: 'plaintext', name: 'Plaintext', dataType: 'bytes' },
    ],
    propertySchema: [...ERROR_UNIFY_FIELDS],
    errorProfile: fixedErrorProfile(['INVALID_KEY_LENGTH', 'INVALID_NONCE_LENGTH', 'INVALID_TAG_LENGTH', 'AUTH_TAG_MISMATCH']),
    execute: async ({ inputs, log }) => {
      log('Running ChaCha20-Poly1305 Decrypt');
      const plaintext = chacha20Poly1305Decrypt({
        key: inputs.key,
        nonce: inputs.nonce,
        ciphertext: inputs.ciphertext,
        tag: inputs.tag,
        aad: inputs.aad,
      });
      return { plaintext };
    },
  },

  // 17. Pure ChaCha20 Stream Cipher
  {
    type: 'symmetric-chacha20-stream',
    label: 'ChaCha20 Stream',
    category: 'symmetric',
    description: 'Pure ChaCha20 Stream Cipher without Poly1305 MAC (RFC 8439)',
    inputs: [
      { id: 'key', name: 'Key', spec: '32B', dataType: 'bytes', required: true, description: 'ChaCha20 256-bit symmetric key.' },
      { id: 'data', name: 'Data In', dataType: 'bytes', required: true },
      { id: 'nonce', name: 'Nonce', spec: '12B', dataType: 'bytes', required: false, description: 'Defaults to 12 zero bytes if omitted.' },
    ],
    outputs: [
      { id: 'data', name: 'Data Out', dataType: 'bytes' },
    ],
    propertySchema: [...ERROR_UNIFY_FIELDS],
    errorProfile: fixedErrorProfile(['INVALID_KEY_LENGTH', 'INVALID_NONCE_LENGTH']),
    execute: async ({ inputs, log }) => {
      log('Running ChaCha20 Stream Cipher');
      const res = chacha20StreamEncrypt({
        key: inputs.key,
        nonce: inputs.nonce,
        data: inputs.data,
      });
      return {
        data: res.ciphertext,
        nonce: res.nonce,
      };
    },
  },

  // 18a. Block Padding Node (ND-6.1a) -- Pad direction only. Split from the former combined
  // Block Padding/Unpadding node because the two directions support different algorithm sets:
  // ISO/IEC 9797-1 Method 1 (Zero Padding) and NIST SP 800-38B cannot be reliably unpadded
  // (see padding.ts and issues/tasks/TASK_029), so a single node with a Pad/Unpad toggle could
  // offer a combination that doesn't actually work.
  {
    type: 'padding-block-pad',
    label: 'Block Padding',
    category: 'utility',
    description: 'Applies cryptographic block padding (PKCS#7, ANSI X9.23, ISO/IEC 9797-1 Method 1/2/3, NIST SP 800-38B, None)',
    inputs: [
      { id: 'data', name: 'Data', dataType: 'bytes', required: true },
    ],
    outputs: [
      { id: 'result', name: 'Padded Data', dataType: 'bytes' },
    ],
    propertySchema: [
      {
        id: 'paddingType',
        label: 'Padding Standard',
        type: 'select',
        options: PADDING_OPTIONS_ENCRYPT_16B,
        defaultValue: 'None',
        helpTopic: 'padding',
      },
      {
        id: 'blockSize',
        label: 'Block Size (Bytes)',
        type: 'select',
        options: [
          { label: '8 Bytes (64 bits - DES/3DES)', value: 8 },
          { label: '16 Bytes (128 bits - AES/SEED/ARIA/Camellia/SM4)', value: 16 },
          { label: '32 Bytes (256 bits)', value: 32 },
        ],
        defaultValue: 16,
      },
      ...ERROR_UNIFY_FIELDS,
    ],
    errorProfile: fixedErrorProfile(['PLAINTEXT_NOT_BLOCK_ALIGNED']),
    execute: async ({ inputs, properties, log }) => {
      const padType = (properties.paddingType || 'None') as BlockPaddingType;
      const blkSize = Number(properties.blockSize) || 16;
      log(`Running Block Padding (${padType}, blockSize=${blkSize})`);
      return { result: applyBlockPadding(inputs.data, padType, blkSize) };
    },
  },

  // 18b. Block Unpadding Node (ND-6.1b) -- Unpad direction only, see 18a for why it's separate.
  {
    type: 'padding-block-unpad',
    label: 'Block Unpadding',
    category: 'utility',
    description: 'Removes cryptographic block padding (PKCS#7, ANSI X9.23, ISO/IEC 9797-1 Method 2/3, None)',
    inputs: [
      { id: 'data', name: 'Padded Data', dataType: 'bytes', required: true },
    ],
    outputs: [
      { id: 'result', name: 'Data', dataType: 'bytes' },
    ],
    propertySchema: [
      {
        id: 'paddingType',
        label: 'Padding Standard',
        type: 'select',
        options: PADDING_OPTIONS_DECRYPT_16B,
        defaultValue: 'None',
        helpTopic: 'padding',
      },
      {
        id: 'blockSize',
        label: 'Block Size (Bytes)',
        type: 'select',
        options: [
          { label: '8 Bytes (64 bits - DES/3DES)', value: 8 },
          { label: '16 Bytes (128 bits - AES/SEED/ARIA/Camellia/SM4)', value: 16 },
          { label: '32 Bytes (256 bits)', value: 32 },
        ],
        defaultValue: 16,
      },
      ...ERROR_UNIFY_FIELDS,
    ],
    errorProfile: fixedErrorProfile(['INVALID_PADDING']),
    execute: async ({ inputs, properties, log }) => {
      const padType = (properties.paddingType || 'None') as BlockPaddingType;
      const blkSize = Number(properties.blockSize) || 16;
      log(`Running Block Unpadding (${padType}, blockSize=${blkSize})`);
      return { result: removeBlockPadding(inputs.data, padType, blkSize) };
    },
  },

  // 19. Asymmetric Padding Node (ND-6.2)
  {
    type: 'padding-asymmetric',
    label: 'Asymmetric Padding',
    category: 'utility',
    description: 'RSA OAEP (Encoding/Decoding) and RSA PSS (Encoding) padding schemes (PKCS#1 v2.2 / RFC 8017)',
    inputs: [
      { id: 'message', name: 'Message', dataType: 'bytes', required: true, description: 'Message to encode with RSA-OAEP.', showWhen: (p) => (p.scheme || 'OAEP-Encode') === 'OAEP-Encode' },
      { id: 'em', name: 'Encoded Message', spec: 'EM', dataType: 'bytes', required: true, description: 'Encoded message (EM) to unpad with RSA-OAEP.', showWhen: (p) => p.scheme === 'OAEP-Decode' },
      { id: 'mHash', name: 'Message Hash', spec: '32B', dataType: 'bytes', required: true, description: 'SHA-256 hash of the message to encode with RSA-PSS.', showWhen: (p) => p.scheme === 'PSS-Encode' },
      { id: 'label', name: 'OAEP Label', dataType: 'bytes', required: false, description: 'Optional OAEP label parameter (rarely used, defaults to empty).', showWhen: (p) => (p.scheme || 'OAEP-Encode') !== 'PSS-Encode' },
      { id: 'salt', name: 'PSS Salt', dataType: 'bytes', required: false, description: 'Optional PSS salt; if omitted, a random salt of Salt Length bytes is generated.', showWhen: (p) => p.scheme === 'PSS-Encode' },
    ],
    outputs: [
      { id: 'result', name: 'Result', dataType: 'bytes' },
    ],
    propertySchema: [
      {
        id: 'scheme',
        label: 'Scheme',
        type: 'select',
        options: [
          { label: 'RSA-OAEP Encode (Encryption Padding)', value: 'OAEP-Encode' },
          { label: 'RSA-OAEP Decode (Decryption Unpadding)', value: 'OAEP-Decode' },
          { label: 'RSA-PSS Encode (Signature Padding)', value: 'PSS-Encode' },
        ],
        defaultValue: 'OAEP-Encode',
      },
      {
        id: 'targetLength',
        label: 'Modulus / Target Length (Bytes)',
        type: 'select',
        options: [
          { label: '128 Bytes (1024-bit RSA)', value: 128 },
          { label: '256 Bytes (2048-bit RSA)', value: 256 },
          { label: '384 Bytes (3072-bit RSA)', value: 384 },
          { label: '512 Bytes (4096-bit RSA)', value: 512 },
        ],
        defaultValue: 256,
      },
      {
        id: 'saltLength',
        label: 'PSS Salt Length (Bytes)',
        type: 'number',
        defaultValue: 32,
        showWhen: (p) => p.scheme === 'PSS-Encode',
      },
      ...ERROR_UNIFY_FIELDS,
    ],
    errorProfile: fixedErrorProfile(['OAEP_MESSAGE_TOO_LONG', 'INVALID_OAEP_PADDING', 'INVALID_PSS_PARAMS']),
    execute: async ({ inputs, properties, log }) => {
      const scheme = properties.scheme || 'OAEP-Encode';
      const targetLength = Number(properties.targetLength) || 256;
      const saltLength = Number(properties.saltLength) || 32;
      log(`Running Asymmetric Padding [${scheme}]`);

      let result: Uint8Array;
      if (scheme === 'OAEP-Encode') {
        result = rsaOaepEncode(inputs.message, targetLength, inputs.label);
      } else if (scheme === 'OAEP-Decode') {
        result = rsaOaepDecode(inputs.em, inputs.label);
      } else if (scheme === 'PSS-Encode') {
        result = rsaPssEncode(inputs.mHash, targetLength * 8, saltLength, inputs.salt);
      } else {
        throw new NodeError('UNSUPPORTED_MODE', `Unsupported asymmetric padding scheme: ${scheme}`);
      }

      return { result };
    },
  },
];
