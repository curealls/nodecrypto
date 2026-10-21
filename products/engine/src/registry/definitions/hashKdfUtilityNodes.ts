/**
 * Hash, MAC, KDF, and Utility Node Definitions
 */

import { NodeDefinition, PropertyFieldDefinition } from '../../dag/types';
import { NodeError } from '../../dag/errors';
import { tmsg } from '../../messages';
import { computeHash, HashAlgorithm } from '../../crypto/hash_kdf/hash';
import { computeHmac, computeCmac, HmacHash } from '../../crypto/hash_kdf/mac';
import { computePbkdf2, computeHkdf } from '../../crypto/hash_kdf/kdf';
import { computeCrc, CRC_PRESETS } from '../../crypto/crc/crc';
import * as B from '../../crypto/utils/bytesOps';
import { minIntBytes } from './converterNodes';
import { utf8ToBytes } from '../../crypto/utils/encoding';
import { fixedErrorProfile } from '../errorProfile';

// errorProfile: judgement (T05, execution-semantics.md §3.2). Same shape as
// the verify-node fields in asymmetricPqcNodes.ts: pick a value to treat as an error, and
// code/message for the reinterpreted ERROR state (blank falls back to runner.ts's default).
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

// errorProfile: fixed (T06, execution-semantics.md §3.1). Shared code/message
// catalog for this file's built-in failures: CMAC reuses the underlying cipher's key-length check
// (aesEncrypt/tdesEncrypt already throw NodeError, see symmetricNodes.ts), PBKDF2/HKDF reject
// out-of-range Iterations/Key Length (kdf.ts), and the CRC node rejects malformed custom
// polynomial/init/xorOut hex parameters.
const NONE_PROFILE = { kind: 'none' as const };

/** Concatenator input -> bytes (node-catalog.md ND-2.14): int becomes the minimal unsigned big-endian bytes. */
function concatPartToBytes(v: unknown): Uint8Array {
  if (v instanceof Uint8Array) return v;
  if (typeof v === 'string') return utf8ToBytes(v);
  if (typeof v === 'boolean') return new Uint8Array([v ? 1 : 0]);
  if (typeof v === 'number' || typeof v === 'bigint') {
    if (typeof v === 'number' && !Number.isInteger(v)) throw new NodeError('BYTES_INVALID_ARGUMENT', tmsg('errors:bytes.concatNonInteger', { value: v }));
    const n = BigInt(v);
    return B.fromInt(n, minIntBytes(n), 'big', false);
  }
  throw new NodeError('BYTES_INVALID_ARGUMENT', tmsg('errors:bytes.concatType'));
}

const COMPARE_OPERATORS = ['==', '!=', '>', '>=', '<', '<='];

/** Comparator operand kind (node-catalog.md ND-2.16): string compares as UTF-8 bytes, number and bigint are both int. */
function compareKind(v: unknown): 'bytes' | 'string' | 'int' | 'bool' {
  if (v instanceof Uint8Array) return 'bytes';
  if (typeof v === 'string') return 'string';
  if (typeof v === 'bigint' || (typeof v === 'number' && Number.isInteger(v))) return 'int';
  if (typeof v === 'boolean') return 'bool';
  throw new NodeError('BYTES_INVALID_ARGUMENT', tmsg('errors:bytes.compareType'));
}
const compareToBytes = (v: unknown) => (typeof v === 'string' ? utf8ToBytes(v) : (v as Uint8Array));
/** cmp is -1/0/1 for a<b, a==b, a>b; boolean operands reach BigInt() as 0/1 below. */
const orderHolds = (op: string, cmp: number) =>
  op === '==' ? cmp === 0 : op === '!=' ? cmp !== 0 : op === '>' ? cmp > 0 : op === '>=' ? cmp >= 0 : op === '<' ? cmp < 0 : cmp <= 0;

// Logic ops for the Bitwise Logic node, folded across all input buffers (bytes-ops.md §3.3)
const LOGIC_OPS: Record<string, (a: Uint8Array, b: Uint8Array) => Uint8Array> = { XOR: B.xor, AND: B.and, OR: B.or };

// Shift/rotate ops for the Bit Shift & Rotate node (whole byte array as one bit string, bytes-ops.md §3.3)
const SHIFT_OPS: Record<string, (b: Uint8Array, n: number) => Uint8Array> = { SHL: B.shl, SHR: B.shr, ROL: B.rol, ROR: B.ror };

export const hashKdfUtilityNodes: NodeDefinition[] = [
  // 1. Hash Digest
  {
    type: 'hash-digest',
    label: 'Cryptographic Hash',
    category: 'hash',
    description: 'Computes cryptographic hash (SHA-2, SHA-3, BLAKE3)',
    inputs: [
      { id: 'data', name: 'Data', dataType: 'bytes', required: true },
    ],
    outputs: [
      { id: 'digest', name: 'Digest', dataType: 'bytes' },
    ],
    propertySchema: [
      {
        id: 'algorithm',
        label: 'Hash Algorithm',
        type: 'select',
        options: [
          { label: 'SHA-256 (NIST FIPS 180-4)', value: 'SHA-256' },
          { label: 'SHA-512', value: 'SHA-512' },
          { label: 'SHA-224', value: 'SHA-224' },
          { label: 'SHA-384', value: 'SHA-384' },
          { label: 'SHA-512/224 (NIST FIPS 180-4)', value: 'SHA-512/224' },
          { label: 'SHA-512/256 (NIST FIPS 180-4)', value: 'SHA-512/256' },
          { label: 'SHA3-224 (NIST FIPS 202)', value: 'SHA3-224' },
          { label: 'SHA3-256 (NIST FIPS 202)', value: 'SHA3-256' },
          { label: 'SHA3-384 (NIST FIPS 202)', value: 'SHA3-384' },
          { label: 'SHA3-512 (NIST FIPS 202)', value: 'SHA3-512' },
          { label: 'Keccak-256 (Ethereum)', value: 'Keccak-256' },
          { label: 'Keccak-512', value: 'Keccak-512' },
          { label: 'SHAKE128 (XOF)', value: 'SHAKE128' },
          { label: 'SHAKE256 (XOF)', value: 'SHAKE256' },
          { label: 'BLAKE2b (64-bit platforms)', value: 'BLAKE2b' },
          { label: 'BLAKE2s (32-bit platforms)', value: 'BLAKE2s' },
          { label: 'BLAKE3 (Ultra-fast parallel)', value: 'BLAKE3' },
          { label: 'RIPEMD-160 (Bitcoin / Legacy)', value: 'RIPEMD-160' },
          { label: 'MD5 (Legacy RFC 1321)', value: 'MD5' },
          { label: 'SHA-1 (Legacy RFC 3174)', value: 'SHA-1' },
        ],
        defaultValue: 'SHA-256',
      },
    ],
    errorProfile: NONE_PROFILE,
    execute: async ({ inputs, properties, log }) => {
      const algorithm = (properties.algorithm || 'SHA-256') as HashAlgorithm;
      log(`Computing ${algorithm} digest`);
      const digest = computeHash(inputs.data, algorithm);
      return {
        digest,
      };
    },
  },

  // 2. HMAC
  {
    type: 'mac-hmac',
    label: 'HMAC Generator',
    category: 'hash',
    description: 'Hash-based Message Authentication Code (RFC 2104)',
    inputs: [
      { id: 'key', name: 'Secret Key', dataType: 'bytes', required: true },
      { id: 'data', name: 'Message', dataType: 'bytes', required: true },
    ],
    outputs: [
      { id: 'mac', name: 'MAC Digest', dataType: 'bytes' },
    ],
    propertySchema: [
      {
        id: 'algorithm',
        label: 'Hash Algorithm',
        type: 'select',
        options: [
          { label: 'SHA-256', value: 'SHA-256' },
          { label: 'SHA-512', value: 'SHA-512' },
          { label: 'SHA3-256', value: 'SHA3-256' },
        ],
        defaultValue: 'SHA-256',
      },
    ],
    errorProfile: NONE_PROFILE,
    execute: async ({ inputs, properties, log }) => {
      const algorithm = (properties.algorithm || 'SHA-256') as HmacHash;
      log(`Computing HMAC-${algorithm}`);
      const mac = computeHmac(inputs.key, inputs.data, algorithm);
      return {
        mac,
      };
    },
  },

  // 3. CMAC (Cipher-based MAC)
  {
    type: 'mac-cmac',
    label: 'CMAC Generator',
    category: 'hash',
    description: 'NIST SP 800-38B Cipher-based MAC (AES-128/256 or 3DES)',
    inputs: [
      { id: 'key', name: 'Cipher Key', dataType: 'bytes', required: true },
      { id: 'data', name: 'Message', dataType: 'bytes', required: true },
    ],
    outputs: [
      { id: 'mac', name: 'CMAC Tag', dataType: 'bytes' },
    ],
    propertySchema: [
      {
        id: 'cipher',
        label: 'Underlying Cipher',
        type: 'select',
        options: [
          { label: 'AES-128 / AES-256', value: 'AES' },
          { label: 'Triple DES (3DES)', value: '3DES' },
        ],
        defaultValue: 'AES',
      },
    ],
    errorProfile: fixedErrorProfile(['INVALID_KEY_LENGTH']),
    execute: async ({ inputs, properties, log }) => {
      const cipher = (properties.cipher || 'AES') as 'AES' | '3DES';
      log(`Computing CMAC (${cipher})`);
      const mac = computeCmac(inputs.key, inputs.data, cipher);
      return {
        mac,
      };
    },
  },

  // 4. CRC Generator
  {
    type: 'utility-crc',
    label: 'CRC Generator',
    category: 'hash',
    description: 'Universal Parametric Cyclic Redundancy Check (Rocksoft Model: 8, 16, 32, 64-bit)',
    inputs: [
      { id: 'data', name: 'Data', dataType: 'bytes', required: true },
    ],
    outputs: [
      { id: 'checksum', name: 'Checksum', dataType: 'int', description: 'Computed CRC checksum value.' },
    ],
    propertySchema: [
      {
        id: 'preset',
        label: 'CRC Algorithm Preset',
        type: 'select',
        options: [
          { label: 'CRC-32 / ISO-HDLC (Ethernet/PNG/ZIP)', value: 'CRC-32/ISO-HDLC' },
          { label: 'CRC-32C / Castagnoli (iSCSI/Ext4)', value: 'CRC-32/CASTAGNOLI' },
          { label: 'CRC-16 / MODBUS (Industrial)', value: 'CRC-16/MODBUS' },
          { label: 'CRC-16 / CCITT-FALSE', value: 'CRC-16/CCITT-FALSE' },
          { label: 'CRC-16 / XMODEM', value: 'CRC-16/XMODEM' },
          { label: 'CRC-16 / USB', value: 'CRC-16/USB' },
          { label: 'CRC-16 / ISO 14443-A (MIFARE/NFC)', value: 'CRC-16/ISO-14443-A' },
          { label: 'CRC-8 / SMBUS', value: 'CRC-8/SMBUS' },
          { label: 'CRC-8 / MAXIM (Dallas/1-Wire)', value: 'CRC-8/MAXIM' },
          { label: 'CRC-64 / ECMA-182', value: 'CRC-64/ECMA' },
          { label: 'CRC-64 / XZ (GO-ISO)', value: 'CRC-64/XZ' },
          { label: 'Custom (Rocksoft Model Parameters)', value: 'custom' },
        ],
        defaultValue: 'CRC-32/ISO-HDLC',
      },
      {
        id: 'customWidth',
        label: 'Custom Width (Bits)',
        type: 'select',
        options: [
          { label: '8-bit', value: 8 },
          { label: '16-bit', value: 16 },
          { label: '32-bit', value: 32 },
          { label: '64-bit', value: 64 },
        ],
        defaultValue: 32,
      },
      {
        id: 'customPoly',
        label: 'Custom Polynomial (Hex)',
        type: 'hex',
        defaultValue: '04C11DB7',
        description: 'Polynomial as a hex value (e.g. 04C11DB7)',
      },
      {
        id: 'customInit',
        label: 'Custom Initial Value (Hex)',
        type: 'hex',
        defaultValue: 'FFFFFFFF',
        description: 'Initial value as a hex value (e.g. FFFFFFFF)',
      },
      {
        id: 'customRefIn',
        label: 'Reflect In (refIn)',
        type: 'boolean',
        defaultValue: true,
      },
      {
        id: 'customRefOut',
        label: 'Reflect Out (refOut)',
        type: 'boolean',
        defaultValue: true,
      },
      {
        id: 'customXorOut',
        label: 'Custom XOR Out (Hex)',
        type: 'hex',
        defaultValue: 'FFFFFFFF',
        description: 'Final XOR value as a hex value (e.g. FFFFFFFF)',
      },
    ],
    errorProfile: fixedErrorProfile(['INVALID_CRC_PARAMETER']),
    execute: async ({ inputs, properties, log }) => {
      const presetKey = properties.preset || 'CRC-32/ISO-HDLC';
      let model: any;
      if (presetKey === 'custom') {
        const width = Number(properties.customWidth) || 32;
        let poly: bigint, init: bigint, xorOut: bigint;
        try {
          poly = BigInt('0x' + (properties.customPoly || '04C11DB7').replace(/^0x/i, ''));
          init = BigInt('0x' + (properties.customInit || 'FFFFFFFF').replace(/^0x/i, ''));
          xorOut = BigInt('0x' + (properties.customXorOut || 'FFFFFFFF').replace(/^0x/i, ''));
        } catch (err) {
          throw new NodeError('INVALID_CRC_PARAMETER', tmsg('errors:crypto.crcCustom', { detail: err instanceof Error ? err.message : String(err) }));
        }
        const refIn = properties.customRefIn !== false;
        const refOut = properties.customRefOut !== false;
        model = { name: 'Custom Rocksoft Model', width, poly, init, refIn, refOut, xorOut };
      } else {
        model = CRC_PRESETS[presetKey] || CRC_PRESETS['CRC-32/ISO-HDLC'];
      }
      log(`Calculating CRC with '${model.name || presetKey}' (width=${model.width})`);

      const { crcBigInt } = computeCrc(inputs.data, model);

      return {
        checksum: Number(crcBigInt),
      };
    },
  },

  // 5. PBKDF2 Key Derivation
  {
    type: 'kdf-pbkdf2',
    label: 'PBKDF2 Key Derivation',
    category: 'kdf',
    description: 'Password-Based Key Derivation Function 2 (RFC 8018)',
    inputs: [
      { id: 'password', name: 'Password', dataType: 'bytes', required: true },
      { id: 'salt', name: 'Salt', dataType: 'bytes', required: false, description: 'Optional salt; if omitted, defaults to 16 zero bytes (supply a random salt for real use).' },
    ],
    outputs: [
      { id: 'derivedKey', name: 'Derived Key', dataType: 'bytes' },
    ],
    propertySchema: [
      {
        id: 'iterations',
        label: 'Iterations',
        type: 'number',
        defaultValue: 10000,
      },
      {
        id: 'keyLength',
        label: 'Output Key Length (bytes)',
        type: 'number',
        defaultValue: 32,
      },
      {
        id: 'hashAlgorithm',
        label: 'PR Hash Function',
        type: 'select',
        options: [
          { label: 'SHA-256', value: 'SHA-256' },
          { label: 'SHA-512', value: 'SHA-512' },
        ],
        defaultValue: 'SHA-256',
      },
    ],
    errorProfile: fixedErrorProfile(['INVALID_KDF_PARAMS']),
    execute: async ({ inputs, properties, log }) => {
      const iterations = Number(properties.iterations) || 10000;
      const keyLength = Number(properties.keyLength) || 32;
      const hash = (properties.hashAlgorithm || 'SHA-256') as 'SHA-256' | 'SHA-512';
      const salt = inputs.salt || new Uint8Array(16);

      log(`Deriving ${keyLength}-byte key with PBKDF2 (${iterations} iterations)`);
      const derivedKey = computePbkdf2({
        password: inputs.password,
        salt,
        iterations,
        keyLength,
        hash,
      });

      return {
        derivedKey,
      };
    },
  },

  // 5. HKDF Key Derivation
  {
    type: 'kdf-hkdf',
    label: 'HKDF Key Derivation',
    category: 'kdf',
    description: 'HMAC-based Extract-and-Expand Key Derivation (RFC 5869)',
    inputs: [
      { id: 'ikm', name: 'Input Keying Material', dataType: 'bytes', required: true },
      { id: 'salt', name: 'Salt', dataType: 'bytes', required: false },
      { id: 'info', name: 'Context Info', dataType: 'bytes', required: false },
    ],
    outputs: [
      { id: 'okm', name: 'Output Key', spec: 'OKM', dataType: 'bytes', description: 'Output Keying Material derived via HKDF-Expand.' },
    ],
    propertySchema: [
      {
        id: 'keyLength',
        label: 'Output Length (bytes)',
        type: 'number',
        defaultValue: 32,
      },
      {
        id: 'hashAlgorithm',
        label: 'Hash Algorithm',
        type: 'select',
        options: [
          { label: 'SHA-256', value: 'SHA-256' },
          { label: 'SHA-512', value: 'SHA-512' },
        ],
        defaultValue: 'SHA-256',
      },
    ],
    errorProfile: fixedErrorProfile(['INVALID_KDF_PARAMS']),
    execute: async ({ inputs, properties, log }) => {
      const keyLength = Number(properties.keyLength) || 32;
      const hash = (properties.hashAlgorithm || 'SHA-256') as 'SHA-256' | 'SHA-512';
      log(`Deriving ${keyLength}-byte key with HKDF-${hash}`);

      const okm = computeHkdf({
        ikm: inputs.ikm,
        salt: inputs.salt,
        info: inputs.info,
        keyLength,
        hash,
      });

      return {
        okm,
      };
    },
  },

  // 7. Byte Concatenator (Dynamic N-ary inputs; starts with no ports, node-catalog.md ND-2.14)
  {
    type: 'utility-concat',
    label: 'Byte Concatenator',
    category: 'utility',
    description: 'Concatenates bytes, string, int and bool inputs in input port order (A || B || C ...)',
    dynamicInputs: {
      min: 0,
      defaultNamePrefix: 'Value',
      defaultDataType: 'bytes',
    },
    inputs: [],
    outputs: [
      { id: 'combined', name: 'Combined', spec: 'A‖B‖...', dataType: 'bytes', description: 'Concatenation of all connected input buffers in port order.' },
      { id: 'length', name: 'Total Length', dataType: 'int' },
    ],
    propertySchema: [],
    errorProfile: fixedErrorProfile(['BYTES_INVALID_ARGUMENT', 'BYTES_INT_OVERFLOW', 'BYTES_SIZE_LIMIT']),
    execute: async ({ inputs, log }) => {
      // The runner hands inputs over in port order; every value becomes bytes first.
      const parts = Object.values(inputs).map(concatPartToBytes);
      const combined = B.concat(parts);
      log(`Concatenating ${parts.length} values (total ${combined.length} bytes)`);
      return { combined, length: combined.length };
    },
  },

  // 8. Bitwise Logic (Dynamic N-ary inputs for XOR/AND/OR)
  {
    type: 'utility-bitwise',
    label: 'Bitwise Logic',
    category: 'utility',
    description: 'Performs bitwise logic (XOR, AND, OR) across byte arrays of equal length',
    dynamicInputs: {
      min: 2,
      defaultNamePrefix: 'In',
      defaultDataType: 'bytes',
    },
    inputs: [
      { id: 'in_1', name: 'Input A', dataType: 'bytes', required: true },
      { id: 'in_2', name: 'Input B', dataType: 'bytes', required: true },
    ],
    outputs: [
      { id: 'result', name: 'Result', dataType: 'bytes' },
    ],
    propertySchema: [
      {
        id: 'operation',
        label: 'Operation',
        type: 'select',
        options: [
          { label: 'XOR (Exclusive OR, ⊕)', value: 'XOR' },
          { label: 'AND (Logical AND, ∧)', value: 'AND' },
          { label: 'OR (Logical OR, ∨)', value: 'OR' },
        ],
        defaultValue: 'XOR',
      },
    ],
    errorProfile: fixedErrorProfile(['BYTES_LENGTH_MISMATCH']),
    execute: async ({ inputs, properties }) => {
      // Saved workflows may carry removed operations (NAND, SHL, ...): treat them as XOR (D-04)
      const fn = LOGIC_OPS[properties.operation] ?? B.xor;

      const buffers: Uint8Array[] = [];
      for (const val of Object.values(inputs)) {
        if (val instanceof Uint8Array) {
          buffers.push(val);
        } else if (typeof val === 'string') {
          buffers.push(new TextEncoder().encode(val));
        }
      }

      if (buffers.length === 0) return { result: new Uint8Array(0) };
      return { result: buffers.reduce(fn) };
    },
  },

  // 8b. Bit Shift & Rotate (single input, bit count as a property)
  {
    type: 'utility-bitshift',
    label: 'Bit Shift & Rotate',
    category: 'utility',
    description: 'Shifts or rotates a byte array by a number of bits (SHL, SHR, ROL, ROR)',
    inputs: [
      { id: 'data', name: 'Value', dataType: 'bytes', required: true },
    ],
    outputs: [
      { id: 'result', name: 'Result', dataType: 'bytes' },
    ],
    propertySchema: [
      {
        id: 'operation',
        label: 'Operation',
        type: 'select',
        options: [
          { label: 'SHL (Bit Shift Left <<)', value: 'SHL' },
          { label: 'SHR (Bit Shift Right >>)', value: 'SHR' },
          { label: 'ROL (Bit Rotate Left)', value: 'ROL' },
          { label: 'ROR (Bit Rotate Right)', value: 'ROR' },
        ],
        defaultValue: 'SHL',
      },
      {
        id: 'bits',
        label: 'Bits',
        type: 'number',
        defaultValue: 1,
        description: 'Number of bits to shift or rotate (an integer of 0 or more)',
      },
    ],
    errorProfile: fixedErrorProfile(['BYTES_INVALID_ARGUMENT']),
    execute: async ({ inputs, properties }) => {
      const fn = SHIFT_OPS[properties.operation];
      if (!fn) throw new NodeError('BYTES_INVALID_ARGUMENT', tmsg('errors:bytes.unknownOperation', { value: properties.operation }));
      // bytesOps rejects non-integer / negative / unsafe bit counts with BYTES_INVALID_ARGUMENT
      return { result: fn(inputs.data, Number(properties.bits)) };
    },
  },

  // 9. Bit Inversion (NOT) - Compact Small Size
  {
    type: 'utility-bitwise-not',
    label: 'Bit Inversion (NOT)',
    category: 'utility',
    description: "Inverts all bits (One's Complement, ~) of the input bytes",
    inputs: [
      { id: 'data', name: 'Data', dataType: 'bytes', required: true },
    ],
    outputs: [
      { id: 'inverted', name: 'Inverted', dataType: 'bytes' },
    ],
    propertySchema: [],
    errorProfile: NONE_PROFILE,
    execute: async ({ inputs }) => ({ inverted: B.not(inputs.data) }),
  },

  // 9b. Endian Converter (reverses byte order; big<->little is the same operation)
  {
    type: 'utility-endian',
    label: 'Endian Converter',
    category: 'utility',
    description: 'Reverses the byte order of the input (big-endian <-> little-endian)',
    inputs: [
      { id: 'data', name: 'Value', dataType: 'bytes', required: true },
    ],
    outputs: [
      { id: 'result', name: 'Result', dataType: 'bytes' },
    ],
    propertySchema: [],
    errorProfile: NONE_PROFILE,
    execute: async ({ inputs }) => ({ result: B.reverse(inputs.data) }),
  },

  // 11. Byte Slicer
  {
    type: 'utility-slicer',
    label: 'Byte Slicer',
    category: 'utility',
    description: 'Extracts bytes like the script slice b[offset, length]: empty length = to the end, negative = end position counted from the back (excluded)',
    inputs: [
      { id: 'data', name: 'Data', dataType: 'bytes', required: true },
    ],
    outputs: [
      { id: 'sliced', name: 'Sliced Bytes', dataType: 'bytes' },
    ],
    propertySchema: [
      {
        id: 'offset',
        label: 'Offset (Start)',
        type: 'number',
        defaultValue: 0,
        description: 'Start position. A negative value counts from the end.',
      },
      {
        id: 'length',
        label: 'Length',
        type: 'text',
        defaultValue: '',
        description: 'Empty = to the end; 0 or more = length; negative = end position counted from the back (excluded; -1 stops before the last byte)',
      },
    ],
    errorProfile: fixedErrorProfile(['BYTES_OUT_OF_RANGE', 'BYTES_INVALID_ARGUMENT']),
    execute: async ({ inputs, properties, log }) => {
      // Same interval rule as the script's b[offset, length] (builtin-script.md §4.7)
      const data = inputs.data as Uint8Array;
      const offset = Number(properties.offset ?? 0);
      const lengthText = String(properties.length ?? '').trim();
      if (lengthText !== '' && !/^-?\d+$/.test(lengthText)) {
        throw new NodeError('BYTES_INVALID_ARGUMENT', tmsg('errors:bytes.lengthIntOrEmpty', { value: lengthText }));
      }
      if (!Number.isSafeInteger(offset)) throw new NodeError('BYTES_INVALID_ARGUMENT', tmsg('errors:bytes.offsetInteger', { value: properties.offset }));
      const length = lengthText === '' ? undefined : Number(lengthText);
      if (length !== undefined && !Number.isSafeInteger(length)) throw new NodeError('BYTES_INVALID_ARGUMENT', tmsg('errors:bytes.lengthTooLarge', { value: lengthText }));

      const start = offset < 0 ? data.length + offset : offset;
      const end = length === undefined ? data.length : length >= 0 ? start + length : data.length + length;
      if (start < 0 || start > end || end > data.length) {
        throw new NodeError('BYTES_OUT_OF_RANGE', tmsg('errors:bytes.rangeOutside', { start, end, length: data.length }));
      }
      const sliced = B.slice(data, start, end - start);
      log(`Sliced [${start}..${end}) (${sliced.length} bytes)`);
      return { sliced };
    },
  },

  // 12. Value Comparator (ND-2.16): same-type strict comparison, one bool output
  {
    type: 'utility-compare',
    label: 'Value Comparator',
    category: 'utility',
    description: 'Compares two values of the same type (bytes, string, int, bool) with ==, !=, >, >=, <, <=',
    inputs: [
      { id: 'a', name: 'Value A', dataType: 'any', required: true, description: 'First operand to compare' },
      { id: 'b', name: 'Value B', dataType: 'any', required: true, description: 'Second operand to compare' },
    ],
    outputs: [
      { id: 'result', name: 'Result', dataType: 'bool', description: 'True if the comparison holds' },
    ],
    propertySchema: [
      {
        id: 'operator',
        label: 'Comparison Operator',
        type: 'select',
        options: COMPARE_OPERATORS.map((o) => ({ label: o, value: o })),
        defaultValue: '==',
      },
      ...JUDGEMENT_ERROR_FIELDS,
    ],
    errorProfile: { kind: 'judgement', port: 'result' },
    validate: ({ inputTypes: t }) =>
      t.a && t.b && t.a !== t.b ? tmsg('errors:design.typesDiffer', { a: t.a, b: t.b }) : null,
    execute: async ({ inputs, properties, log }) => {
      const op = properties.operator || '==';
      if (!COMPARE_OPERATORS.includes(op)) throw new NodeError('BYTES_INVALID_ARGUMENT', tmsg('errors:bytes.unknownOperator', { value: op }));
      const [ta, tb] = [compareKind(inputs.a), compareKind(inputs.b)];
      if (ta !== tb) throw new NodeError('BYTES_INVALID_ARGUMENT', tmsg('errors:bytes.operandTypesDiffer', { a: ta, b: tb }));

      let result: boolean;
      if (ta === 'bytes' || ta === 'string') {
        // bytes and UTF-8 string: ==/!= via ctEquals (best effort, JavaScript cannot guarantee constant time), ordering via compare
        const [x, y] = [compareToBytes(inputs.a), compareToBytes(inputs.b)];
        result = op === '==' || op === '!=' ? B.ctEquals(x, y) === (op === '==') : orderHolds(op, B.compare(x, y));
      } else {
        // int (number | bigint mixed) and bool (false=0, true=1)
        const [x, y] = [BigInt(inputs.a), BigInt(inputs.b)];
        result = orderHolds(op, x < y ? -1 : x > y ? 1 : 0);
      }
      log(`Compare: A ${op} B => ${result}`);
      return { result };
    },
  },

  // 13. Byte Length (ND-2.20): byte count of the input after the Concatenator's conversion to bytes
  {
    type: 'utility-byte-length',
    label: 'Byte Length',
    category: 'utility',
    description: 'Converts the input to bytes (string = UTF-8, int = minimal length, bool = 1 byte) and returns the byte count',
    inputs: [
      { id: 'in', name: 'Value', dataType: 'any', required: true },
    ],
    outputs: [
      { id: 'length', name: 'Length', dataType: 'int' },
    ],
    propertySchema: [],
    errorProfile: fixedErrorProfile(['BYTES_INVALID_ARGUMENT', 'BYTES_INT_OVERFLOW']),
    execute: async ({ inputs }) => ({ length: B.length(concatPartToBytes(inputs.in)) }),
  },
];
