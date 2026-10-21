/**
 * Converter Node Definitions - Micro Encoding & Format Converters
 * [PRD Section 4.2] Data Conversion & Encoding Node Group
 */

import { NodeDefinition } from '../../dag/types';
import { NodeError } from '../../dag/errors';
import { tmsg } from '../../messages';
import * as B from '../../crypto/utils/bytesOps';
import { fixedErrorProfile } from '../errorProfile';
import {
  bytesToHex,
  hexToBytes,
  bytesToBase64,
  base64ToBytes,
  bytesToBase58,
  base58ToBytes,
  bytesToString,
  stringToBytes,
  bytesToMultibase,
  multibaseToBytes,
  MultibaseType,
} from '../../crypto/utils/encoding';

// errorProfile: fixed (T06, execution-semantics.md §3.1). Decode-direction
// nodes reject malformed input text (encoding.ts); encode-direction nodes take arbitrary bytes
// and can't fail, so they get `none` instead.
const NONE_PROFILE = { kind: 'none' as const };

/** Minimal unsigned byte length that holds n (value 0 takes 1 byte); shared by Int to Bytes and Concatenator. */
export const minIntBytes = (n: bigint) => Math.max(1, Math.ceil(n.toString(2).length / 8));

export const converterNodes: NodeDefinition[] = [
  // 1. Bytes to Hex
  {
    type: 'converter-bytes-to-hex',
    label: 'Bytes to Hex',
    category: 'converter',
    description: 'Encodes raw byte array into hexadecimal string representation',
    inputs: [
      { id: 'bytes', name: 'Bytes In', dataType: 'bytes', required: true, description: 'Raw byte array' },
    ],
    outputs: [
      { id: 'string', name: 'Hex Out', dataType: 'string', description: 'Hexadecimal string' },
    ],
    propertySchema: [
      {
        id: 'case',
        label: 'Letter Case',
        type: 'select',
        options: [
          { label: 'Lowercase (0-9, a-f)', value: 'lower' },
          { label: 'Uppercase (0-9, A-F)', value: 'upper' },
        ],
        defaultValue: 'lower',
        description: 'Hex character case',
      },
      {
        id: 'prefix0x',
        label: 'Prefix 0x',
        type: 'boolean',
        defaultValue: false,
        description: 'Prepend 0x to hex string',
      },
      {
        id: 'separator',
        label: 'Delimiter',
        type: 'select',
        options: [
          { label: 'None (aabbcc)', value: 'none' },
          { label: 'Space (aa bb cc)', value: 'space' },
          { label: 'Colon (aa:bb:cc)', value: 'colon' },
        ],
        defaultValue: 'none',
        description: 'Byte separation delimiter',
      },
    ],
    errorProfile: NONE_PROFILE,
    execute: async ({ inputs, properties, log }) => {
      const data: Uint8Array = inputs.bytes instanceof Uint8Array ? inputs.bytes : new Uint8Array(0);
      const isUpper = properties.case === 'upper';
      const prefix0x = Boolean(properties.prefix0x);
      const separator = properties.separator || 'none';

      const hexStr = bytesToHex(data, {
        uppercase: isUpper,
        prefix0x,
        separator,
      });

      log(`Converted ${data.length} bytes to Hex (${hexStr.length} chars)`);
      return { string: hexStr };
    },
  },

  // 2. Hex to Bytes
  {
    type: 'converter-hex-to-bytes',
    label: 'Hex to Bytes',
    category: 'converter',
    description: 'Decodes a hexadecimal string into a raw byte array',
    inputs: [
      { id: 'string', name: 'Hex In', dataType: 'string', required: true, description: 'Hex string to decode' },
    ],
    outputs: [
      { id: 'bytes', name: 'Bytes Out', dataType: 'bytes', description: 'Decoded byte array' },
    ],
    propertySchema: [],
    errorProfile: fixedErrorProfile(['INVALID_HEX_LENGTH', 'INVALID_HEX_CHAR']),
    execute: async ({ inputs, log }) => {
      const str = String(inputs.string ?? '').trim();
      const bytes = hexToBytes(str);
      log(`Decoded Hex string to ${bytes.length} bytes`);
      return { bytes };
    },
  },

  // 3. Bytes to Base64
  {
    type: 'converter-bytes-to-base64',
    label: 'Bytes to Base64',
    category: 'converter',
    description: 'Encodes raw byte array into Base64 / Base64URL string',
    inputs: [
      { id: 'bytes', name: 'Bytes In', dataType: 'bytes', required: true, description: 'Raw byte array' },
    ],
    outputs: [
      { id: 'string', name: 'Base64 Out', dataType: 'string', description: 'Base64 string' },
    ],
    propertySchema: [
      {
        id: 'variant',
        label: 'Base64 Variant',
        type: 'select',
        options: [
          { label: 'Standard (+/)', value: 'standard' },
          { label: 'URL-Safe (-_)', value: 'url_safe' },
        ],
        defaultValue: 'standard',
        description: 'Alphabet variant',
      },
      {
        id: 'padding',
        label: 'Include Padding (=)',
        type: 'boolean',
        defaultValue: true,
        description: 'Pad output with = characters',
      },
    ],
    errorProfile: NONE_PROFILE,
    execute: async ({ inputs, properties, log }) => {
      const data: Uint8Array = inputs.bytes instanceof Uint8Array ? inputs.bytes : new Uint8Array(0);
      const urlSafe = properties.variant === 'url_safe';
      const padding = properties.padding !== false;

      const b64 = bytesToBase64(data, { urlSafe, padding });
      log(`Encoded ${data.length} bytes to Base64 (${b64.length} chars)`);
      return { string: b64 };
    },
  },

  // 4. Base64 to Bytes
  {
    type: 'converter-base64-to-bytes',
    label: 'Base64 to Bytes',
    category: 'converter',
    description: 'Decodes Base64 or Base64URL string into raw byte array',
    inputs: [
      { id: 'string', name: 'Base64 In', dataType: 'string', required: true, description: 'Base64 string' },
    ],
    outputs: [
      { id: 'bytes', name: 'Bytes Out', dataType: 'bytes', description: 'Decoded byte array' },
    ],
    propertySchema: [],
    errorProfile: fixedErrorProfile(['INVALID_BASE64_INPUT']),
    execute: async ({ inputs, log }) => {
      const str = String(inputs.string ?? '').trim();
      const bytes = base64ToBytes(str);
      log(`Decoded Base64 string to ${bytes.length} bytes`);
      return { bytes };
    },
  },

  // 5. Bytes to Base58
  {
    type: 'converter-bytes-to-base58',
    label: 'Bytes to Base58',
    category: 'converter',
    description: 'Encodes raw byte array into Base58 string (Bitcoin / Flickr)',
    inputs: [
      { id: 'bytes', name: 'Bytes In', dataType: 'bytes', required: true, description: 'Raw byte array' },
    ],
    outputs: [
      { id: 'string', name: 'Base58 Out', dataType: 'string', description: 'Base58 string' },
    ],
    propertySchema: [
      {
        id: 'alphabet',
        label: 'Alphabet',
        type: 'select',
        options: [
          { label: 'Bitcoin (BTC / IPFS)', value: 'btc' },
          { label: 'Flickr', value: 'flickr' },
        ],
        defaultValue: 'btc',
        description: 'Base58 alphabet scheme',
      },
    ],
    errorProfile: NONE_PROFILE,
    execute: async ({ inputs, properties, log }) => {
      const data: Uint8Array = inputs.bytes instanceof Uint8Array ? inputs.bytes : new Uint8Array(0);
      const alphabet = properties.alphabet || 'btc';
      const b58 = bytesToBase58(data, alphabet);
      log(`Encoded ${data.length} bytes to Base58 (${b58.length} chars)`);
      return { string: b58 };
    },
  },

  // 6. Base58 to Bytes
  {
    type: 'converter-base58-to-bytes',
    label: 'Base58 to Bytes',
    category: 'converter',
    description: 'Decodes Base58 string into raw byte array',
    inputs: [
      { id: 'string', name: 'Base58 In', dataType: 'string', required: true, description: 'Base58 string' },
    ],
    outputs: [
      { id: 'bytes', name: 'Bytes Out', dataType: 'bytes', description: 'Decoded byte array' },
    ],
    propertySchema: [
      {
        id: 'alphabet',
        label: 'Alphabet',
        type: 'select',
        options: [
          { label: 'Bitcoin (BTC / IPFS)', value: 'btc' },
          { label: 'Flickr', value: 'flickr' },
        ],
        defaultValue: 'btc',
        description: 'Base58 alphabet scheme',
      },
    ],
    errorProfile: fixedErrorProfile(['INVALID_BASE58_CHAR']),
    execute: async ({ inputs, properties, log }) => {
      const str = String(inputs.string ?? '').trim();
      const alphabet = properties.alphabet || 'btc';
      const bytes = base58ToBytes(str, alphabet);
      log(`Decoded Base58 string to ${bytes.length} bytes`);
      return { bytes };
    },
  },

  // 7. Bytes to String
  {
    type: 'converter-bytes-to-string',
    label: 'Bytes to String',
    category: 'converter',
    description: 'Decodes byte array into human-readable text string (UTF-8, ASCII, Latin-1)',
    inputs: [
      { id: 'bytes', name: 'Bytes In', dataType: 'bytes', required: true, description: 'Raw byte array' },
    ],
    outputs: [
      { id: 'string', name: 'String Out', dataType: 'string', description: 'Decoded text string' },
    ],
    propertySchema: [
      {
        id: 'encoding',
        label: 'Character Encoding',
        type: 'select',
        options: [
          { label: 'UTF-8 (Standard)', value: 'utf-8' },
          { label: 'ASCII (7-bit)', value: 'ascii' },
          { label: 'Latin-1 (ISO-8859-1)', value: 'latin1' },
        ],
        defaultValue: 'utf-8',
        description: 'Character encoding format',
      },
    ],
    errorProfile: NONE_PROFILE,
    execute: async ({ inputs, properties, log }) => {
      const data: Uint8Array = inputs.bytes instanceof Uint8Array ? inputs.bytes : new Uint8Array(0);
      const encoding = properties.encoding || 'utf-8';
      const text = bytesToString(data, encoding);
      log(`Decoded ${data.length} bytes to ${encoding} string (${text.length} chars)`);
      return { string: text };
    },
  },

  // 8. String to Bytes
  {
    type: 'converter-string-to-bytes',
    label: 'String to Bytes',
    category: 'converter',
    description: 'Encodes text string into raw byte array using specified charset',
    inputs: [
      { id: 'string', name: 'String In', dataType: 'string', required: true, description: 'Input text string' },
    ],
    outputs: [
      { id: 'bytes', name: 'Bytes Out', dataType: 'bytes', description: 'Encoded byte array' },
    ],
    propertySchema: [
      {
        id: 'encoding',
        label: 'Character Encoding',
        type: 'select',
        options: [
          { label: 'UTF-8 (Standard)', value: 'utf-8' },
          { label: 'ASCII (7-bit)', value: 'ascii' },
          { label: 'Latin-1 (ISO-8859-1)', value: 'latin1' },
        ],
        defaultValue: 'utf-8',
        description: 'Character encoding format',
      },
    ],
    errorProfile: NONE_PROFILE,
    execute: async ({ inputs, properties, log }) => {
      const text = String(inputs.string ?? '');
      const encoding = properties.encoding || 'utf-8';
      const bytes = stringToBytes(text, encoding);
      log(`Encoded text (${text.length} chars) to ${bytes.length} bytes (${encoding})`);
      return { bytes };
    },
  },

  // 8a. Int to Bytes (unsigned, node-catalog.md ND-2.11)
  {
    type: 'utility-int-to-bytes',
    label: 'Int to Bytes',
    category: 'converter',
    description: 'Converts an unsigned integer to bytes (length: minimal, fixed, or from the Length port)',
    inputs: [
      { id: 'in', name: 'Value', dataType: 'int', required: true },
      { id: 'length', name: 'Length', dataType: 'int', required: false },
    ],
    outputs: [
      { id: 'out', name: 'Bytes', dataType: 'bytes' },
    ],
    propertySchema: [
      {
        id: 'lengthMode',
        label: 'Length Mode',
        type: 'select',
        options: [
          { label: '최소 길이', value: 'min' },
          { label: '입력 포트의 값', value: 'port' },
          { label: '고정 길이', value: 'fixed' },
        ],
        defaultValue: 'min',
        description: 'How the result byte count is decided. Minimal length is the fewest bytes that hold the value (0 takes 1 byte)',
      },
      {
        id: 'length',
        label: 'Length',
        type: 'number',
        defaultValue: 1,
        showWhen: (p) => p.lengthMode === 'fixed',
        description: 'Fixed length (byte count, an integer of 0 or more)',
      },
      {
        id: 'endian',
        label: 'Endian',
        type: 'select',
        options: [
          { label: 'Big Endian', value: 'big' },
          { label: 'Little Endian', value: 'little' },
        ],
        defaultValue: 'big',
      },
    ],
    errorProfile: fixedErrorProfile(['BYTES_INT_OVERFLOW', 'BYTES_INVALID_ARGUMENT']),
    execute: async ({ inputs, properties }) => {
      const asInt = (v: unknown, what: 'value' | 'length') => {
        if (typeof v === 'number' ? !Number.isInteger(v) : typeof v !== 'bigint') {
          throw new NodeError('BYTES_INVALID_ARGUMENT', tmsg(what === 'value' ? 'errors:bytes.valueNotInteger' : 'errors:bytes.lengthNotInteger', { value: String(v) }));
        }
        return BigInt(v as number | bigint);
      };
      const n = asInt(inputs.in, 'value');
      if (n < 0n) throw new NodeError('BYTES_INT_OVERFLOW', tmsg('errors:bytes.negativeNotConvertible'));
      let len = minIntBytes(n);
      const mode = properties.lengthMode ?? 'min';
      if (mode === 'port' || mode === 'fixed') {
        if (mode === 'port' && inputs.length === undefined) throw new NodeError('BYTES_INVALID_ARGUMENT', tmsg('errors:bytes.lengthPortNotConnected'));
        const l = asInt(mode === 'port' ? inputs.length : properties.length, 'length');
        if (l < 0n || l > BigInt(Number.MAX_SAFE_INTEGER)) throw new NodeError('BYTES_INVALID_ARGUMENT', tmsg('errors:bytes.lengthNonNegative', { value: l }));
        len = Number(l);
      }
      return { out: B.fromInt(n, len, properties.endian, false) };
    },
  },

  // 8b. Bytes to Int (unsigned, node-catalog.md ND-2.12)
  {
    type: 'utility-bytes-to-int',
    label: 'Bytes to Int',
    category: 'converter',
    description: 'Interprets bytes as an unsigned integer (bigint when beyond the safe range)',
    inputs: [
      { id: 'in', name: 'Bytes', dataType: 'bytes', required: true },
    ],
    outputs: [
      { id: 'out', name: 'Value', dataType: 'int' },
    ],
    propertySchema: [
      {
        id: 'endian',
        label: 'Endian',
        type: 'select',
        options: [
          { label: 'Big Endian', value: 'big' },
          { label: 'Little Endian', value: 'little' },
        ],
        defaultValue: 'big',
      },
    ],
    errorProfile: NONE_PROFILE,
    execute: async ({ inputs, properties }) => {
      const n = B.toInt(inputs.in, properties.endian, false);
      return { out: n <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(n) : n };
    },
  },

  // 9. Bytes to Multibase
  {
    type: 'converter-bytes-to-multibase',
    label: 'Bytes to Multibase',
    category: 'converter',
    description: 'Encodes bytes into self-describing Multibase string with format prefix',
    inputs: [
      { id: 'bytes', name: 'Bytes In', dataType: 'bytes', required: true, description: 'Raw byte array' },
    ],
    outputs: [
      { id: 'string', name: 'Multibase Out', dataType: 'string', description: 'Multibase encoded string' },
    ],
    propertySchema: [
      {
        id: 'base',
        label: 'Multibase Format',
        type: 'select',
        options: [
          { label: 'Base58BTC (prefix: z)', value: 'base58btc' },
          { label: 'Base16 Hex Lower (prefix: f)', value: 'base16' },
          { label: 'Base16 Hex Upper (prefix: F)', value: 'base16_upper' },
          { label: 'Base64 Standard (prefix: m)', value: 'base64' },
          { label: 'Base64URL (prefix: u)', value: 'base64url' },
        ],
        defaultValue: 'base58btc',
        description: 'Multibase encoding format and prefix',
      },
    ],
    errorProfile: NONE_PROFILE,
    execute: async ({ inputs, properties, log }) => {
      const data: Uint8Array = inputs.bytes instanceof Uint8Array ? inputs.bytes : new Uint8Array(0);
      const base: MultibaseType = properties.base || 'base58btc';
      const mbStr = bytesToMultibase(data, base);
      log(`Encoded ${data.length} bytes to Multibase [${base}] (${mbStr.length} chars)`);
      return { string: mbStr };
    },
  },

  // 10. Multibase to Bytes
  {
    type: 'converter-multibase-to-bytes',
    label: 'Multibase to Bytes',
    category: 'converter',
    description: 'Decodes self-describing Multibase string with automatic prefix detection',
    inputs: [
      { id: 'string', name: 'Multibase In', dataType: 'string', required: true, description: 'Multibase string' },
    ],
    outputs: [
      { id: 'bytes', name: 'Bytes Out', dataType: 'bytes', description: 'Decoded byte array' },
    ],
    propertySchema: [],
    errorProfile: fixedErrorProfile(['INVALID_MULTIBASE_STRING', 'UNSUPPORTED_MULTIBASE_PREFIX', 'INVALID_HEX_LENGTH', 'INVALID_HEX_CHAR', 'INVALID_BASE58_CHAR', 'INVALID_BASE64_INPUT']),
    execute: async ({ inputs, log }) => {
      const str = String(inputs.string ?? '').trim();
      const { bytes, base } = multibaseToBytes(str);
      log(`Auto-detected Multibase prefix [${base}] and decoded to ${bytes.length} bytes`);
      return { bytes };
    },
  },
];
