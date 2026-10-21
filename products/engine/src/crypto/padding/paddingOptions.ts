/**
 * Canonical padding scheme metadata: one table drives the Encrypt/Decrypt (Pad/Unpad)
 * dropdown option lists for both the 16-byte+ block family (AES/SEED/ARIA/Camellia/SM4)
 * and the 8-byte block family (DES/TDES), so labels can never drift apart between them
 * (see issues/tasks/TASK_029).
 */
import { BlockPaddingType } from './padding';

interface PaddingSchemeMeta {
  value: BlockPaddingType;
  /** Label for 16-byte+ block ciphers and block-size-agnostic utility nodes. */
  label16: string;
  /** Label for 8-byte block ciphers (DES/TDES), where the historical name is PKCS#5. */
  label8: string;
  /**
   * false => pad-only: NIST SP 800-38B and ISO/IEC 9797-1 Method 1 (Zero Padding) do not
   * add a value when the data is already block-aligned, so an unpad step cannot tell
   * "no padding was added" from "the data happens to end that way" (see padding.ts).
   */
  unpadSupported: boolean;
}

const PADDING_SCHEMES: PaddingSchemeMeta[] = [
  { value: 'None', label16: 'None', label8: 'None', unpadSupported: true },
  { value: 'Zero', label16: 'ISO/IEC 9797-1 Method 1 (Zero Padding)', label8: 'ISO/IEC 9797-1 Method 1 (Zero Padding)', unpadSupported: false },
  { value: 'ISO7816', label16: 'ISO/IEC 9797-1 Method 2 (ISO/IEC 7816-4)', label8: 'ISO/IEC 9797-1 Method 2 (ISO/IEC 7816-4)', unpadSupported: true },
  { value: 'ISO97971M3', label16: 'ISO/IEC 9797-1 Method 3', label8: 'ISO/IEC 9797-1 Method 3', unpadSupported: true },
  { value: 'PKCS7', label16: 'PKCS#7 (RFC 5652)', label8: 'PKCS#5 (RFC 2898)', unpadSupported: true },
  { value: 'NIST80038B', label16: 'NIST SP 800-38B', label8: 'NIST SP 800-38B', unpadSupported: false },
  { value: 'ANSIX923', label16: 'ANSI X9.23', label8: 'ANSI X9.23', unpadSupported: true },
];

function buildOptions(family: 'label16' | 'label8', direction: 'pad' | 'unpad') {
  return PADDING_SCHEMES.filter((s) => direction === 'pad' || s.unpadSupported).map((s) => ({
    label: s[family],
    value: s.value,
  }));
}

export const PADDING_OPTIONS_ENCRYPT_16B = buildOptions('label16', 'pad');
export const PADDING_OPTIONS_DECRYPT_16B = buildOptions('label16', 'unpad');
export const PADDING_OPTIONS_ENCRYPT_8B = buildOptions('label8', 'pad');
export const PADDING_OPTIONS_DECRYPT_8B = buildOptions('label8', 'unpad');
