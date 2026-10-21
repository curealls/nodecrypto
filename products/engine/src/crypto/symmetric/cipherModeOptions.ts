/**
 * Canonical cipher mode metadata: one ordered table drives every cipher's Cipher Mode
 * dropdown (AES/SEED/ARIA/Camellia/SM4/DES/TDES), so the display order and standard
 * citations can never drift apart between ciphers (see issues/tasks/TASK_030).
 *
 * Order rule (user-confirmed, TASK_030 §2): ECB/CBC first (most common) -> {GCM, CCM}
 * grouped -> CTR -> {CFB, OFB} grouped -> XTS -> KW (special-purpose, least common).
 */
export type CipherModeValue = 'ECB' | 'CBC' | 'GCM' | 'CCM' | 'CTR' | 'CFB' | 'OFB' | 'XTS' | 'KW';

interface CipherModeMeta {
  value: CipherModeValue;
  label: string;
  /** Standard/spec citation, reused by the static help (public/help/ko/cipher-modes.html). */
  standard: string;
}

const CIPHER_MODE_SCHEMES: CipherModeMeta[] = [
  { value: 'ECB', label: 'ECB (Electronic Codebook)', standard: 'NIST SP 800-38A §6.1' },
  { value: 'CBC', label: 'CBC (Cipher Block Chaining)', standard: 'NIST SP 800-38A §6.2' },
  { value: 'GCM', label: 'GCM (AEAD)', standard: 'NIST SP 800-38D' },
  { value: 'CCM', label: 'CCM (AEAD)', standard: 'NIST SP 800-38C' },
  { value: 'CTR', label: 'CTR (Counter Mode)', standard: 'NIST SP 800-38A §6.5 (Update 1)' },
  { value: 'CFB', label: 'CFB (Cipher Feedback)', standard: 'NIST SP 800-38A §6.3' },
  { value: 'OFB', label: 'OFB (Output Feedback)', standard: 'NIST SP 800-38A §6.4' },
  { value: 'XTS', label: 'XTS (Tweakable)', standard: 'IEEE 1619-2007 / NIST SP 800-38E' },
  { value: 'KW', label: 'KW (Key Wrap)', standard: 'NIST SP 800-38F / RFC 3394' },
];

function buildModeOptions(values: CipherModeValue[]) {
  return CIPHER_MODE_SCHEMES.filter((m) => values.includes(m.value)).map((m) => ({ label: m.label, value: m.value }));
}

export function cipherModeStandard(value: CipherModeValue): string {
  return CIPHER_MODE_SCHEMES.find((m) => m.value === value)?.standard ?? '-';
}

export const AES_MODE_OPTIONS = buildModeOptions(['ECB', 'CBC', 'GCM', 'CCM', 'CTR', 'CFB', 'OFB', 'XTS', 'KW']);
export const SEED_MODE_OPTIONS = buildModeOptions(['ECB', 'CBC', 'GCM', 'CCM', 'CTR']);
export const ARIA_MODE_OPTIONS = buildModeOptions(['ECB', 'CBC', 'GCM', 'CCM', 'CTR', 'CFB', 'OFB']);
export const CBC_ECB_CTR_GCM_MODE_OPTIONS = buildModeOptions(['ECB', 'CBC', 'GCM', 'CTR']);
export const DES_MODE_OPTIONS = buildModeOptions(['ECB', 'CBC']);
