/**
 * bytesOps - 바이트 연산 모듈 (bytes-ops.md)
 *
 * 규칙: 입력을 바꾸지 않고 새 Uint8Array를 반환한다. 범위·길이 위반은 보정하지 않고
 * NodeError(BYTES_*)로 던진다. 인덱스·길이·개수·이동량은 number, toInt/fromInt의 정수는 bigint이다.
 */

import { NodeError } from '../../dag/errors';
import { Msg, tmsg } from '../../messages';
import { validateHexInput } from './hexValidation';
import { hexToBytes, bytesToHex } from './encoding';

/** 결과 bytes 길이 상한(초안 16 MiB, builtin-script.md §9 / U-03에서 확정). */
export const MAX_BYTES = 16 * 1024 * 1024;

export type Endian = 'big' | 'little';

const fail = (code: string, message: Msg): never => {
  throw new NodeError(code, message);
};

/** 인덱스·길이·개수 인자는 안전 정수여야 한다. */
function int(v: number, name: string): number {
  if (!Number.isSafeInteger(v)) fail('BYTES_INVALID_ARGUMENT', tmsg('errors:bytes.notInteger', { name, value: v }));
  return v;
}

function nonNeg(v: number, name: string): number {
  if (int(v, name) < 0) fail('BYTES_INVALID_ARGUMENT', tmsg('errors:bytes.negative', { name, value: v }));
  return v;
}

function checkSize(n: number): number {
  if (n > MAX_BYTES) fail('BYTES_SIZE_LIMIT', tmsg('errors:bytes.sizeLimit', { n, max: MAX_BYTES }));
  return n;
}

/** 규칙 4: 음수 인덱스 -k는 길이 - k. 해석 결과가 0 미만이면 오류. */
function resolveOffset(len: number, offset: number): number {
  int(offset, 'offset');
  const o = offset < 0 ? len + offset : offset;
  if (o < 0) fail('BYTES_OUT_OF_RANGE', tmsg('errors:bytes.indexOutOfRange', { index: offset, length: len }));
  return o;
}

// ---- 3.1 생성 ----

export function zeros(n: number): Uint8Array {
  return new Uint8Array(checkSize(nonNeg(n, 'n')));
}

export function fill(value: number, n: number): Uint8Array {
  if (!Number.isInteger(value) || value < 0 || value > 255) {
    fail('BYTES_INVALID_ARGUMENT', tmsg('errors:bytes.byteValue', { value }));
  }
  return new Uint8Array(checkSize(nonNeg(n, 'n'))).fill(value);
}

export function fromHex(s: string): Uint8Array {
  const r = validateHexInput(s, { allowEmpty: true });
  if (!r.isValid) fail('BYTES_INVALID_HEX', r.errorMsg ?? tmsg('errors:bytes.invalidHexDefault'));
  checkSize(r.byteCount);
  return hexToBytes(r.cleanHex);
}

export function toHex(b: Uint8Array, upper = false): string {
  return bytesToHex(b, { uppercase: upper });
}

export function fromUtf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

export function toUtf8(b: Uint8Array): string {
  try {
    // ignoreBOM: true는 선행 BOM(EF BB BF)을 지우지 않고 U+FEFF로 보존한다.
    return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(b);
  } catch {
    return fail('BYTES_INVALID_UTF8', tmsg('errors:bytes.invalidUtf8'));
  }
}

// ---- 3.2 구조 조작 ----

export function length(b: Uint8Array): number {
  return b.length;
}

export function get(b: Uint8Array, i: number): number {
  const idx = resolveOffset(b.length, i);
  if (idx >= b.length) fail('BYTES_OUT_OF_RANGE', tmsg('errors:bytes.indexOutOfRange', { index: i, length: b.length }));
  return b[idx];
}

export function slice(b: Uint8Array, offset: number, len: number): Uint8Array {
  nonNeg(len, 'length');
  const o = resolveOffset(b.length, offset);
  if (o + len > b.length) fail('BYTES_OUT_OF_RANGE', tmsg('errors:bytes.sliceOutOfRange', { start: o, end: o + len, length: b.length }));
  return b.slice(o, o + len);
}

export function replace(b: Uint8Array, offset: number, part: Uint8Array): Uint8Array {
  const o = resolveOffset(b.length, offset);
  if (o + part.length > b.length) {
    fail('BYTES_OUT_OF_RANGE', tmsg('errors:bytes.sliceOutOfRange', { start: o, end: o + part.length, length: b.length }));
  }
  const out = b.slice();
  out.set(part, o);
  return out;
}

export function concat(parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(checkSize(total));
  let pos = 0;
  for (const p of parts) {
    out.set(p, pos);
    pos += p.length;
  }
  return out;
}

export function reverse(b: Uint8Array): Uint8Array {
  return b.slice().reverse();
}

export function repeat(b: Uint8Array, n: number): Uint8Array {
  nonNeg(n, 'n');
  const total = b.length * n;
  const out = new Uint8Array(checkSize(total));
  for (let pos = 0; pos < total; pos += b.length) out.set(b, pos);
  return out;
}

export function toInts(b: Uint8Array): number[] {
  return Array.from(b);
}

export function fromInts(xs: readonly number[]): Uint8Array {
  checkSize(xs.length);
  const out = new Uint8Array(xs.length);
  xs.forEach((v, i) => {
    if (!Number.isInteger(v) || v < 0 || v > 255) fail('BYTES_INVALID_ARGUMENT', tmsg('errors:bytes.byteValue', { value: v }));
    out[i] = v;
  });
  return out;
}

export function blocks(b: Uint8Array, size: number): Uint8Array[] {
  if (int(size, 'size') <= 0) fail('BYTES_INVALID_ARGUMENT', tmsg('errors:bytes.sizeAtLeastOne', { value: size }));
  const out: Uint8Array[] = [];
  for (let i = 0; i < b.length; i += size) out.push(b.slice(i, i + size));
  return out;
}

// ---- 3.3 비트 연산 ----

function zip(a: Uint8Array, b: Uint8Array, f: (x: number, y: number) => number): Uint8Array {
  if (a.length !== b.length) fail('BYTES_LENGTH_MISMATCH', tmsg('errors:bytes.lengthsDiffer', { a: a.length, b: b.length }));
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) out[i] = f(a[i], b[i]);
  return out;
}

export const and = (a: Uint8Array, b: Uint8Array) => zip(a, b, (x, y) => x & y);
export const or = (a: Uint8Array, b: Uint8Array) => zip(a, b, (x, y) => x | y);
export const xor = (a: Uint8Array, b: Uint8Array) => zip(a, b, (x, y) => x ^ y);

export function not(b: Uint8Array): Uint8Array {
  return b.map((x) => ~x & 0xff);
}

// 이동량 n이 아무리 커도 시간은 바이트열 길이에만 비례한다(바이트 단위 이동 + 0~7비트 이동).
export function shl(b: Uint8Array, n: number): Uint8Array {
  nonNeg(n, 'n');
  const len = b.length;
  const out = new Uint8Array(len);
  if (n >= 8 * len) return out;
  const bs = Math.floor(n / 8);
  const bits = n % 8;
  for (let i = 0; i + bs < len; i++) {
    const hi = b[i + bs] << bits;
    const lo = i + bs + 1 < len ? b[i + bs + 1] >> (8 - bits) : 0;
    out[i] = (hi | lo) & 0xff;
  }
  return out;
}

export function shr(b: Uint8Array, n: number): Uint8Array {
  nonNeg(n, 'n');
  const len = b.length;
  const out = new Uint8Array(len);
  if (n >= 8 * len) return out;
  const bs = Math.floor(n / 8);
  const bits = n % 8;
  for (let i = bs; i < len; i++) {
    const lo = b[i - bs] >> bits;
    const hi = i - bs - 1 >= 0 ? b[i - bs - 1] << (8 - bits) : 0;
    out[i] = (hi | lo) & 0xff;
  }
  return out;
}

export function rol(b: Uint8Array, n: number): Uint8Array {
  nonNeg(n, 'n');
  const total = 8 * b.length;
  if (total === 0 || n % total === 0) return b.slice();
  const k = n % total;
  return or(shl(b, k), shr(b, total - k));
}

export function ror(b: Uint8Array, n: number): Uint8Array {
  nonNeg(n, 'n');
  const total = 8 * b.length;
  if (total === 0) return b.slice();
  return rol(b, total - (n % total));
}

// ---- 3.4 비교 ----

export function equals(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

/**
 * 첫 불일치에서 조기 종료하지 않고 전체를 훑는다(최선 노력).
 * JavaScript 런타임(JIT, GC 등)에서는 시간 일정성을 보장하지 못한다(bytes-ops.md §3.4).
 */
export function ctEquals(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

export function compare(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1;
  return a.length === b.length ? 0 : a.length < b.length ? -1 : 1;
}

// ---- 3.5 정수 변환 ----

function checkEndian(endian: string): void {
  if (endian !== 'big' && endian !== 'little') {
    fail('BYTES_INVALID_ARGUMENT', tmsg('errors:bytes.endian', { value: endian }));
  }
}

export function toInt(b: Uint8Array, endian: Endian, signed: boolean): bigint {
  checkEndian(endian);
  if (b.length === 0) return 0n;
  const be = endian === 'big' ? b : reverse(b);
  let v = BigInt('0x' + bytesToHex(be));
  if (signed && be[0] & 0x80) v -= 1n << BigInt(8 * be.length);
  return v;
}

export function fromInt(n: bigint, len: number, endian: Endian, signed: boolean): Uint8Array {
  checkEndian(endian);
  nonNeg(len, 'length');
  checkSize(len);
  if (len === 0) {
    if (n !== 0n) fail('BYTES_INT_OVERFLOW', tmsg('errors:bytes.zeroLength'));
    return new Uint8Array(0);
  }
  const bits = BigInt(8 * len);
  const min = signed ? -(1n << (bits - 1n)) : 0n;
  const max = signed ? (1n << (bits - 1n)) - 1n : (1n << bits) - 1n;
  if (n < min || n > max) fail('BYTES_INT_OVERFLOW', tmsg(signed ? 'errors:bytes.intOverflowSigned' : 'errors:bytes.intOverflowUnsigned', { len }));
  const v = n < 0n ? n + (1n << bits) : n;
  const out = hexToBytes(v.toString(16).padStart(2 * len, '0'));
  return endian === 'big' ? out : out.reverse();
}
