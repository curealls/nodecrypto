/**
 * f-string 서식 지정 (builtin-script.md §4.9).
 * 파서가 parseFormatSpec으로 지정을 읽고, 검사기가 validateSpec으로 값 타입과 맞는지 확인하고,
 * 평가기가 formatValue로 값을 문자열로 바꾼다.
 */

import type { FormatSpec } from './ast';
import { MAX_FORMAT_WIDTH } from './limits';
import { Msg, tmsg } from '../messages';

const SPEC_RE = /^(?:([^{}])?([<>^]))?([+\- ])?(#)?(0)?(\d+)?([A-Za-z])?$/;

/** 지정 문자열을 읽는다. 잘못되었으면 오류 메시지(Msg)를 돌려준다. */
export function parseFormatSpec(raw: string): FormatSpec | Msg {
  const m = SPEC_RE.exec(raw);
  if (!m) return tmsg('script:format.unparsable', { raw });
  const [, fill, align, sign, alt, zero, width, type] = m;
  const spec: FormatSpec = {
    fill, align: align as FormatSpec['align'], sign: sign as FormatSpec['sign'],
    alt: !!alt, zero: !!zero, width: width === undefined ? undefined : Number(width), type,
  };
  if (spec.width !== undefined && spec.width > MAX_FORMAT_WIDTH) {
    return tmsg('script:format.widthTooLarge', { width: spec.width, MAX_FORMAT_WIDTH });
  }
  if (spec.zero && align) return tmsg('script:format.zeroWithAlign');
  return spec;
}

const TYPES: Record<string, string> = { int: 'dxXbo', string: 's', bytes: 'xX', bool: 's' };

/** 값 타입(int/string/bytes/bool)에 쓸 수 없는 지정이면 오류 메시지를 돌려준다. */
export function validateSpec(spec: FormatSpec, ty: string): Msg | null {
  const allowed = TYPES[ty];
  if (!allowed) return tmsg('script:format.typeNotFormattable', { ty });
  if (spec.type && !allowed.includes(spec.type)) {
    return tmsg('script:format.typeNotAllowed', { ty, type: spec.type, allowed: [...allowed].join(', ') });
  }
  if (ty !== 'int' && (spec.sign || spec.alt || spec.zero)) {
    return tmsg('script:format.intOnlyFlags', { ty });
  }
  if (spec.alt && !'xXbo'.includes(spec.type ?? 'd')) return tmsg('script:format.altForm');
  return null;
}

function pad(text: string, spec: FormatSpec, defaultAlign: '<' | '>'): string {
  const n = (spec.width ?? 0) - Array.from(text).length;
  if (n <= 0) return text;
  const fill = spec.fill ?? ' ';
  switch (spec.align ?? defaultAlign) {
    case '<': return text + fill.repeat(n);
    case '>': return fill.repeat(n) + text;
    default: { const left = Math.floor(n / 2); return fill.repeat(left) + text + fill.repeat(n - left); }
  }
}

const RADIX: Record<string, [number, string]> = { d: [10, ''], x: [16, '0x'], X: [16, '0X'], b: [2, '0b'], o: [8, '0o'] };

export function formatValue(v: bigint | string | boolean | Uint8Array, spec: FormatSpec): string {
  if (typeof v === 'bigint') {
    const t = spec.type ?? 'd';
    const [radix, prefix] = RADIX[t];
    let digits = (v < 0n ? -v : v).toString(radix);
    if (t === 'X') digits = digits.toUpperCase();
    const sign = v < 0n ? '-' : spec.sign === '+' ? '+' : spec.sign === ' ' ? ' ' : '';
    const head = sign + (spec.alt ? prefix : '');
    if (spec.zero) return head + digits.padStart(Math.max(0, (spec.width ?? 0) - head.length), '0');
    return pad(head + digits, spec, '>');
  }
  if (v instanceof Uint8Array) {
    const hex = Array.from(v, (b) => b.toString(16).padStart(2, '0')).join('');
    return pad(spec.type === 'X' ? hex.toUpperCase() : hex, spec, '<');
  }
  return pad(typeof v === 'boolean' ? (v ? 'True' : 'False') : v, spec, '<');
}
