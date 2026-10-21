/**
 * Workflow Input port constraints (node-catalog.md ND-1.5, execution-semantics.md §4.3).
 * bytes/string: `lengths`, `min`, `max` bound the byte length (string = UTF-8 bytes).
 * int: `min`, `max` bound the value, kept as decimal strings so bigint survives JSON.
 */

import type { NodePortDefinition, PortConstraint } from '../types';
import { Msg, tmsg } from '../messages';

type Port = Pick<NodePortDefinition, 'name' | 'dataType' | 'constraint'>;

const isLength = (t: string) => t === 'bytes' || t === 'string';
const utf8Length = (s: string) => new TextEncoder().encode(s).length;
const big = (v: number | string) => BigInt(v);
const MULTIPLE = /^([1-9]\d*)\*N$/;
const multipleOf = (e: number | string) => (typeof e === 'string' ? Number(MULTIPLE.exec(e)?.[1]) : NaN);
const lengthFits = (e: number | string, n: number) => (typeof e === 'number' ? e === n : n > 0 && n % multipleOf(e) === 0);

/** Length (bytes/string) or value (int) of a runtime value; undefined when the value does not fit the port type. */
function measure(type: string, value: unknown): number | bigint | undefined {
  if (type === 'bytes') return value instanceof Uint8Array ? value.length : undefined;
  if (type === 'string') return typeof value === 'string' ? utf8Length(value) : undefined;
  if (type === 'int') return typeof value === 'bigint' ? value : typeof value === 'number' && Number.isInteger(value) ? BigInt(value) : undefined;
  return undefined;
}

/** Reason the value breaks the port's constraint, or null. */
export function checkConstraint(port: Port, value: unknown): Msg | null {
  const c = port.constraint;
  const n = c && measure(port.dataType, value);
  if (!c || n === undefined) return null;
  const say = (why: Msg) => tmsg('errors:constraint.say', { name: port.name, why });
  if (isLength(port.dataType)) {
    if (c.lengths && !c.lengths.some((e) => lengthFits(e, Number(n)))) return say(tmsg('errors:constraint.lengthNotAllowed', { n, allowed: c.lengths.join(', ') }));
    if (c.min !== undefined && n < big(c.min)) return say(tmsg('errors:constraint.lengthTooShort', { n, min: c.min }));
    if (c.max !== undefined && n > big(c.max)) return say(tmsg('errors:constraint.lengthTooLong', { n, max: c.max }));
  } else {
    if (c.min !== undefined && n < big(c.min)) return say(tmsg('errors:constraint.valueTooSmall', { n, min: c.min }));
    if (c.max !== undefined && n > big(c.max)) return say(tmsg('errors:constraint.valueTooLarge', { n, max: c.max }));
  }
  return null;
}

/**
 * Check a Workflow Input port's `defaultValue` text (ND-1.5 "기본값 검사"): `error` when it is not a valid
 * notation for the port type (blocks saving), `warning` when it parses but breaks the constraint (does not block).
 */
export function checkDefaultValue(port: Port, text: string): { error?: Msg; warning?: Msg } {
  if (text === '') return {};
  let value: unknown;
  if (port.dataType === 'bytes') {
    const hex = text.replace(/\s+/g, '').replace(/^0x/i, '');
    if (!/^[0-9a-fA-F]*$/.test(hex) || hex.length % 2) return { error: tmsg('errors:constraint.hexExpected') };
    value = Uint8Array.from(hex.match(/../g) ?? [], (h) => parseInt(h, 16));
  } else if (port.dataType === 'int') {
    if (!/^-?\d+$/.test(text.trim())) return { error: tmsg('errors:constraint.intExpected') };
    value = BigInt(text.trim());
  } else if (port.dataType === 'bool') {
    if (text !== 'true' && text !== 'false') return { error: tmsg('errors:constraint.boolExpected') };
    return {};
  } else value = text;
  const warning = checkConstraint(port, value);
  return warning ? { warning } : {};
}

/** Badge text computed from the constraint (ND-1.5): `16/24/32 B`, `≥32 B`, `16×N/24 B · 16–256 B`, `0–255`. Not stored. */
export function constraintSpec(port: Port): string | undefined {
  const c = port.constraint;
  const lengthy = isLength(port.dataType);
  if (!c || (!lengthy && port.dataType !== 'int')) return undefined;
  const u = lengthy ? ' B' : '';
  const parts: string[] = [];
  if (lengthy && c.lengths?.length) parts.push(`${c.lengths.map((e) => (typeof e === 'string' ? `${multipleOf(e)}×N` : e)).join('/')} B`);
  if (c.min !== undefined && c.max !== undefined) parts.push(`${c.min}–${c.max}${u}`);
  else if (c.min !== undefined) parts.push(`≥${c.min}${u}`);
  else if (c.max !== undefined) parts.push(`≤${c.max}${u}`);
  return parts.length ? parts.join(' · ') : undefined;
}

/** The same constraint in words, for hover text: one message per part (the UI joins them with ' · '). Not stored. */
export function constraintText(port: Port): Msg[] | undefined {
  const c = port.constraint;
  const lengthy = isLength(port.dataType);
  if (!c || (!lengthy && port.dataType !== 'int')) return undefined;
  const u = lengthy ? tmsg('errors:constraint.unitBytes') : '';
  const parts: Msg[] = [];
  if (lengthy && c.lengths?.length) parts.push(tmsg('errors:constraint.allowedLengths', { allowed: c.lengths.map((e) => (typeof e === 'string' ? `${multipleOf(e)}×N` : e)).join(' / ') }));
  if (c.min !== undefined) parts.push(tmsg('errors:constraint.min', { min: c.min, u }));
  if (c.max !== undefined) parts.push(tmsg('errors:constraint.max', { max: c.max, u }));
  return parts.length ? parts : undefined;
}

/** Problem with the constraint itself (editing time), or null. Types without constraints (bool, any) never have one. */
export function validateConstraint(port: Port): Msg | null {
  const c = port.constraint;
  if (!c) return null;
  const lengthy = isLength(port.dataType);
  if (!lengthy && port.dataType !== 'int') return tmsg('errors:constraint.noConstraintForType');
  const okInt = (v: unknown) => /^-?\d+$/.test(String(v));
  const okLen = (v: unknown) => /^\d+$/.test(String(v));
  const okEntry = (e: unknown) => (typeof e === 'string' ? MULTIPLE.test(e) : okLen(e));
  const ok = lengthy ? okLen : okInt;
  if (c.lengths !== undefined) {
    if (!lengthy) return tmsg('errors:constraint.lengthsOnlyBytesString');
    if (!c.lengths.length || !c.lengths.every(okEntry)) return LENGTHS_HINT;
  }
  for (const [k, v] of [['min', c.min], ['max', c.max]] as const) {
    if (v !== undefined && !ok(v)) return tmsg(`errors:constraint.${k}${lengthy ? 'Length' : 'Int'}Invalid`);
  }
  if (c.min !== undefined && c.max !== undefined && big(c.min) > big(c.max)) return tmsg('errors:constraint.minGreaterThanMax');
  return null;
}

const LENGTHS_HINT = tmsg('errors:constraint.lengthsHint');

export interface ConstraintDraft { lengths: string; min: string; max: string }

export const constraintToDraft = (c?: PortConstraint): ConstraintDraft => ({
  lengths: c?.lengths?.join(', ') ?? '',
  min: c?.min !== undefined ? String(c.min) : '',
  max: c?.max !== undefined ? String(c.max) : '',
});

/** Editor text -> constraint. All fields empty means no constraint (constraint undefined, no error). */
export function parseConstraintDraft(
  dataType: NodePortDefinition['dataType'],
  d: ConstraintDraft
): { constraint?: PortConstraint; error?: Msg } {
  const lengthy = isLength(dataType);
  const c: PortConstraint = {};
  const lengths = d.lengths.split(',').map((t) => t.trim()).filter(Boolean);
  if (lengths.length) {
    // "16*N", "16*", "16 * n" all mean multiples of 16 and are stored as "16*N"
    const entries = lengths.map((t) => (/^\d+$/.test(t) ? Number(t) : /^\d+\s*\*\s*[nN]?$/.test(t) ? `${parseInt(t, 10)}*N` : undefined));
    if (entries.includes(undefined)) return { error: LENGTHS_HINT };
    c.lengths = entries as (number | string)[];
  } else if (d.lengths.trim()) return { error: LENGTHS_HINT };
  const bound = (t: string) => { const s = t.trim(); return !s ? undefined : lengthy && /^\d+$/.test(s) ? Number(s) : s; };
  if (bound(d.min) !== undefined) c.min = bound(d.min);
  if (bound(d.max) !== undefined) c.max = bound(d.max);
  if (!Object.keys(c).length) return {};
  const error = validateConstraint({ name: '', dataType, constraint: c });
  return error ? { error } : { constraint: c };
}
