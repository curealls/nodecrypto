/**
 * 변수 참조 값과 해석 (UI·localStorage 비의존)
 *
 * 규격: value-registry.md §4, §5
 */
import { validateHexInput } from '../crypto/utils/hexValidation';
import type { NodeDefinition, PropertyFieldDefinition, PropertyFieldType } from '../dag/types';
import { Registry, VariableType, VariableValue, effectiveValue, validateValue } from './registry';
import { Msg, formatMsg, tmsg } from '../messages';

// ─── 참조 값 ─────────────────────────────────────────────────────────────

export interface VarRef {
  $var: string;
}

/** 참조는 키가 `$var` 하나뿐이고 값이 문자열인 객체이다. `"$100"` 같은 리터럴 문자열이나 다른 키가 있는 객체는 참조가 아니다. */
export function isVarRef(value: unknown): value is VarRef {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const keys = Object.keys(value);
  return keys.length === 1 && keys[0] === '$var' && typeof (value as VarRef).$var === 'string';
}

export const makeVarRef = (path: string): VarRef => ({ $var: path });

/** 실행 호스트가 실행 시작 때 넘기는 변수 맵: 경로 → 타입과 유효 값 (§5.1) */
export type VariableMap = Record<string, { type: VariableType; value: VariableValue }>;

/** 레지스트리를 변수 맵으로 스냅샷한다(유효 값 = current ?? default). */
export function toVariableMap(registry: Registry): VariableMap {
  const map: VariableMap = {};
  for (const [path, e] of Object.entries(registry)) map[path] = { type: e.type, value: effectiveValue(e) };
  return map;
}

// ─── 참조를 둘 수 있는 자리 ──────────────────────────────────────────────

/** 필드 종류 → 필요한 변수 타입 (§4.2). `select`는 정의가 `variable`로 지정한 경우만 대상이다. */
export const FIELD_VAR_TYPE: Partial<Record<PropertyFieldType, VariableType>> = {
  hex: 'bytes',
  text: 'string',
  textarea: 'string',
  number: 'int',
  boolean: 'bool',
};

/** 필드가 받는 변수 타입. 정의의 `variable`이 우선하고(`false`는 제외), 없으면 필드 종류를 따른다. 대상이 아니면 undefined. */
export function fieldVarType(f: Pick<PropertyFieldDefinition, 'type' | 'variable'>): VariableType | undefined {
  if (f.variable === false) return undefined;
  return f.variable ?? FIELD_VAR_TYPE[f.type];
}

/** hex 필드가 빈 값을 허용하는가 (선택 입력 필드). */
export function hexAllowsEmpty(field: Pick<PropertyFieldDefinition, 'id' | 'description'>): boolean {
  return field.id === 'mask' || Boolean(field.description?.toLowerCase().includes('optional'));
}

export interface RefSlot {
  label: string;
  /** 필요한 변수 타입 */
  type: VariableType;
  /** 빈 Hex를 허용하는가 (bytes일 때만 의미가 있다) */
  allowEmpty: boolean;
}

export interface RefSlots {
  /** 속성 필드 id → 자리 */
  fields: Record<string, RefSlot>;
  /** ValueSet 행 포트 id → 자리 (`properties.rows[id].value`) */
  rows: Record<string, RefSlot>;
}

/** 노드 정의와 현재 출력 포트에서 참조를 둘 수 있는 자리를 계산한다. */
export function slotsFor(
  def: Pick<NodeDefinition, 'propertySchema' | 'rowValueRefs'> | undefined,
  outputPorts: Array<{ id: string; name: string; dataType: string }> = [],
): RefSlots {
  const slots: RefSlots = { fields: {}, rows: {} };
  for (const f of def?.propertySchema ?? []) {
    const type = fieldVarType(f);
    if (type) slots.fields[f.id] = { label: f.label, type, allowEmpty: type === 'bytes' && f.type === 'hex' && hexAllowsEmpty(f) };
  }
  if (def?.rowValueRefs) {
    for (const p of outputPorts) {
      if (p.dataType === 'bytes' || p.dataType === 'string' || p.dataType === 'int' || p.dataType === 'bool') {
        slots.rows[p.id] = { label: p.name, type: p.dataType, allowEmpty: true };
      }
    }
  }
  return slots;
}

// ─── 해석 ────────────────────────────────────────────────────────────────

export type RefErrorReason = 'unregistered' | 'type_mismatch' | 'invalid_value' | 'out_of_range';

const REASON_TEXT: Record<RefErrorReason, Msg> = {
  unregistered: tmsg('errors:variable.reason.unregistered'),
  type_mismatch: tmsg('errors:variable.reason.type_mismatch'),
  invalid_value: tmsg('errors:variable.reason.invalid_value'),
  out_of_range: tmsg('errors:variable.reason.out_of_range'),
};

export interface RefError {
  /** 필드 id, 또는 ValueSet 행이면 `rows.<포트 id>` */
  slot: string;
  label: string;
  /** 참조의 변수 경로 */
  path: string;
  /** 필요한 변수 타입 */
  expected: VariableType;
  reason: RefErrorReason;
  /** 필드 라벨, 변수 경로, 사유. 변수 값은 담지 않는다(§5.3). */
  message: string;
  /** Translatable form of `message` (i18n.md §6.2) */
  msg: Msg;
}

/** 참조 하나를 값으로 푼다. 실패하면 사유를 돌려준다. */
export function resolveRef(path: string, slot: RefSlot, variables: VariableMap): { ok: true; value: string | number | boolean } | { ok: false; reason: RefErrorReason } {
  const v = variables[path];
  if (!v) return { ok: false, reason: 'unregistered' };
  if (v.type !== slot.type) return { ok: false, reason: 'type_mismatch' };
  const checked = validateValue(v.type, v.value);
  if (!checked.ok) return { ok: false, reason: 'invalid_value' };
  const value = checked.value;
  switch (slot.type) {
    case 'bytes':
      return validateHexInput(String(value), { allowEmpty: slot.allowEmpty }).isValid ? { ok: true, value } : { ok: false, reason: 'invalid_value' };
    case 'int': {
      const n = BigInt(String(value));
      return n >= BigInt(Number.MIN_SAFE_INTEGER) && n <= BigInt(Number.MAX_SAFE_INTEGER) ? { ok: true, value: Number(n) } : { ok: false, reason: 'out_of_range' };
    }
    default:
      return { ok: true, value };
  }
}

export type ResolveResult = { ok: true; properties: Record<string, any> } | { ok: false; errors: RefError[] };

/**
 * `properties`의 참조를 유효 값으로 바꾼 사본을 돌려준다. 입력은 바꾸지 않는다.
 * 풀 수 없는 참조가 하나라도 있으면 모든 오류를 모아 돌려준다. 숨겨진 필드(`showWhen`)의 참조도 똑같이 처리한다(D-17).
 */
export function resolveProperties(properties: Record<string, any> | undefined, slots: RefSlots, variables: VariableMap = {}): ResolveResult {
  const src = properties ?? {};
  const out: Record<string, any> = { ...src };
  const errors: RefError[] = [];

  const resolveAt = (slotKey: string, slot: RefSlot, ref: VarRef): any => {
    const r = resolveRef(ref.$var, slot, variables);
    if (r.ok) return r.value;
    const refMsg = tmsg('errors:variable.refError', { label: slot.label, path: ref.$var, reason: REASON_TEXT[r.reason] });
    errors.push({
      slot: slotKey,
      label: slot.label,
      path: ref.$var,
      expected: slot.type,
      reason: r.reason,
      message: formatMsg(refMsg),
      msg: refMsg,
    });
    return ref;
  };

  for (const [id, slot] of Object.entries(slots.fields)) {
    if (isVarRef(src[id])) out[id] = resolveAt(id, slot, src[id]);
  }

  const rows = src.rows;
  if (rows && typeof rows === 'object' && !Array.isArray(rows)) {
    let copy: Record<string, any> | null = null;
    for (const [id, slot] of Object.entries(slots.rows)) {
      const row = rows[id];
      if (row && isVarRef(row.value)) {
        const next: Record<string, any> = copy ?? { ...rows };
        next[id] = { ...row, value: resolveAt(`rows.${id}`, slot, row.value) };
        copy = next;
      }
    }
    if (copy) out.rows = copy;
  }

  return errors.length ? { ok: false, errors } : { ok: true, properties: out };
}

/** 속성에 있는 모든 참조(필드와 ValueSet 행). 스키마를 쓰지 않고 구조만 본다. */
export function collectRefs(properties: Record<string, any> | undefined): Array<{ slot: string; path: string }> {
  const out: Array<{ slot: string; path: string }> = [];
  for (const [id, v] of Object.entries(properties ?? {})) {
    if (isVarRef(v)) out.push({ slot: id, path: v.$var });
  }
  const rows = properties?.rows;
  if (rows && typeof rows === 'object' && !Array.isArray(rows)) {
    for (const [id, row] of Object.entries<any>(rows)) {
      if (row && isVarRef(row.value)) out.push({ slot: `rows.${id}`, path: row.value.$var });
    }
  }
  return out;
}

export const hasRefs = (properties: Record<string, any> | undefined): boolean => collectRefs(properties).length > 0;

/** 사용자 정의 노드 정의의 본문 노드에 참조가 남아 있는가 (§8.3, `package-format.md` §3.3). */
export function definitionHasRef(def: { workflow?: { nodes?: any[] } }): boolean {
  return (def.workflow?.nodes ?? []).some((n) => hasRefs(n?.data?.properties));
}
