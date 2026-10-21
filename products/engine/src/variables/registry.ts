/**
 * 변수 레지스트리 코어 (순수 함수)
 *
 * 규격: value-registry.md §2, §6
 * UI·localStorage·React에 의존하지 않으며, 모든 함수는 입력을 바꾸지 않고 새 객체를 돌려준다.
 */
import { validateHexInput } from '../crypto/utils/hexValidation';
import { Msg, formatMsg, tmsg } from '../messages';

export type VariableType = 'bytes' | 'string' | 'int' | 'bool';
export const VARIABLE_TYPES: readonly VariableType[] = ['bytes', 'string', 'int', 'bool'];

/** bytes=hex 문자열, string=문자열, int=10진 문자열(bigint 보존), bool=불리언 */
export type VariableValue = string | boolean;

export interface VariableEntry {
  name: string;
  type: VariableType;
  default: VariableValue;
  current?: VariableValue;
  description: string;
}

/** 변수 경로(`$a.b.A`) → 항목. 그룹은 경로에서 파생한다. */
export type Registry = Record<string, VariableEntry>;

/** `message` is the English text; `msg` lets the UI translate it (i18n.md §6.2). */
export type Result<T> = { ok: true; value: T } | { ok: false; code: string; message: string; msg: Msg };

export const fail = (code: string, msg: Msg): { ok: false; code: string; message: string; msg: Msg } => ({
  ok: false,
  code,
  message: formatMsg(msg),
  msg,
});

// ─── 경로 ────────────────────────────────────────────────────────────────

const SEGMENT = /^[A-Za-z_][A-Za-z0-9_]*$/;

/** `$a.b.A` → ['a','b','A']. 변수 경로로 유효하지 않으면 null (`$` 단독 포함). */
export function parsePath(path: unknown): string[] | null {
  if (typeof path !== 'string' || !path.startsWith('$')) return null;
  const segs = path.slice(1).split('.');
  return segs.every((s) => SEGMENT.test(s)) ? segs : null;
}

export const isValidPath = (path: unknown): path is string => parsePath(path) !== null;

/** 접두어(그룹 또는 변수 경로). 루트 `$`도 허용한다. */
export const isValidPrefix = (prefix: unknown): prefix is string => prefix === '$' || isValidPath(prefix);

/** `path`가 `prefix` 자신이거나 그 하위인가 */
export const inSubtree = (path: string, prefix: string): boolean =>
  prefix === '$' || path === prefix || path.startsWith(prefix + '.');

export const joinPath = (prefix: string, relative: string): string =>
  prefix === '$' ? '$' + relative : `${prefix}.${relative}`;

/** `$a.b.A` → ['$a', '$a.b'] (자기 자신 제외) */
export function ancestorsOf(path: string): string[] {
  const segs = path.slice(1).split('.');
  return segs.slice(0, -1).map((_, i) => '$' + segs.slice(0, i + 1).join('.'));
}

/** 경로 집합에서 변수/그룹이 겹치는 경로(어떤 변수의 하위에 또 다른 변수가 있는 경우)를 찾는다. 없으면 null. */
export function findPathConflict(paths: string[]): string | null {
  const set = new Set(paths);
  for (const p of paths) if (ancestorsOf(p).some((a) => set.has(a))) return p;
  return null;
}

/**
 * 명시적 그룹(`groups`)이 변수와 겹치는 경로를 찾는다. 그룹이 변수 경로와 같거나 변수의 하위이면 겹침이다.
 * 변수가 그룹 아래에 있는 것은 정상이다. 없으면 null.
 */
export function findGroupConflict(variablePaths: string[], groups: string[]): string | null {
  const vars = new Set(variablePaths);
  return groups.find((g) => vars.has(g) || ancestorsOf(g).some((a) => vars.has(a))) ?? null;
}

/** 존재하는 모든 그룹: 명시적 그룹, 변수 경로의 상위, 명시적 그룹의 상위. 정렬됨. */
export function listGroups(registry: Registry, groups: string[] = []): string[] {
  return [...new Set([...Object.keys(registry).flatMap(ancestorsOf), ...groups, ...groups.flatMap(ancestorsOf)])].sort();
}

// ─── 값 ──────────────────────────────────────────────────────────────────

/** 타입별 검증과 정규화. bytes는 공백 제거·소문자, int는 정규형 10진 문자열. */
export function validateValue(type: VariableType, value: unknown): Result<VariableValue> {
  switch (type) {
    case 'bytes': {
      if (typeof value !== 'string') return fail('INVALID_VALUE', tmsg('errors:variable.bytesNotHex'));
      const r = validateHexInput(value, { allowEmpty: true });
      return r.isValid ? { ok: true, value: r.cleanHex.toLowerCase() } : fail('INVALID_VALUE', r.errorMsg ?? tmsg('errors:variable.hexInvalid'));
    }
    case 'string':
      return typeof value === 'string' ? { ok: true, value } : fail('INVALID_VALUE', tmsg('errors:variable.stringNotString'));
    case 'int': {
      const s = typeof value === 'number' && Number.isSafeInteger(value) ? String(value) : typeof value === 'string' ? value.trim() : '';
      return /^-?[0-9]+$/.test(s) ? { ok: true, value: BigInt(s).toString() } : fail('INVALID_VALUE', tmsg('errors:variable.intNotDecimal'));
    }
    case 'bool':
      return typeof value === 'boolean' ? { ok: true, value } : fail('INVALID_VALUE', tmsg('errors:variable.boolNotBool'));
    default:
      return fail('INVALID_TYPE', tmsg('errors:variable.unknownType', { type: String(type) }));
  }
}

/** 유효 값 = current ?? default (D-03) */
export const effectiveValue = (entry: VariableEntry): VariableValue => entry.current ?? entry.default;

/** 외부 입력(파일·저장값)을 항목으로 검증·정규화한다. name/description은 없으면 빈 문자열. */
export function normalizeEntry(raw: unknown): Result<VariableEntry> {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return fail('INVALID_VALUE', tmsg('errors:variable.entryNotObject'));
  const r = raw as Record<string, unknown>;
  if (!VARIABLE_TYPES.includes(r.type as VariableType)) return fail('INVALID_TYPE', tmsg('errors:variable.unknownType', { type: String(r.type) }));
  const type = r.type as VariableType;
  if (r.default === undefined) return fail('INVALID_VALUE', tmsg('errors:variable.defaultRequired'));
  const def = validateValue(type, r.default);
  if (!def.ok) return fail(def.code, tmsg('errors:variable.fieldPrefix', { field: 'default', detail: def.msg }));
  const entry: VariableEntry = { name: typeof r.name === 'string' ? r.name : '', type, default: def.value, description: '' };
  if (r.current !== undefined) {
    const cur = validateValue(type, r.current);
    if (!cur.ok) return fail(cur.code, tmsg('errors:variable.fieldPrefix', { field: 'current', detail: cur.msg }));
    entry.current = cur.value;
  }
  if (typeof r.description === 'string') entry.description = r.description;
  return { ok: true, value: entry };
}

// ─── 조작 ────────────────────────────────────────────────────────────────

/** 새 경로 `path`가 `rest`(레지스트리)의 변수/그룹 배타 규칙을 지키는지 확인한다. */
function checkExclusive(rest: Registry, path: string, groups: string[] = []): Result<null> {
  if (ancestorsOf(path).some((a) => a in rest)) return fail('PATH_CONFLICT', tmsg('errors:variable.parentIsVariable', { path }));
  if (Object.keys(rest).some((k) => k.startsWith(path + '.')) || groups.some((g) => g === path || g.startsWith(path + '.'))) {
    return fail('PATH_CONFLICT', tmsg('errors:variable.groupHasVariables', { path }));
  }
  return { ok: true, value: null };
}

/** 그룹(폴더)을 만든다. 상위 그룹은 따로 만들지 않아도 함께 존재한다. 이미 있는 그룹이면 실패한다. */
export function addGroup(registry: Registry, groups: string[], path: string): Result<string[]> {
  if (!isValidPath(path)) return fail('INVALID_PATH', tmsg('errors:variable.invalidPath', { path }));
  if (path in registry) return fail('PATH_CONFLICT', tmsg('errors:variable.sameNameVariable', { path }));
  if (ancestorsOf(path).some((a) => a in registry)) return fail('PATH_CONFLICT', tmsg('errors:variable.parentIsVariable', { path }));
  if (listGroups(registry, groups).includes(path)) return fail('PATH_EXISTS', tmsg('errors:variable.groupExists', { path }));
  return { ok: true, value: [...groups, path] };
}

export function addVariable(registry: Registry, path: string, entry: unknown, groups: string[] = []): Result<Registry> {
  if (!isValidPath(path)) return fail('INVALID_PATH', tmsg('errors:variable.invalidPath', { path }));
  if (path in registry) return fail('PATH_EXISTS', tmsg('errors:variable.variableExists', { path }));
  const ex = checkExclusive(registry, path, groups);
  if (!ex.ok) return ex;
  const e = normalizeEntry(entry);
  if (!e.ok) return e;
  return { ok: true, value: { ...registry, [path]: e.value } };
}

export interface VariablePatch {
  name?: string;
  type?: VariableType;
  default?: VariableValue;
  /** null이면 current를 지워 "default 사용 중"으로 되돌린다. */
  current?: VariableValue | null;
  description?: string;
}

/** 타입을 바꾸면 default/current를 새 타입으로 다시 검증한다(통과하지 못하면 실패). */
export function updateVariable(registry: Registry, path: string, patch: VariablePatch): Result<Registry> {
  const old = registry[path];
  if (!old) return fail('NOT_FOUND', tmsg('errors:variable.noSuchVariable', { path }));
  const merged: Record<string, unknown> = { ...old, ...patch };
  if (patch.current === null) delete merged.current;
  const e = normalizeEntry(merged);
  if (!e.ok) return e;
  return { ok: true, value: { ...registry, [path]: e.value } };
}

/** 변수 하나(상위 그룹은 남는다), 또는 그룹이면 그 아래의 변수와 하위 그룹 전부를 지운다. */
export function removeSubtree(
  registry: Registry,
  prefix: string,
  groups: string[] = [],
): Result<{ registry: Registry; groups: string[]; removed: string[] }> {
  if (!isValidPrefix(prefix)) return fail('INVALID_PATH', tmsg('errors:variable.invalidPath', { path: prefix }));
  const removed = Object.keys(registry).filter((k) => inSubtree(k, prefix));
  const keptGroups = groups.filter((g) => !inSubtree(g, prefix));
  if (removed.length === 0 && keptGroups.length === groups.length) return fail('NOT_FOUND', tmsg('errors:variable.noSuchPath', { path: prefix }));
  const next = { ...registry };
  for (const k of removed) delete next[k];
  return { ok: true, value: { registry: next, groups: keptGroups, removed } };
}

/**
 * `from`(변수 또는 그룹)을 `to` 경로로 옮긴다. 그룹이면 하위 변수와 하위 그룹이 함께 옮겨진다.
 * 그룹끼리 합치지 않으며 하나라도 실패하면 아무것도 바꾸지 않는다. `moved`는 변수의 이전 경로 → 새 경로.
 */
export function moveSubtree(
  registry: Registry,
  from: string,
  to: string,
  groups: string[] = [],
): Result<{ registry: Registry; groups: string[]; moved: Record<string, string> }> {
  if (!isValidPath(from) || !isValidPath(to)) return fail('INVALID_PATH', tmsg('errors:variable.invalidPath', { path: isValidPath(from) ? to : from }));
  const keys = Object.keys(registry).filter((k) => inSubtree(k, from));
  const movedGroups = groups.filter((g) => inSubtree(g, from));
  if (keys.length === 0 && movedGroups.length === 0) return fail('NOT_FOUND', tmsg('errors:variable.noSuchPath', { path: from }));
  if (to === from) return { ok: true, value: { registry, groups, moved: {} } };
  if (to.startsWith(from + '.')) return fail('MOVE_INTO_SELF', tmsg('errors:variable.moveIntoSelf', { to }));

  const rest: Registry = { ...registry };
  const moved: Record<string, string> = {};
  for (const k of keys) {
    delete rest[k];
    moved[k] = to + k.slice(from.length);
  }
  const restGroups = groups.filter((g) => !inSubtree(g, from));
  if (Object.keys(rest).some((k) => inSubtree(k, to)) || restGroups.some((g) => inSubtree(g, to))) {
    return fail('TARGET_EXISTS', tmsg('errors:variable.pathExists', { to }));
  }
  const ex = checkExclusive(rest, to, []);
  if (!ex.ok) return ex;

  for (const k of keys) rest[moved[k]] = registry[k];
  return { ok: true, value: { registry: rest, groups: [...restGroups, ...movedGroups.map((g) => to + g.slice(from.length))], moved } };
}

// ─── 조회 ────────────────────────────────────────────────────────────────

export interface ChildNode {
  path: string;
  /** 경로의 마지막 구간 */
  name: string;
  kind: 'group' | 'variable';
}

/** `prefix` 바로 아래 항목(변수, 그룹 — 빈 그룹 포함). 그룹 먼저, 이름순. */
export function listChildren(registry: Registry, prefix: string, groups: string[] = []): ChildNode[] {
  const skip = prefix === '$' ? 1 : prefix.length + 1;
  const children = new Map<string, ChildNode>();
  const visit = (path: string, isGroup: boolean) => {
    if (path === prefix || !inSubtree(path, prefix)) return;
    const rest = path.slice(skip);
    const name = rest.split('.')[0];
    const childPath = joinPath(prefix, name);
    const kind = isGroup || rest.includes('.') ? 'group' : 'variable';
    if (!children.has(childPath) || kind === 'group') children.set(childPath, { path: childPath, name, kind });
  };
  Object.keys(registry).forEach((k) => visit(k, false));
  groups.forEach((g) => visit(g, true));
  return [...children.values()].sort((a, b) => (a.kind === b.kind ? a.name.localeCompare(b.name) : a.kind === 'group' ? -1 : 1));
}

/** 경로·이름·설명 부분 일치(대소문자 무시). 빈 키워드는 전부. */
export function search(registry: Registry, keyword: string, opts: { type?: VariableType } = {}): Array<{ path: string; entry: VariableEntry }> {
  const kw = keyword.trim().toLowerCase();
  return Object.keys(registry)
    .sort()
    .filter((p) => !opts.type || registry[p].type === opts.type)
    .filter((p) => !kw || [p, registry[p].name, registry[p].description].some((s) => s.toLowerCase().includes(kw)))
    .map((path) => ({ path, entry: registry[path] }));
}
