import { tmsg } from '../messages';
/**
 * 레지스트리 파일 직렬화 (내보내기·가져오기)
 *
 * 규격: value-registry.md §7
 */
import {
  Registry,
  Result,
  ancestorsOf,
  findGroupConflict,
  listGroups,
  VariableEntry,
  fail,
  findPathConflict,
  inSubtree,
  isValidPrefix,
  joinPath,
  normalizeEntry,
  parsePath,
} from './registry';

export const REGISTRY_FILE_FORMAT = 'nodecrypto-values';
export const REGISTRY_FILE_VERSION = 1;

export interface RegistryFile {
  format: typeof REGISTRY_FILE_FORMAT;
  formatVersion: number;
  /** 명시적 그룹의 `$` 없는 상대 경로(빈 그룹 포함). 없을 수 있다. */
  groups: string[];
  /** `$` 없는 점 구분 상대 경로 → 항목 */
  variables: Record<string, VariableEntry>;
}

/**
 * 전체(`$`) 또는 하위 경로를 내보낸다. 경로는 내보낸 노드의 부모 기준 상대 경로이다.
 * `$a.b`의 `$a.b.c.A`는 `b.c.A`, 전체 내보내기의 `$a.b.A`는 `a.b.A`.
 */
export function exportRegistry(registry: Registry, prefix = '$', groups: string[] = []): RegistryFile {
  const parentLen = prefix === '$' ? 1 : prefix.lastIndexOf('.') + 1 || 1;
  const variables: RegistryFile['variables'] = {};
  for (const path of Object.keys(registry).sort()) {
    if (inSubtree(path, prefix)) variables[path.slice(parentLen)] = { ...registry[path] };
  }
  const outGroups = groups.filter((g) => inSubtree(g, prefix)).map((g) => g.slice(parentLen)).sort();
  return { format: REGISTRY_FILE_FORMAT, formatVersion: REGISTRY_FILE_VERSION, groups: outGroups, variables };
}

/** 파일 내용을 §7.3의 순서로 검증한다. 처음 실패한 항목의 오류 코드와 경로를 돌려준다. */
export function parseRegistryFile(input: unknown): Result<RegistryFile> {
  let raw = input;
  if (typeof input === 'string') {
    try {
      raw = JSON.parse(input);
    } catch {
      return fail('VREG_UNSUPPORTED_FORMAT', tmsg('errors:variable.file.notJson'));
    }
  }
  const f = raw as Record<string, unknown> | null;
  if (typeof f !== 'object' || f === null || f.format !== REGISTRY_FILE_FORMAT) {
    return fail('VREG_UNSUPPORTED_FORMAT', tmsg('errors:variable.file.wrongFormat', { REGISTRY_FILE_FORMAT }));
  }
  if (f.formatVersion !== REGISTRY_FILE_VERSION) {
    return fail('VREG_UNSUPPORTED_VERSION', tmsg('errors:variable.file.unsupportedVersion', { version: String(f.formatVersion) }));
  }
  const vars = f.variables;
  if (typeof vars !== 'object' || vars === null || Array.isArray(vars)) {
    return fail('VREG_INVALID_VALUE', tmsg('errors:variable.file.variablesNotObject'));
  }

  const rawGroups = f.groups === undefined ? [] : f.groups;
  if (!Array.isArray(rawGroups) || rawGroups.some((g) => typeof g !== 'string')) {
    return fail('VREG_INVALID_PATH', tmsg('errors:variable.file.groupsNotArray'));
  }
  const groups = rawGroups as string[];
  const rels = Object.keys(vars);
  for (const rel of [...rels, ...groups]) {
    if (rel.includes('$') || !parsePath('$' + rel)) return fail('VREG_INVALID_PATH', tmsg('errors:variable.invalidPath', { path: rel }));
  }
  const conflict = findPathConflict(rels.map((r) => '$' + r)) ?? findGroupConflict(rels.map((r) => '$' + r), groups.map((g) => '$' + g));
  if (conflict) return fail('VREG_PATH_CONFLICT', tmsg('errors:variable.file.pathConflict', { path: conflict.slice(1) }));

  const variables: RegistryFile['variables'] = {};
  for (const rel of rels) {
    const e = normalizeEntry((vars as Record<string, unknown>)[rel]);
    if (!e.ok) return fail('VREG_INVALID_VALUE', tmsg('errors:variable.fieldPrefix', { field: rel, detail: e.msg }));
    variables[rel] = e.value;
  }
  return { ok: true, value: { format: REGISTRY_FILE_FORMAT, formatVersion: REGISTRY_FILE_VERSION, groups: [...new Set(groups)], variables } };
}

// ─── 가져오기 ────────────────────────────────────────────────────────────

export type ImportStatus = 'new' | 'conflict' | 'overlap';

export interface ImportItem {
  /** 대상 경로를 붙인 전체 경로 */
  path: string;
  entry: VariableEntry;
  /** new: 비어 있음, conflict: 같은 경로에 변수가 있음, overlap: 기존 변수와 그룹으로 맞물림(덮어쓸 수 없음) */
  status: ImportStatus;
}

export interface ImportGroupItem {
  path: string;
  /** new: 등록, exists: 이미 있는 그룹, overlap: 기존 변수와 겹침(건너뜀) */
  status: 'new' | 'exists' | 'overlap';
}

export interface ImportPlan {
  base: Registry;
  baseGroups: string[];
  items: ImportItem[];
  groupItems: ImportGroupItem[];
  /** 변수 기준 개수 */
  counts: Record<ImportStatus, number>;
}

export function planImport(registry: Registry, file: RegistryFile, targetPrefix: string, groups: string[] = []): Result<ImportPlan> {
  if (!isValidPrefix(targetPrefix)) return fail('INVALID_PATH', tmsg('errors:variable.file.invalidTarget', { path: targetPrefix }));
  const keys = Object.keys(registry);
  const existingGroups = listGroups(registry, groups);
  const counts: ImportPlan['counts'] = { new: 0, conflict: 0, overlap: 0 };
  const items = Object.entries(file.variables).map(([rel, entry]): ImportItem => {
    const path = joinPath(targetPrefix, rel);
    const status: ImportStatus = path in registry
      ? 'conflict'
      : keys.some((k) => path.startsWith(k + '.') || k.startsWith(path + '.')) || groups.some((g) => g === path || g.startsWith(path + '.'))
        ? 'overlap'
        : 'new';
    counts[status]++;
    return { path, entry, status };
  });
  const groupItems = (file.groups ?? []).map((rel): ImportGroupItem => {
    const path = joinPath(targetPrefix, rel);
    const blocked = path in registry || ancestorsOf(path).some((a) => a in registry);
    return { path, status: blocked ? 'overlap' : existingGroups.includes(path) ? 'exists' : 'new' };
  });
  return { ok: true, value: { base: registry, baseGroups: groups, items, groupItems, counts } };
}

/** 신규는 항상 등록한다. 충돌은 정책(덮어쓰기/건너뛰기)을 따르고, 겹침은 항상 건너뛴다. 취소는 호출하지 않는 것이다. */
export function applyImport(plan: ImportPlan, policy: 'overwrite' | 'skip'): { registry: Registry; groups: string[] } {
  const registry = { ...plan.base };
  for (const { path, entry, status } of plan.items) {
    if (status === 'new' || (status === 'conflict' && policy === 'overwrite')) registry[path] = { ...entry };
  }
  const groups = [...plan.baseGroups, ...plan.groupItems.filter((g) => g.status === 'new').map((g) => g.path)];
  return { registry, groups: [...new Set(groups)] };
}
