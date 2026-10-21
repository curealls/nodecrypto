/**
 * 워크플로우 저장 변환 (UI·localStorage 비의존)
 *
 * 규격: value-registry.md §8.1~8.3, §8.6, package-format.md §2.5
 */
import type { NodeDefinition } from '../dag/types';
import { Registry, VariableEntry, ancestorsOf, effectiveValue, listGroups } from './registry';
import { VariableMap, collectRefs, resolveProperties, slotsFor, toVariableMap } from './reference';
import { Msg, formatMsg, tmsg } from '../messages';

const asMsg = (msg: Msg) => ({ message: formatMsg(msg), msg });

type Def = Pick<NodeDefinition, 'propertySchema' | 'rowValueRefs'>;
type GetDef = (type: string) => Def | undefined;

interface WfNode {
  id: string;
  type?: string;
  data: { label?: string; nodeType?: string; type?: string; properties?: Record<string, any>; outputs?: Array<{ id: string; name?: string; dataType: string }> };
}
interface Wf {
  nodes: WfNode[];
  [key: string]: any;
}

/** 풀 수 없는 참조 하나. 메시지에는 변수 값을 담지 않는다(§5.3). */
export interface UnresolvedRef {
  nodeId: string;
  nodeLabel: string;
  path: string;
  message: string;
  /** Translatable form of `message` (i18n.md §6.2) */
  msg: Msg;
}

export type ExportResult<T> = ({ ok: true } & T) | { ok: false; errors: UnresolvedRef[] };

const defOf = (n: WfNode, getDef: GetDef) => getDef(n.data.nodeType || n.data.type || n.type || '');
const outputsOf = (n: WfNode) => (n.data.outputs ?? []).map((p) => ({ id: p.id, name: p.name ?? p.id, dataType: p.dataType }));

/** 저장 모달용: 참조 유무와 풀 수 없는 참조 목록(레지스트리 기준) */
export function refStatus(workflow: Wf, registry: Registry, getDef: GetDef): { hasRefs: boolean; unresolved: UnresolvedRef[] } {
  const hasRefs = workflowHasRefs(workflow);
  return { hasRefs, unresolved: hasRefs ? unresolvedRefs(workflow, toVariableMap(registry), getDef) : [] };
}

/** 본문의 풀 수 없는 참조를 모두 모은다(자리가 아닌 곳의 참조는 등록 여부만 본다). */
export function unresolvedRefs(workflow: Wf, variables: VariableMap, getDef: GetDef): UnresolvedRef[] {
  const out: UnresolvedRef[] = [];
  for (const n of workflow.nodes) {
    const nodeLabel = n.data.label || n.id;
    const r = resolveProperties(n.data.properties, slotsFor(defOf(n, getDef), outputsOf(n)), variables);
    const seen = new Set<string>();
    if (!r.ok) {
      for (const e of r.errors) {
        seen.add(e.slot);
        out.push({ nodeId: n.id, nodeLabel, path: e.path, ...asMsg(tmsg('errors:variable.exportRefError', { nodeLabel, detail: e.msg })) });
      }
    }
    for (const ref of collectRefs(n.data.properties)) {
      if (!seen.has(ref.slot) && !variables[ref.path]) {
        out.push({ nodeId: n.id, nodeLabel, path: ref.path, ...asMsg(tmsg('errors:variable.exportUnregistered', { nodeLabel, path: ref.path })) });
      }
    }
  }
  return out;
}

/** 본문에 참조가 하나라도 있는가 */
export const workflowHasRefs = (workflow: Wf): boolean => workflow.nodes.some((n) => collectRefs(n.data.properties).length > 0);

/** 본문이 참조하는 변수 경로(중복 제거, 정렬) */
export const referencedPaths = (workflow: Wf): string[] =>
  [...new Set(workflow.nodes.flatMap((n) => collectRefs(n.data.properties).map((r) => r.path)))].sort();

/** 모드 A: 모든 참조를 유효 값으로 바꾼 사본. 풀 수 없는 참조가 있으면 오류 목록. */
export function inlineReferences<W extends Wf>(workflow: W, variables: VariableMap, getDef: GetDef): ExportResult<{ workflow: W }> {
  const errors = unresolvedRefs(workflow, variables, getDef);
  if (errors.length) return { ok: false, errors };
  const copy = structuredClone(workflow);
  for (const n of copy.nodes) {
    if (collectRefs(n.data.properties).length === 0) continue;
    const r = resolveProperties(n.data.properties, slotsFor(defOf(n, getDef), outputsOf(n)), variables);
    if (r.ok) n.data.properties = r.properties;
  }
  return { ok: true, workflow: copy };
}

/**
 * 모드 B: 참조를 유지하고 사용된 변수만 절대 경로로 담는다.
 * `includeCurrent`가 거짓이면 current를 빼고 default만 담는다. 참조가 없으면 빈 객체이다.
 */
export function bundleVariables(
  workflow: Wf,
  registry: Registry,
  getDef: GetDef,
  { includeCurrent }: { includeCurrent: boolean }
): ExportResult<{ variables: Record<string, VariableEntry> }> {
  const errors = unresolvedRefs(workflow, toVariableMap(registry), getDef);
  if (errors.length) return { ok: false, errors };
  const variables: Record<string, VariableEntry> = {};
  for (const path of referencedPaths(workflow)) {
    const { name, type, default: def, current, description } = registry[path];
    variables[path] = includeCurrent && current !== undefined ? { name, type, default: def, current, description } : { name, type, default: def, description };
  }
  return { ok: true, variables };
}

// ─── B 파일을 열 때 (§8.4) ───────────────────────────────────────────────

export type BundleKind = 'new' | 'same' | 'diff' | 'typeDiff' | 'overlap';

export interface BundleItem {
  path: string;
  kind: BundleKind;
  entry: VariableEntry;
  /** 같은 경로에 이미 있는 변수 (new, overlap에는 없다) */
  existing?: VariableEntry;
}

/** 동봉된 변수를 레지스트리와 대조해 분류한다. 비교는 유효 값 기준이다. */
export function classifyBundle(bundled: Record<string, VariableEntry>, registry: Registry, groups: string[] = []): BundleItem[] {
  const allGroups = new Set(listGroups(registry, groups));
  return Object.keys(bundled).sort().map((path) => {
    const entry = bundled[path];
    const existing = registry[path];
    if (existing) {
      const kind = existing.type !== entry.type ? 'typeDiff' : effectiveValue(existing) === effectiveValue(entry) ? 'same' : 'diff';
      return { path, kind, entry, existing };
    }
    const overlap = allGroups.has(path) || ancestorsOf(path).some((a) => a in registry);
    return { path, kind: overlap ? 'overlap' : 'new', entry };
  });
}

/** 확정: 신규를 등록하고 `overwrite`에 든 경로(다른 값·타입 다름)를 파일 값으로 덮어쓴 레지스트리. 겹침이 있으면 호출하지 않는다. */
export function applyBundle(registry: Registry, items: BundleItem[], overwrite: ReadonlySet<string>): Registry {
  const next = { ...registry };
  for (const it of items) {
    if (it.kind === 'new' || ((it.kind === 'diff' || it.kind === 'typeDiff') && overwrite.has(it.path))) next[it.path] = it.entry;
  }
  return next;
}
