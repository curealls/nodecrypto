/**
 * 워크플로우가 쓰는 변수 수집과 상태 계산 (UI·localStorage 비의존)
 *
 * 규격: ui-canvas-spec.md §15.4, value-registry.md §5.3
 */
import type { NodeDefinition } from '../dag/types';
import { Registry, VariableType, VariableValue, effectiveValue, inSubtree } from './registry';
import { collectRefs, isVarRef, resolveRef, slotsFor } from './reference';
import { Msg, tmsg } from '../messages';

/** 심각한 순서의 반대로 나열한다(앞쪽이 덜 심각). */
export type UsageStatus = 'ok' | 'default' | 'invalid_value' | 'type_mismatch' | 'unregistered';
const SEVERITY: UsageStatus[] = ['ok', 'default', 'invalid_value', 'type_mismatch', 'unregistered'];

export const STATUS_LABEL: Record<UsageStatus, Msg> = {
  ok: tmsg('errors:variable.status.ok'),
  default: tmsg('errors:variable.status.default'),
  invalid_value: tmsg('errors:variable.status.invalid_value'),
  type_mismatch: tmsg('errors:variable.status.type_mismatch'),
  unregistered: tmsg('errors:variable.status.unregistered'),
};

export const STATUS_ORDER: readonly UsageStatus[] = [...SEVERITY].reverse();

export interface UsageSite {
  nodeId: string;
  nodeLabel: string;
  /** 필드 id, 또는 ValueSet 행이면 `rows.<포트 id>` */
  slot: string;
  /** 필드 라벨(ValueSet 행은 포트 이름) */
  slotLabel: string;
  type: VariableType;
  status: UsageStatus;
}

export interface UsedVariable {
  path: string;
  /** 사용처가 요구하는 타입(중복 제거) */
  types: VariableType[];
  sites: UsageSite[];
  /** 사용처 중 가장 심각한 상태 */
  status: UsageStatus;
  /** 등록되어 있을 때의 유효 값 */
  value?: VariableValue;
  /** 등록된 변수의 타입 */
  registeredType?: VariableType;
}

export interface UsageNode {
  id: string;
  type?: string;
  data: { label?: string; nodeType?: string; type?: string; properties?: Record<string, any>; outputs?: Array<{ id: string; name?: string; dataType: string }> };
}

type UsageDef = Pick<NodeDefinition, 'propertySchema' | 'rowValueRefs'>;

function siteStatus(path: string, type: VariableType, allowEmpty: boolean, registry: Registry): UsageStatus {
  const e = registry[path];
  if (!e) return 'unregistered';
  if (e.type !== type) return 'type_mismatch';
  const r = resolveRef(path, { label: '', type, allowEmpty }, { [path]: { type: e.type, value: effectiveValue(e) } });
  if (!r.ok) return 'invalid_value';
  return e.current === undefined ? 'default' : 'ok';
}

/**
 * 노드 목록에서 모든 참조를 모아 변수별 사용처와 상태를 계산한다. 숨겨진 필드의 참조도 센다(D-17).
 * 참조를 둘 수 없는 자리의 참조는 해석에서도 무시되므로 세지 않는다. 경로순으로 돌려준다.
 */
export function collectUsage(nodes: UsageNode[], getDef: (type: string) => UsageDef | undefined, registry: Registry): UsedVariable[] {
  const byPath = new Map<string, UsedVariable>();
  for (const n of nodes) {
    const refs = collectRefs(n.data.properties);
    if (refs.length === 0) continue;
    const outputs = (n.data.outputs ?? []).map((p) => ({ id: p.id, name: p.name ?? p.id, dataType: p.dataType }));
    const slots = slotsFor(getDef(n.data.nodeType || n.data.type || n.type || ''), outputs);
    for (const ref of refs) {
      const slot = ref.slot.startsWith('rows.') ? slots.rows[ref.slot.slice(5)] : slots.fields[ref.slot];
      if (!slot) continue;
      const used = byPath.get(ref.path) ?? { path: ref.path, types: [], sites: [], status: 'ok' as UsageStatus };
      const status = siteStatus(ref.path, slot.type, slot.allowEmpty, registry);
      used.sites.push({ nodeId: n.id, nodeLabel: n.data.label || n.id, slot: ref.slot, slotLabel: slot.label, type: slot.type, status });
      if (!used.types.includes(slot.type)) used.types.push(slot.type);
      if (SEVERITY.indexOf(status) > SEVERITY.indexOf(used.status)) used.status = status;
      byPath.set(ref.path, used);
    }
  }
  for (const u of byPath.values()) {
    const e = registry[u.path];
    if (e) {
      u.value = effectiveValue(e);
      u.registeredType = e.type;
    }
  }
  return [...byPath.values()].sort((a, b) => a.path.localeCompare(b.path));
}

/** 변수의 사용처를 노드 단위로 중복 없이(처음 나온 순서) 돌려준다. */
export const usedNodeIds = (u: UsedVariable): string[] => [...new Set(u.sites.map((s) => s.nodeId))];

// ─── 이동·이름 변경·삭제의 영향 (ui-canvas-spec.md §15.7) ────────────────

export interface NodeRefCount {
  nodeId: string;
  nodeLabel: string;
  count: number;
}

/** `prefix`(자신 또는 하위) 변수를 참조하는 노드와 참조 개수. 노드 순서대로. */
export function usagesUnder(nodes: UsageNode[], prefix: string): NodeRefCount[] {
  const out: NodeRefCount[] = [];
  for (const n of nodes) {
    const count = collectRefs(n.data.properties).filter((r) => inSubtree(r.path, prefix)).length;
    if (count > 0) out.push({ nodeId: n.id, nodeLabel: n.data.label || n.id, count });
  }
  return out;
}

export interface TabRefUsage {
  tabId: string;
  title: string;
  nodes: NodeRefCount[];
  total: number;
}

/** 열린 모든 탭의 사용처. 활성 탭은 캔버스의 노드를 쓴다. 참조가 없는 탭은 뺀다. */
export function tabUsagesUnder(
  tabs: Array<{ id: string; title: string; nodes: UsageNode[] }>,
  activeTabId: string,
  activeNodes: UsageNode[],
  prefix: string,
): TabRefUsage[] {
  return tabs
    .map((t) => {
      const nodes = usagesUnder(t.id === activeTabId ? activeNodes : t.nodes, prefix);
      return { tabId: t.id, title: t.title, nodes, total: nodes.reduce((a, n) => a + n.count, 0) };
    })
    .filter((t) => t.total > 0);
}

/**
 * `from` 접두어 아래 변수의 참조를 `to` 아래로 바꾼 새 노드 목록. 입력은 바꾸지 않고, 바뀌지 않은 노드는 그대로 돌려준다.
 * 노드 `properties`만 바꾼다(필드와 ValueSet 행).
 */
export function rewriteReferences<N extends { data: { properties?: Record<string, any> } }>(nodes: N[], from: string, to: string): N[] {
  const map = (v: any) => (isVarRef(v) && inSubtree(v.$var, from) ? { $var: to + v.$var.slice(from.length) } : v);
  return nodes.map((n) => {
    const props = n.data.properties;
    if (!props || !collectRefs(props).some((r) => inSubtree(r.path, from))) return n;
    const next: Record<string, any> = {};
    for (const [k, v] of Object.entries(props)) next[k] = map(v);
    const rows = props.rows;
    if (rows && typeof rows === 'object' && !Array.isArray(rows)) {
      next.rows = Object.fromEntries(Object.entries<any>(rows).map(([id, row]) => [id, row && isVarRef(row.value) ? { ...row, value: map(row.value) } : row]));
    }
    return { ...n, data: { ...n.data, properties: next } };
  });
}
