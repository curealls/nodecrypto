/**
 * Design-time validation (node-catalog.md §2.2-8, ui-canvas-spec.md §13.5).
 * Judges a node by the dataType of the upstream output port each input is wired to.
 * Link nodes already mirror their source's type, so no special handling is needed.
 */

import type { DataType } from '../types';
import type { NodeDefinition } from './types';
import { VariableMap, hasRefs, resolveProperties, slotsFor } from '../variables/reference';
import { Msg, tmsg } from '../messages';

interface ValidatableNode {
  id: string;
  type?: string;
  data: { nodeType?: string; type?: string; label?: string; outputs?: { id: string; name?: string; dataType: DataType }[]; properties?: Record<string, any> };
}
interface ValidatableEdge { source: string; sourceHandle: string; target: string; targetHandle: string }

type DesignDef = Pick<NodeDefinition, 'validate' | 'propertySchema' | 'rowValueRefs'>;

/** Reason for variable references the given snapshot cannot resolve (value-registry.md §5.3), or null. */
function referenceError(node: ValidatableNode, def: DesignDef | undefined, variables: VariableMap): Msg | null {
  if (!hasRefs(node.data.properties)) return null;
  const r = resolveProperties(node.data.properties, slotsFor(def, (node.data.outputs ?? []).map((p) => ({ ...p, name: p.name ?? p.id }))), variables);
  if (r.ok) return null;
  return r.errors.length === 1 ? r.errors[0].msg : tmsg('errors:variable.unresolvedMany', { first: r.errors[0].msg, more: r.errors.length - 1 });
}

/**
 * Reason the node breaks its rules with the current connections, or null.
 * With `variables`, variable references that cannot be resolved against that snapshot count too (D-07).
 */
export function designErrorFor(
  nodeId: string,
  nodes: ValidatableNode[],
  edges: ValidatableEdge[],
  getDef: (type: string) => DesignDef | undefined,
  variables?: VariableMap
): Msg | null {
  const node = nodes.find((n) => n.id === nodeId);
  if (!node) return null;
  const def = getDef(node.data.nodeType || node.data.type || node.type || '');
  const refReason = variables ? referenceError(node, def, variables) : null;
  const validate = def?.validate;
  if (!validate) return refReason;

  const inputTypes: Record<string, DataType> = {};
  for (const e of edges) {
    if (e.target !== nodeId) continue;
    const t = nodes.find((n) => n.id === e.source)?.data.outputs?.find((p) => p.id === e.sourceHandle)?.dataType;
    if (t && t !== 'any') inputTypes[e.targetHandle] = t;
  }
  const reasons = [validate({ inputTypes }), refReason].filter((r): r is Msg => !!r);
  return reasons.length > 1 ? tmsg('errors:design.both', { a: reasons[0], b: reasons[1] }) : reasons[0] ?? null;
}

/** Every node that breaks its rules, with the reason (empty when the workflow is valid). Nodes keep their array order. */
export function designErrorList(
  nodes: ValidatableNode[],
  edges: ValidatableEdge[],
  getDef: (type: string) => DesignDef | undefined,
  variables?: VariableMap
): { id: string; label: string; reason: Msg }[] {
  const out: { id: string; label: string; reason: Msg }[] = [];
  for (const n of nodes) {
    const reason = designErrorFor(n.id, nodes, edges, getDef, variables);
    if (reason) out.push({ id: n.id, label: n.data.label || n.id, reason });
  }
  return out;
}

/** Every node that breaks its rules, as "label: reason" lines (empty when the workflow is valid). */
export function designErrors(
  nodes: ValidatableNode[],
  edges: ValidatableEdge[],
  getDef: (type: string) => DesignDef | undefined,
  variables?: VariableMap
): Msg[] {
  return designErrorList(nodes, edges, getDef, variables).map((e) => tmsg('errors:design.line', { label: e.label, reason: e.reason }));
}
