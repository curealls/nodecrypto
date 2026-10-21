/**
 * Package file build/validate (pure, no UI). Rules: package-format.md §2, §4, §6.1.
 */

import {
  CustomNodeDefinition,
  CustomNodeManifest,
  CUSTOM_NODE_PREFIX,
  WORKFLOW_INPUT,
  WORKFLOW_OUTPUT,
  canonicalize,
  collectDefinitionClosure,
  computeDefinitionId,
  deriveInterface,
  nodeTypeOf,
  referencedDefinitionIds,
  shortId,
} from './customNode';
import { defaultNodeRegistry } from '../registry/nodeRegistry';
import { VariableEntry, findPathConflict, normalizeEntry, parsePath } from '../variables/registry';
import { collectRefs, definitionHasRef } from '../variables/reference';
import { Msg, formatMsg, tmsg } from '../messages';

export const PACKAGE_FORMAT = 'nodecrypto';
export const PACKAGE_FORMAT_VERSION = 1;
/** 본문에 변수 참조가 있는 파일의 형식 버전 (package-format.md §2.3). 읽기 측은 1과 2를 받는다. */
export const PACKAGE_FORMAT_VERSION_VARIABLES = 2;

export type PackageMeta = Pick<CustomNodeManifest, 'label' | 'version' | 'description' | 'category'>;

export interface PackageWorkflow {
  nodes: any[];
  edges: any[];
  [key: string]: any;
}

export interface NodePackage {
  format: string;
  formatVersion: number;
  protection: string;
  manifest: CustomNodeManifest;
  requires: string[];
  workflow: PackageWorkflow;
  definitions: Record<string, CustomNodeDefinition>;
  /** 변수 동봉(B) 파일만 가진다. 절대 경로 → 항목 (§2.5) */
  variables?: Record<string, VariableEntry>;
}

export type PackageErrorCode =
  | 'PKG_UNSUPPORTED_FORMAT' | 'PKG_UNSUPPORTED_VERSION' | 'PKG_UNSUPPORTED_PROTECTION'
  | 'PKG_MISSING_DEFINITION' | 'PKG_DEFINITION_CYCLE' | 'PKG_HASH_MISMATCH'
  | 'PKG_UNKNOWN_NODE_TYPE' | 'PKG_INTERFACE_MISMATCH' | 'PKG_REQUIRES_MISMATCH'
  | 'PKG_DEFINITION_HAS_VARIABLE' | 'PKG_INVALID_VARIABLES' | 'PKG_MISSING_VARIABLE';

export interface PackageError { code: PackageErrorCode; message: string; msg: Msg }

/** package-format.md §2.2: tokens declared by standard nodes in the body and every definition, deduped and sorted. */
function computeRequires(workflows: { nodes: any[] }[]): string[] {
  const tokens = new Set<string>();
  for (const w of workflows) {
    for (const n of w.nodes) {
      const t = nodeTypeOf(n);
      if (typeof t === 'string' && !t.startsWith(CUSTOM_NODE_PREFIX)) {
        defaultNodeRegistry.get(t)?.requires?.forEach((r) => tokens.add(r));
      }
    }
  }
  return [...tokens].sort();
}

/** package-format.md §2.1 / §6.3: a body with neither Workflow Input nor Workflow Output cannot become a node. */
export const canRegisterAsNode = (pkg: NodePackage): boolean =>
  pkg.workflow.nodes.some((n) => [WORKFLOW_INPUT, WORKFLOW_OUTPUT].includes(nodeTypeOf(n)));

const RUN_STATE_KEYS = new Set(['inputValues', 'outputValues', 'executionState', 'errorMessage', 'errorCode', 'executionDurationMs']);

/** Run results are not saved (D-08); also keeps out values JSON can't carry (a script's bigint int output). */
const dropRunState = <T>(v: T): T => JSON.parse(JSON.stringify(v, (k, x) => (RUN_STATE_KEYS.has(k) ? undefined : x)));

/** Test-run values in Workflow Input are not saved either (D-08). */
const clearTestInputs = (nodes: any[]): any[] =>
  nodes.map((n) => (nodeTypeOf(n) === WORKFLOW_INPUT ? { ...n, data: { ...n.data, properties: {} } } : n));

/** Top-level keys React Flow sets while editing (selection, drag, measured size). The file carries them but they are not edits. */
const dropTransient = ({ selected, dragging, resizing, measured, positionAbsolute, ...rest }: any) => rest;

/**
 * Text that is equal exactly when two canvases would save the same content (ui-canvas-spec.md §16.4):
 * the saved body rules (no run results, empty Workflow Input values) without transient editing keys or the viewport.
 */
export function contentSignature(nodes: any[], edges: any[]): string {
  const body = dropRunState({ nodes, edges });
  return JSON.stringify({ nodes: clearTestInputs(body.nodes).map(dropTransient), edges: body.edges.map(dropTransient) });
}

/**
 * Build the envelope. `resolve` finds a definition by id (pool, tab-embedded, session — caller's order).
 * A body that still holds references is version 2 (value-registry.md §8.6); the caller adds `variables` for mode B.
 */
export function buildPackage(
  workflow: PackageWorkflow,
  meta: PackageMeta,
  resolve: (id: string) => CustomNodeDefinition | undefined
): NodePackage {
  // Run results and test-run values are not part of the package (D-08), same as saving as a node.
  const body: PackageWorkflow = dropRunState(workflow);
  body.nodes = clearTestInputs(body.nodes);
  const pool: Record<string, CustomNodeDefinition> = {};
  const stack = referencedDefinitionIds(body.nodes);
  while (stack.length) {
    const id = stack.pop()!;
    if (pool[id]) continue;
    const def = resolve(id);
    if (!def) continue;
    pool[id] = def;
    stack.push(...referencedDefinitionIds(def.workflow.nodes));
  }
  const definitions = JSON.parse(JSON.stringify(collectDefinitionClosure(Object.keys(pool), pool)));
  const hasRefs = body.nodes.some((n) => collectRefs(n?.data?.properties).length > 0);
  return {
    format: PACKAGE_FORMAT,
    formatVersion: hasRefs ? PACKAGE_FORMAT_VERSION_VARIABLES : PACKAGE_FORMAT_VERSION,
    protection: 'public',
    manifest: { ...meta, ...deriveInterface(body.nodes) },
    requires: computeRequires([body, ...Object.values<CustomNodeDefinition>(definitions).map((d) => d.workflow)]),
    workflow: body,
    definitions,
  };
}

/** package-format.md §6.1. Returns the first failure, or null. Never registers or trusts file contents. */
export function validatePackage(json: any, knownTypes: ReadonlySet<string>): PackageError | null {
  const fail = (code: PackageErrorCode, msg: Msg): PackageError => ({ code, message: formatMsg(msg), msg });
  const isObj = (v: any) => v !== null && typeof v === 'object' && !Array.isArray(v);

  if (!isObj(json) || json.format !== PACKAGE_FORMAT) return fail('PKG_UNSUPPORTED_FORMAT', tmsg('errors:package.notPackage'));
  if (!Number.isInteger(json.formatVersion) || json.formatVersion > PACKAGE_FORMAT_VERSION_VARIABLES || json.formatVersion < 1) {
    return fail('PKG_UNSUPPORTED_VERSION', tmsg('errors:package.unsupportedVersion', { formatVersion: json.formatVersion }));
  }
  if (json.protection !== 'public') return fail('PKG_UNSUPPORTED_PROTECTION', tmsg('errors:package.unsupportedProtection', { protection: json.protection }));

  const wellFormed = (w: any) => isObj(w) && Array.isArray(w.nodes) && Array.isArray(w.edges);
  const defs: Record<string, CustomNodeDefinition> = json.definitions;
  if (!wellFormed(json.workflow) || !isObj(json.manifest) || !isObj(defs) || !Array.isArray(json.requires)
    || !Object.values(defs).every((d) => isObj(d) && isObj(d.manifest) && wellFormed(d.workflow))) {
    return fail('PKG_UNSUPPORTED_FORMAT', tmsg('errors:package.badStructure'));
  }
  const named = (id: string) => `${defs[id]?.manifest?.label ?? ''} (${shortId(id)})`;

  // 4. every referenced sha256: type is present
  for (const refs of [referencedDefinitionIds(json.workflow.nodes), ...Object.values(defs).map((d) => referencedDefinitionIds(d.workflow.nodes))]) {
    const missing = refs.find((r) => !defs[r]);
    if (missing) return fail('PKG_MISSING_DEFINITION', tmsg('errors:package.missingDefinition', { id: shortId(missing) }));
  }

  // 5. cycle check; the post-order is the "sub-definitions first" order for step 6
  const order: string[] = [];
  const state = new Map<string, 1 | 2>();
  let cycleAt: string | null = null;
  const visit = (id: string) => {
    if (cycleAt || state.get(id) === 2) return;
    if (state.get(id) === 1) { cycleAt = id; return; }
    state.set(id, 1);
    referencedDefinitionIds(defs[id].workflow.nodes).forEach(visit);
    state.set(id, 2);
    order.push(id);
  };
  Object.keys(defs).forEach(visit);
  if (cycleAt) return fail('PKG_DEFINITION_CYCLE', tmsg('errors:package.definitionCycle', { name: named(cycleAt) }));

  // 6. recomputed identifier equals the key
  for (const id of order) {
    if (computeDefinitionId(defs[id]) !== id) return fail('PKG_HASH_MISMATCH', tmsg('errors:package.hashMismatch', { name: named(id) }));
  }

  // 7. standard node types are known
  for (const [owner, w] of [[tmsg('errors:package.ownerBody'), json.workflow] as const, ...Object.keys(defs).map((id) => [named(id), defs[id].workflow] as const)]) {
    const bad = w.nodes.find((n: any) => {
      const t = nodeTypeOf(n);
      return typeof t !== 'string' || (!t.startsWith(CUSTOM_NODE_PREFIX) && !knownTypes.has(t));
    });
    if (bad) return fail('PKG_UNKNOWN_NODE_TYPE', tmsg('errors:package.unknownNodeType', { type: nodeTypeOf(bad), owner, id: bad.id }));
  }

  // 8. stored interface equals the derived one
  const sameInterface = (m: CustomNodeManifest, w: PackageWorkflow) =>
    canonicalize({ inputs: m.inputs, outputs: m.outputs }) === canonicalize(deriveInterface(w.nodes));
  if (!sameInterface(json.manifest, json.workflow)) return fail('PKG_INTERFACE_MISMATCH', tmsg('errors:package.bodyInterfaceMismatch'));
  for (const id of order) {
    if (!sameInterface(defs[id].manifest, defs[id].workflow)) return fail('PKG_INTERFACE_MISMATCH', tmsg('errors:package.interfaceMismatch', { name: named(id) }));
  }

  // 9. requires
  const expected = computeRequires([json.workflow, ...Object.values(defs).map((d) => d.workflow)]);
  if (canonicalize(expected) !== canonicalize(json.requires)) return fail('PKG_REQUIRES_MISMATCH', tmsg('errors:package.requiresMismatch', { expected: expected.join(', ') }));

  // 10. definitions never hold references (node-save always inlines them)
  for (const id of order) {
    if (definitionHasRef(defs[id])) return fail('PKG_DEFINITION_HAS_VARIABLE', tmsg('errors:package.definitionHasVariable', { name: named(id) }));
  }

  // 11~12. a closed file (has `variables`): entries are valid and every body reference is in it
  if (json.variables !== undefined) {
    const vars = json.variables;
    if (!isObj(vars)) return fail('PKG_INVALID_VARIABLES', tmsg('errors:package.variablesNotObject'));
    const paths = Object.keys(vars);
    const badPath = paths.find((p) => !parsePath(p));
    if (badPath) return fail('PKG_INVALID_VARIABLES', tmsg('errors:package.invalidVariablePath', { badPath }));
    const overlap = findPathConflict(paths);
    if (overlap) return fail('PKG_INVALID_VARIABLES', tmsg('errors:package.variablePathOverlap', { overlap }));
    for (const p of paths) {
      const e = normalizeEntry(vars[p]);
      if (!e.ok) return fail('PKG_INVALID_VARIABLES', tmsg('errors:variable.fieldPrefix', { field: p, detail: e.msg }));
    }
    for (const n of json.workflow.nodes) {
      const missing = collectRefs(n?.data?.properties).find((r) => !(r.path in vars));
      if (missing) return fail('PKG_MISSING_VARIABLE', tmsg('errors:package.missingVariable', { path: missing.path, id: n.id }));
    }
  }
  return null;
}
