/**
 * User-defined (custom) nodes: content-hash identifiers and black-box sub-DAG execution.
 * Identifier rules: package-format.md §2.1, §2.4, §3.
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';
import { NodeDefinition, DAGEdgeConnection } from './types';
import { NodePortDefinition } from '../types';
import { DAGRunner } from './runner';
import { defaultNodeRegistry } from '../registry/nodeRegistry';
import { NodeError } from './errors';
import { SCRIPT_NODE_TYPE } from '../registry/definitions/scriptNode';
import { constraintSpec } from './portConstraint';
import { fixedErrorProfile } from '../registry/errorProfile';
import { definitionHasRef } from '../variables/reference';
import { withoutDocuments } from './documentNode';

export const WORKFLOW_INPUT = 'workflow-input';
export const WORKFLOW_OUTPUT = 'workflow-output';
export const CUSTOM_NODE_PREFIX = 'sha256:';

export interface CustomNodeManifest {
  label: string;
  version: string;
  description: string;
  category: string;
  inputs: NodePortDefinition[];
  outputs: NodePortDefinition[];
}

/** Definition entry (package-format.md §2.4). `workflow` keeps layout so edit mode can restore it. */
export interface CustomNodeDefinition {
  manifest: CustomNodeManifest;
  workflow: { nodes: any[]; edges: any[]; [key: string]: any };
}

export const nodeTypeOf = (n: any): string => n?.data?.nodeType || n?.data?.type;

/** package-format.md §2.1 interface derivation. */
export function deriveInterface(nodes: any[]): Pick<CustomNodeManifest, 'inputs' | 'outputs'> {
  const pick = (p: NodePortDefinition) => ({ id: p.id, name: p.name, dataType: p.dataType, description: p.description || undefined }); // '' is no description, so the id stays as without one
  const entry = nodes.find((n) => nodeTypeOf(n) === WORKFLOW_INPUT);
  const exit = nodes.find((n) => nodeTypeOf(n) === WORKFLOW_OUTPUT);
  return {
    // spec is the badge computed from the constraint; the constraint itself stays in the body (package-format.md §2.1)
    inputs: (entry?.data?.outputs || []).map((p: NodePortDefinition) => ({ ...pick(p), spec: constraintSpec(p), required: true })),
    outputs: (exit?.data?.inputs || []).map(pick),
  };
}

// The only fields the engine sees. Shared by execution and hashing so they cannot drift (§3.3).
type EngineNode = { id: string; type: string; properties?: Record<string, any>; inputs?: NodePortDefinition[]; outputs?: NodePortDefinition[] };
const toEngineNode = (n: any): EngineNode => ({
  id: n.id,
  type: nodeTypeOf(n),
  properties: nodeTypeOf(n) === SCRIPT_NODE_TYPE && typeof n.data.properties?.code === 'string'
    ? { ...n.data.properties, code: n.data.properties.code.replace(/\r\n?/g, '\n') } // package-format.md §3.4
    : n.data.properties,
  inputs: n.data.inputs,
  // Workflow Input's defaultValue only seeds the test-run form, so it is not part of the definition (package-format.md §3.4)
  outputs: nodeTypeOf(n) === WORKFLOW_INPUT ? n.data.outputs?.map(({ defaultValue: _d, ...p }: NodePortDefinition) => p) : n.data.outputs,
});
const toEngineEdge = (e: any) => ({
  source: e.source,
  sourceHandle: e.sourceHandle || '',
  target: e.target,
  targetHandle: e.targetHandle || '',
});

/** RFC 8785 (JCS): JSON.stringify already serializes strings/numbers per ECMAScript; we only sort keys. */
export function canonicalize(value: any): string {
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    const keys = Object.keys(value).filter((k) => value[k] !== undefined).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalize(value[k])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

/** package-format.md §3.2–3.4. */
export function computeDefinitionId(def: CustomNodeDefinition): string {
  const plain = JSON.parse(JSON.stringify(def)) as CustomNodeDefinition; // drop functions / undefined
  const hashInput = {
    inputs: plain.manifest.inputs,
    outputs: plain.manifest.outputs,
    nodes: withoutDocuments(plain.workflow.nodes).map(toEngineNode).sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0)),
    edges: plain.workflow.edges.map((e) => canonicalize(toEngineEdge(e))).sort().map((s) => JSON.parse(s)),
  };
  return CUSTOM_NODE_PREFIX + bytesToHex(sha256(utf8ToBytes(canonicalize(hashInput))));
}

/** Custom-node types referenced directly by a workflow's nodes. */
export const referencedDefinitionIds = (nodes: any[]): string[] =>
  [...new Set(nodes.map(nodeTypeOf).filter((t) => typeof t === 'string' && t.startsWith(CUSTOM_NODE_PREFIX)))];

// Every definition registered this session. Deleting a library entry does not unregister (web architecture §4.2),
// so a canvas that still uses it can be saved again with its dependency.
const sessionDefinitions = new Map<string, CustomNodeDefinition>();

export const getSessionDefinition = (id: string) => sessionDefinitions.get(id);

/** The ids plus every definition they reach (nested), resolved from the given pool or this session. */
export function collectDefinitionClosure(
  ids: string[],
  pool: Record<string, CustomNodeDefinition> = {}
): Record<string, CustomNodeDefinition> {
  const out: Record<string, CustomNodeDefinition> = {};
  const stack = [...ids];
  while (stack.length) {
    const id = stack.pop()!;
    if (out[id]) continue;
    const def = pool[id] || sessionDefinitions.get(id);
    if (!def) continue;
    out[id] = def;
    stack.push(...referencedDefinitionIds(def.workflow.nodes));
  }
  return out;
}

/** Black-box NodeDefinition: inject inputs into Workflow Input, run the sub-DAG, return Workflow Output. */
export function createCustomNodeDefinition(id: string, def: CustomNodeDefinition): NodeDefinition {
  const { manifest } = def;
  return {
    type: id,
    label: manifest.label,
    category: manifest.category as any,
    description: manifest.description, // an empty description is translated by the UI (i18n.md §7.4)
    inputs: manifest.inputs.map((p) => ({ ...p })),
    outputs: manifest.outputs.map((p) => ({ ...p })),
    propertySchema: [],
    // Custom nodes are listed in the palette from the library entries, not from the registry.
    hidden: true,
    // The sub-DAG's representative error is re-thrown as-is (node-catalog.md ND-8.2).
    errorProfile: fixedErrorProfile(['SUBTASK_ERROR']),
    execute: async ({ inputs, log }) => {
      const subNodes = withoutDocuments(structuredClone(def.workflow.nodes)).map(toEngineNode);
      const entry = subNodes.find((n) => n.type === WORKFLOW_INPUT);
      if (entry) entry.properties = { ...(entry.properties || {}), ...inputs, injectedValues: inputs };

      const subEdges: DAGEdgeConnection[] = def.workflow.edges.map((e: any, i: number) => ({ id: e.id || `e${i}`, ...toEngineEdge(e) }));
      const subResult = await DAGRunner.execute(subNodes, subEdges, defaultNodeRegistry.getMap(), {
        onLog: (subLog) => log(`[${manifest.label} > ${subLog.nodeType}] ${subLog.message}`, subLog.level),
      });

      if (!subResult.success) {
        const inner = subResult.taskError;
        throw new NodeError(inner?.code || 'UNKNOWN_ERROR', inner?.message || subResult.error || `Sub-DAG execution failed inside ${manifest.label}`);
      }

      const exit = subNodes.find((n) => n.type === WORKFLOW_OUTPUT);
      const exitData = exit && subResult.nodeOutputs[exit.id];
      const finalOutputs: Record<string, any> = {};
      if (exitData) {
        for (const outPort of manifest.outputs) {
          finalOutputs[outPort.id] = exitData[outPort.id] ?? exitData.result?.[outPort.id];
        }
        finalOutputs.result = exitData.result || exitData;
      }
      return finalOutputs;
    },
  };
}

export function registerCustomNodes(pool: Record<string, CustomNodeDefinition>): void {
  for (const [id, def] of Object.entries(pool)) {
    // Custom node definitions never carry variable references (value-registry.md §8.3): refuse rather than run them unresolved.
    if (definitionHasRef(def)) {
      console.warn(`[CustomNode] ${id}: a definition that still has variable references is not registered.`);
      continue;
    }
    sessionDefinitions.set(id, def);
    defaultNodeRegistry.register(createCustomNodeDefinition(id, def));
  }
}

/** "sha256:<hex>" → first 8 hex chars. */
export const shortId = (id: string) => id.slice(CUSTOM_NODE_PREFIX.length, CUSTOM_NODE_PREFIX.length + 8);

/**
 * package-format.md §3.6: within one category, duplicate labels get "(version)";
 * if label and version both collide, the short identifier is appended too.
 */
export function disambiguatedLabels(
  items: { id: string; label: string; version: string; category: string }[]
): Map<string, string> {
  const count = (key: (i: (typeof items)[number]) => string) => {
    const m = new Map<string, number>();
    items.forEach((i) => m.set(key(i), (m.get(key(i)) || 0) + 1));
    return m;
  };
  const byLabel = count((i) => `${i.category}\n${i.label}`);
  const byVersion = count((i) => `${i.category}\n${i.label}\n${i.version}`);
  return new Map(
    items.map((i) => {
      if (byLabel.get(`${i.category}\n${i.label}`)! < 2) return [i.id, i.label];
      const suffix = byVersion.get(`${i.category}\n${i.label}\n${i.version}`)! > 1
        ? [i.version, shortId(i.id)].filter(Boolean).join(', ')
        : i.version;
      return [i.id, suffix ? `${i.label} (${suffix})` : i.label];
    })
  );
}
