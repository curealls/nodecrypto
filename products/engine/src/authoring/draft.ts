/**
 * Draft loader (authoring.md §2): expands a terse draft into a full workflow and a `.ncw` package.
 * Pure functions; shares nothing with the UI stores. Semantic checks beyond expansion belong to the validator (T05).
 */
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';
import { buildPackage, type NodePackage } from '../dag/package';
import { canonicalize, CUSTOM_NODE_PREFIX } from '../dag/customNode';
import { NOTE_MAX_LENGTH } from '../dag/nodeNote';
import { LINK_NODE_TYPE, LINK_BOX_NODE_TYPE, SWITCH_NODE_TYPE } from '../dag/links';
import { defaultNodeRegistry, type NodeRegistry } from '../registry/nodeRegistry';
import { NODE_WIDTH_BY_SIZE } from '../types';
import { VALUE_SET_NODE_TYPE, isTypeDrivenOutput, typedOutputType } from '../registry/definitions/inputNodes';
import type { NodeDefinition } from '../dag/types';
import { autoLayout } from './layout';
import { issue, nearest, type Issue } from './issues';

export const DRAFT_VERSION = 1;
const ROOT_FIELDS = ['draft', 'name', 'description', 'nodes', 'edges', 'variables'];
const NODE_FIELDS = ['id', 'type', 'label', 'note', 'props', 'inputs', 'outputs', 'portNames', 'position'];
const PORT_FIELDS = ['id', 'dataType', 'name', 'constraint', 'defaultValue', 'description'];
const EDGE_FIELDS = ['from', 'to'];
const NODE_ID = /^[A-Za-z0-9_-]{1,64}$/;

export interface ExpandedWorkflow {
  id: string;
  name: string;
  description: string;
  viewport: { x: number; y: number; zoom: number };
  nodes: any[];
  edges: any[];
  metadata: Record<string, never>;
}
export type ExpandResult = { ok: true; workflow: ExpandedWorkflow } | { ok: false; issues: Issue[] };
export type PackageResult = { ok: true; package: NodePackage } | { ok: false; issues: Issue[] };

/** A draft is told apart from a package by its top-level `draft` field (D-02). */
export const isDraft = (json: unknown): boolean => typeof json === 'object' && json !== null && 'draft' in json;

const isObj = (v: unknown): v is Record<string, any> => typeof v === 'object' && v !== null && !Array.isArray(v);

function unknownFields(o: Record<string, any>, allowed: string[], path: string, out: Issue[]) {
  for (const k of Object.keys(o)) if (!allowed.includes(k)) out.push(issue('DRAFT_UNKNOWN_FIELD', path ? `${path}.${k}` : k, { field: k }));
}

/** Port as written in the draft -> port definition stored in `data.inputs`/`data.outputs`. */
function toPort(p: Record<string, any>, required: boolean) {
  const port: Record<string, any> = { id: p.id, name: p.name ?? p.id, dataType: p.dataType };
  if (required) port.required = true;
  for (const k of ['description', 'constraint', 'defaultValue']) if (p[k] !== undefined) port[k] = p[k];
  return port;
}

/**
 * The fixed ports a `portNames` key can mean (authoring.md §2.2): a side whose ports the definition fixes, i.e. neither
 * variable nor derived from properties. A bare id looks at both sides; `inputs.<id>`/`outputs.<id>` at one.
 */
export function portNameTargets(def: NodeDefinition, type: string, key: string) {
  const m = /^(inputs|outputs)\.(.+)$/.exec(key);
  const id = m ? m[2] : key;
  const fixed = (side: 'inputs' | 'outputs') =>
    !(side === 'inputs' ? def.dynamicInputs || type === VALUE_SET_NODE_TYPE : def.dynamicOutputs || type === SWITCH_NODE_TYPE);
  const sides = (m ? [m[1]] : ['inputs', 'outputs']) as ('inputs' | 'outputs')[];
  return { id, sides, hits: sides.filter((side) => fixed(side) && def[side].some((p) => p.id === id)) };
}

function checkPorts(list: unknown, path: string, out: Issue[]): list is Record<string, any>[] {
  if (!Array.isArray(list)) {
    out.push(issue('DRAFT_BAD_STRUCTURE', path, { detail: 'must be an array' }));
    return false;
  }
  let ok = true;
  list.forEach((p, i) => {
    const pp = `${path}[${i}]`;
    if (!isObj(p)) {
      ok = false;
      return void out.push(issue('DRAFT_BAD_STRUCTURE', pp, { detail: 'must be an object' }));
    }
    unknownFields(p, PORT_FIELDS, pp, out);
    for (const k of ['id', 'dataType'])
      if (typeof p[k] !== 'string') {
        ok = false;
        out.push(issue('DRAFT_BAD_STRUCTURE', `${pp}.${k}`, { detail: `${k} must be a string` }));
      }
  });
  return ok;
}

export function expandDraft(draft: unknown, registry: NodeRegistry = defaultNodeRegistry): ExpandResult {
  const issues: Issue[] = [];
  if (!isObj(draft)) return { ok: false, issues: [issue('DRAFT_BAD_STRUCTURE', '', { detail: 'the root must be an object' })] };
  if (draft.draft !== DRAFT_VERSION) issues.push(issue('DRAFT_UNSUPPORTED_VERSION', 'draft', { version: String(draft.draft) }));
  unknownFields(draft, ROOT_FIELDS, '', issues);
  if (typeof draft.name !== 'string' || !draft.name) issues.push(issue('DRAFT_BAD_STRUCTURE', 'name', { detail: 'name must be a non-empty string' }));
  if (draft.description !== undefined && typeof draft.description !== 'string') issues.push(issue('DRAFT_BAD_STRUCTURE', 'description', { detail: 'description must be a string' }));
  const rawNodes = draft.nodes;
  const rawEdges = draft.edges ?? [];
  if (!Array.isArray(rawNodes) || !rawNodes.length) issues.push(issue('DRAFT_BAD_STRUCTURE', 'nodes', { detail: 'nodes must be a non-empty array' }));
  if (!Array.isArray(rawEdges)) issues.push(issue('DRAFT_BAD_STRUCTURE', 'edges', { detail: 'edges must be an array' }));
  if (draft.variables !== undefined && !isObj(draft.variables)) issues.push(issue('DRAFT_BAD_STRUCTURE', 'variables', { detail: 'variables must be an object' }));
  if (!Array.isArray(rawNodes) || !Array.isArray(rawEdges)) return { ok: false, issues };

  // Nodes
  const nodes: any[] = [];
  const byId = new Map<string, any>();
  const rejected = new Set<string>(); // nodes already reported; their connections are not reported again
  rawNodes.forEach((n, i) => {
    const path = `nodes[${i}]`;
    if (!isObj(n)) return void issues.push(issue('DRAFT_BAD_STRUCTURE', path, { detail: 'must be an object' }));
    unknownFields(n, NODE_FIELDS, path, issues);
    if (typeof n.id !== 'string' || typeof n.type !== 'string') return void issues.push(issue('DRAFT_BAD_STRUCTURE', path, { detail: 'id and type must be strings' }));
    if (!NODE_ID.test(n.id)) issues.push(issue('NODE_ID_INVALID', `${path}.id`, { id: n.id }, 'Use 1-64 characters of A-Z, a-z, 0-9, _ or -'));
    if (byId.has(n.id)) return void issues.push(issue('NODE_ID_DUPLICATE', `${path}.id`, { id: n.id }));
    rejected.add(n.id);
    if (n.type.startsWith(CUSTOM_NODE_PREFIX) || n.type === LINK_NODE_TYPE || n.type === LINK_BOX_NODE_TYPE)
      return void issues.push(issue('NODE_TYPE_NOT_ALLOWED', `${path}.type`, { type: n.type }));
    const def = registry.get(n.type);
    if (!def) {
      const near = nearest(n.type, registry.getAll().map((d) => d.type));
      return void issues.push(issue('NODE_TYPE_UNKNOWN', `${path}.type`, { type: n.type }, near.length ? `Did you mean: ${near.join(', ')}` : undefined));
    }
    if (n.props !== undefined && !isObj(n.props)) issues.push(issue('DRAFT_BAD_STRUCTURE', `${path}.props`, { detail: 'props must be an object' }));

    const inst = registry.createNodeInstance(n.type, n.id, undefined);
    const data: Record<string, any> = { ...inst.data, properties: { ...inst.data.properties, ...(isObj(n.props) ? n.props : {}) } };
    delete data.executionState;
    // A property decides the output type of Static Value, Random Value, User Input Dialog and CRC Generator (authoring.md §2.3).
    if (isTypeDrivenOutput(n.type) && Array.isArray(data.outputs) && data.outputs.length)
      data.outputs = data.outputs.map((p: any, k: number) => (k === 0 ? { ...p, dataType: typedOutputType(n.type, data.properties, p.dataType) } : p));
    if (n.label !== undefined) data.label = String(n.label);
    // Memo (authoring.md §2.2): markdown text for the person who reviews the workflow; blank means none
    if (n.note !== undefined) {
      if (typeof n.note !== 'string') issues.push(issue('DRAFT_BAD_STRUCTURE', `${path}.note`, { detail: 'note must be a string' }));
      else if (n.note.length > NOTE_MAX_LENGTH) issues.push(issue('DRAFT_BAD_STRUCTURE', `${path}.note`, { detail: `note must be at most ${NOTE_MAX_LENGTH} characters` }));
      else if (n.note.trim() !== '') data.note = n.note;
    }

    // A written list is used as is (the validator compares it with the definition); a missing one is
    // required for variable-port sides and comes from the definition otherwise (D-04).
    const hasDynamic = Boolean(def.dynamicInputs || def.dynamicOutputs);
    for (const [side, isInput] of [['inputs', true], ['outputs', false]] as const) {
      const dyn = isInput ? def.dynamicInputs : def.dynamicOutputs;
      const given = n[side];
      if (given === undefined) {
        if (dyn) issues.push(issue('PORT_LIST_REQUIRED', `${path}.${side}`, { type: n.type, side }));
      } else if (checkPorts(given, `${path}.${side}`, issues) && hasDynamic) {
        // Switch inputs are optional in the definition: only the active one is wired (ND-1.12).
        const required = isInput && def.inputs?.[0]?.required !== false;
        data[side] = given.map((p) => toPort(p, required));
      }
    }
    // portNames (authoring.md §2.2): only the name of a fixed port changes; the validator reports what cannot apply.
    if (n.portNames !== undefined && !isObj(n.portNames)) issues.push(issue('DRAFT_BAD_STRUCTURE', `${path}.portNames`, { detail: 'portNames must be an object' }));
    else if (n.portNames) {
      for (const [key, value] of Object.entries(n.portNames)) {
        const { id, hits } = portNameTargets(def, n.type, key);
        const name = typeof value === 'string' ? value.trim() : '';
        const port = hits.length === 1 && name ? data[hits[0]].find((p: any) => p.id === id) : undefined;
        if (port) port.name = name;
      }
    }
    const node = {
      id: n.id,
      type: 'cryptoNode',
      position: isObj(n.position) ? { x: n.position.x, y: n.position.y } : undefined,
      width: NODE_WIDTH_BY_SIZE[(def.size ?? 'basic') as keyof typeof NODE_WIDTH_BY_SIZE],
      data,
    };
    rejected.delete(n.id);
    byId.set(n.id, node);
    nodes.push(node);
  });

  // Edges
  const edges: any[] = [];
  const ref = (s: unknown, path: string): [string, string] | null => {
    const dot = typeof s === 'string' ? s.indexOf('.') : -1;
    if (typeof s !== 'string' || dot < 1 || dot === s.length - 1) {
      issues.push(issue('EDGE_BAD_REFERENCE', path, { value: String(s) }, 'Use "<node id>.<port id>"'));
      return null;
    }
    const nodeId = s.slice(0, dot);
    if (rejected.has(nodeId)) return null;
    if (!byId.has(nodeId)) {
      issues.push(issue('EDGE_NODE_UNKNOWN', path, { node: nodeId }, `Defined node ids: ${[...byId.keys()].join(', ')}`));
      return null;
    }
    return [nodeId, s.slice(dot + 1)];
  };
  rawEdges.forEach((e, i) => {
    const path = `edges[${i}]`;
    if (!isObj(e)) return void issues.push(issue('DRAFT_BAD_STRUCTURE', path, { detail: 'must be an object' }));
    unknownFields(e, EDGE_FIELDS, path, issues);
    const from = ref(e.from, `${path}.from`);
    const to = ref(e.to, `${path}.to`);
    if (!from || !to) return;
    const sourcePort = byId.get(from[0]).data.outputs.find((p: any) => p.id === from[1]);
    edges.push({
      id: `edge-${from[0]}-${from[1]}-${to[0]}-${to[1]}`,
      source: from[0],
      sourceHandle: from[1],
      target: to[0],
      targetHandle: to[1],
      type: 'custom',
      data: { dataType: sourcePort?.dataType ?? 'any' },
    });
  });

  if (issues.length) return { ok: false, issues };
  return {
    ok: true,
    workflow: {
      id: 'wf-' + bytesToHex(sha256(utf8ToBytes(canonicalize(draft)))).slice(0, 8),
      name: draft.name,
      description: draft.description ?? '',
      viewport: { x: 0, y: 0, zoom: 1 },
      nodes: autoLayout(nodes, edges),
      edges,
      metadata: {},
    },
  };
}

/** Expands a draft and wraps it as a `.ncw` package; `variables` makes it a closed file (authoring.md §2.5). */
export function draftToPackage(draft: unknown, registry: NodeRegistry = defaultNodeRegistry): PackageResult {
  const r = expandDraft(draft, registry);
  if (!r.ok) return r;
  const pkg = buildPackage(r.workflow, { label: r.workflow.name, version: '', description: r.workflow.description, category: '' }, () => undefined);
  const variables = (draft as Record<string, any>).variables;
  if (variables) pkg.variables = variables;
  return { ok: true, package: pkg };
}
