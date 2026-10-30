/**
 * Strict validator (authoring.md §4). One pure function for drafts and packages;
 * it collects every problem it can reach instead of stopping at the first one.
 */
import { validatePackage } from '../dag/package';
import { DAGScheduler } from '../dag/scheduler';
import { isDocumentNode } from '../dag/documentNode';
import { designErrorFor } from '../dag/designValidation';
import { checkDefaultValue, validateConstraint } from '../dag/portConstraint';
import { getEffectiveEdges, LINK_NODE_TYPE } from '../dag/links';
import { visiblePorts, type NodeDefinition } from '../dag/types';
import { isTypeDrivenOutput, typedOutputType } from '../registry/definitions/inputNodes';
import { validateHexInput } from '../crypto/utils/hexValidation';
import { compile, portIdProblem } from '../script';
import { collectRefs, isVarRef, slotsFor } from '../variables/reference';
import { defaultNodeRegistry, type NodeRegistry } from '../registry/nodeRegistry';
import { formatMsg, type Msg } from '../messages';
import { portNameError } from '../dag/portName';
import { expandDraft, portNameTargets } from './draft';
import { visibleWhen } from './catalog';
import { issue, nearest, type Issue } from './issues';

export interface ValidateResult {
  ok: boolean;
  kind: 'draft' | 'package';
  issues: Issue[];
}

const DATA_TYPES = ['bytes', 'string', 'bool', 'int', 'any', 'set'];
const VALUE_TYPES = ['bytes', 'string', 'bool', 'int'];
const WORKFLOW_INPUT = 'workflow-input';
const WORKFLOW_OUTPUT = 'workflow-output';
const VALUE_SET = 'input-value-set';
const SWITCH = 'switch';
const SCRIPT = 'utility-script';
/** Keys a node keeps in `properties` although its definition has no property for them. */
const EXTRA_KEYS: Record<string, string[]> = { [VALUE_SET]: ['rows'], [SWITCH]: ['activeInput'] };

const same = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b);
const show = (v: unknown) => {
  const s = JSON.stringify(v) ?? String(v);
  return s.length > 60 ? s.slice(0, 57) + '...' : s;
};

/** What the checks need to know about one node, whether it came from a draft or a package. */
interface CNode {
  id: string;
  type: string;
  def?: NodeDefinition;
  /** properties with defaults applied */
  props: Record<string, any>;
  /** keys the author wrote (draft); undefined for a package, where every key is the file's own */
  written?: string[];
  /** a package's own properties, without defaults: a missing key marks an old file (typed output, authoring.md §2.3) */
  saved?: Record<string, any>;
  inputs: any[];
  outputs: any[];
  /** port lists the author wrote (draft only) */
  given?: { inputs?: any[]; outputs?: any[] };
  /** the node as the engine sees it (`designErrorFor`) */
  node: any;
}

interface Edge { source: string; sourceHandle: string; target: string; targetHandle: string }

interface Paths {
  prop(i: number, key: string): string;
  ports(i: number, side: 'inputs' | 'outputs'): string;
  node(i: number): string;
  /** `part`: 'node' for the node id half, 'port' for the port id half */
  edge(j: number, end: 'from' | 'to', part: 'node' | 'port'): string;
}

interface Ctx {
  registry: NodeRegistry;
  /** draft rules: unknown and hidden properties are errors (D-20) */
  strict: boolean;
  /** closed file: variable paths the file carries */
  variables?: Record<string, { type: string }>;
}

const condition = (def: NodeDefinition, f: ((p: Record<string, any>) => boolean) | undefined): string => {
  const terms = f ? visibleWhen(def, f) : undefined;
  if (!terms) return 'always';
  if (!terms.length) return 'never';
  return terms.map((t) => Object.entries(t).map(([k, v]) => `${k}=${v.join('|')}`).join(' and ')).join(' or ');
};

function checkProps(n: CNode, i: number, p: Paths, ctx: Ctx, out: Issue[]) {
  const def = n.def;
  if (!def) return;
  const schema = new Map(def.propertySchema.map((f) => [f.id, f]));
  for (const key of n.written ?? Object.keys(n.props)) {
    const f = schema.get(key);
    const value = n.props[key];
    const path = p.prop(i, key);
    if (!f) {
      if (ctx.strict && !EXTRA_KEYS[n.type]?.includes(key)) {
        const near = nearest(key, [...schema.keys()]);
        out.push(issue('PROP_UNKNOWN', path, { node: n.id, prop: key }, near.length ? `Did you mean: ${near.join(', ')}` : `Properties: ${[...schema.keys()].join(', ') || '(none)'}`));
      }
      continue;
    }
    if (isVarRef(value)) continue; // checked with the other references below
    let expected: string | undefined;
    switch (f.type) {
      case 'select':
        if (!(f.options ?? []).some((o) => same(o.value, value))) expected = `one of ${(f.options ?? []).map((o) => show(o.value)).join(', ')}`;
        break;
      case 'boolean':
        if (typeof value !== 'boolean') expected = 'true or false';
        break;
      case 'number':
        if (typeof value !== 'number' || !Number.isFinite(value)) expected = 'a number';
        break;
      case 'hex':
        if (typeof value !== 'string' || !validateHexInput(value, { allowEmpty: true }).isValid) expected = 'a hex string of an even number of digits';
        break;
      default:
        if (typeof value !== 'string') expected = 'a string';
    }
    if (expected) {
      const options = f.type === 'select' ? (f.options ?? []).map((o) => String(o.value)) : [];
      const near = typeof value === 'string' ? nearest(value, options, 1) : [];
      out.push(issue('PROP_INVALID_VALUE', path, { node: n.id, prop: key, expected, value: show(value) }, near.length ? `Did you mean: ${near[0]}` : undefined));
      continue;
    }
    if (ctx.strict && f.showWhen && !f.showWhen(n.props) && !same(value, f.defaultValue)) {
      out.push(issue('PROP_HIDDEN', path, { node: n.id, prop: key }, `"${key}" is used only when ${condition(def, f.showWhen)}`));
    }
  }

  // Variable references (value-registry.md §4.2)
  const slots = slotsFor(def, n.outputs.map((o) => ({ id: o.id, name: o.name ?? o.id, dataType: o.dataType })));
  for (const ref of collectRefs(n.props)) {
    const isRow = ref.slot.startsWith('rows.');
    const slot = isRow ? slots.rows[ref.slot.slice(5)] : slots.fields[ref.slot];
    const path = isRow ? `${p.prop(i, 'rows')}.${ref.slot.slice(5)}.value` : p.prop(i, ref.slot);
    if (!slot) {
      out.push(issue('VARIABLE_NOT_ALLOWED', path, { node: n.id, prop: ref.slot }));
      continue;
    }
    if (!ctx.variables) continue;
    const entry = ctx.variables[ref.path];
    if (!entry) out.push(issue('VARIABLE_UNDEFINED', path, { node: n.id, path: ref.path }, 'Add it to "variables"'));
    else if (entry.type !== slot.type) out.push(issue('VARIABLE_TYPE_MISMATCH', path, { node: n.id, path: ref.path, want: slot.type, got: entry.type }));
  }
}

function checkPorts(n: CNode, i: number, p: Paths, nodes: Map<string, CNode>, out: Issue[], strictLists: boolean) {
  const def = n.def;
  if (!def) return;
  for (const side of ['inputs', 'outputs'] as const) {
    const dyn = side === 'inputs' ? def.dynamicInputs : def.dynamicOutputs;
    const derived = (n.type === VALUE_SET && side === 'inputs') || (n.type === SWITCH && side === 'outputs');
    const list: any[] = n[side];
    const path = p.ports(i, side);

    if (!dyn && !derived) {
      // Fixed ports: a written list must match the visible ports of the definition; a package carries them all.
      let expected = (strictLists ? visiblePorts(def[side], n.props) : def[side]).map((x) => `${x.id}:${x.dataType}`);
      // A Link's `out` has the type of the port it points at, not the definition's `any` (authoring.md §2.3).
      if (n.type === LINK_NODE_TYPE && side === 'outputs') {
        const from = nodes.get(n.props.sourceNodeId)?.outputs.find((x) => x.id === n.props.sourcePortId);
        if (from) {
          if (from.dataType === 'set' || !same(n[side].map((x) => `${x.id}:${x.dataType}`), [`out:${from.dataType}`])) {
            out.push(issue('LINK_TYPE_MISMATCH', path, { node: n.id }, `Source port ${n.props.sourceNodeId}.${from.id} is ${from.dataType}${from.dataType === 'set' ? ', which cannot be linked' : ''}`));
          }
          continue;
        }
        expected = ['out:' + (n.outputs[0]?.dataType ?? 'any')];
      }
      // Static Value, Random Value, User Input Dialog, CRC Generator: a property sets the type of the first output (authoring.md §2.3).
      if (side === 'outputs' && isTypeDrivenOutput(n.type) && expected.length) expected[0] = `${def.outputs[0].id}:${typedOutputType(n.type, n.saved ?? n.props, def.outputs[0].dataType)}`;
      const got = strictLists ? n.given?.[side] : list;
      // A package keeps the order the user chose (node-catalog.md §2.2-14); only a draft must match the definition order.
      const order = (l: string[]) => (strictLists ? l : [...l].sort());
      if (got && !same(order(got.map((x) => `${x.id}:${x.dataType}`)), order(expected))) {
        out.push(issue('PORT_MISMATCH', path, { node: n.id, side }, `Expected ${side}: ${expected.join(', ') || '(none)'}. Leave "${side}" out to use the definition.`));
      }
      continue;
    }
    if (dyn) {
      const min = dyn.min ?? 0;
      if (list.length < min || (dyn.max !== undefined && list.length > dyn.max)) {
        out.push(issue('PORT_COUNT_OUT_OF_RANGE', path, { node: n.id, side, count: list.length, range: dyn.max !== undefined ? `${min}-${dyn.max}` : `${min} or more` }));
      }
    }
    const seen = new Set<string>();
    list.forEach((port, k) => {
      const at = `${path}[${k}]`;
      if (typeof port.id !== 'string' || !port.id || port.id.includes('.')) out.push(issue('PORT_ID_INVALID', `${at}.id`, { node: n.id, id: String(port.id) }, 'A port id is not empty and has no "."'));
      else if (seen.has(port.id)) out.push(issue('PORT_ID_DUPLICATE', `${at}.id`, { node: n.id, id: port.id }));
      seen.add(port.id);
      const t = port.dataType;
      const allowed = n.type === WORKFLOW_INPUT ? ['bytes', 'string', 'bool', 'int']
        : n.type === VALUE_SET ? (port.id === 'set' ? ['set'] : VALUE_TYPES)
        : n.type === SWITCH ? ['set', ...VALUE_TYPES]
        : n.type === SCRIPT ? VALUE_TYPES
        : DATA_TYPES.filter((x) => x !== 'set');
      if (!DATA_TYPES.includes(t) || !allowed.includes(t)) {
        out.push(issue('PORT_TYPE_INVALID', `${at}.dataType`, { node: n.id, id: String(port.id), dataType: String(t) }, `Allowed: ${allowed.join(', ')}`));
      }
      if (n.type === WORKFLOW_INPUT && side === 'outputs') {
        const c = validateConstraint(port);
        if (c) out.push(issue('PORT_CONSTRAINT_INVALID', `${at}.constraint`, { node: n.id, id: port.id, reason: c }));
        if (port.defaultValue !== undefined) {
          const d = checkDefaultValue(port, String(port.defaultValue));
          const why = d.error ?? d.warning;
          if (why) out.push(issue('PORT_DEFAULT_INVALID', `${at}.defaultValue`, { node: n.id, id: port.id, reason: why }));
        }
      }
    });

    // Keys the CLI reads and writes (cli-spec.md §5): the name, or the id when names collide.
    if ((n.type === WORKFLOW_INPUT && side === 'outputs') || (n.type === WORKFLOW_OUTPUT && side === 'inputs')) {
      const names = list.map((x) => x.name ?? x.id);
      const keys = list.map((x, k) => (names.filter((m) => m === names[k]).length > 1 ? x.id : names[k]));
      keys.forEach((key, k) => {
        if (keys.indexOf(key) !== k) out.push(issue('PORT_KEY_AMBIGUOUS', `${path}[${k}]`, { node: n.id, key: String(key) }, 'Give the ports distinct names'));
      });
    }
  }
}

/** ValueSet/Switch/Script ports follow from properties and connections (workflow-spec.md §3.2, node-catalog.md ND-8.3). */
function checkDerived(n: CNode, i: number, p: Paths, nodes: Map<string, CNode>, edges: Edge[], out: Issue[]) {
  const mismatch = (path: string, detail: string) => out.push(issue('PORTS_DERIVATION_MISMATCH', path, { node: n.id, detail }));
  const brief = (ports: any[]) => ports.map((x) => `${x.id}:${x.name ?? x.id}:${x.dataType}`).join(', ') || '(none)';

  if (n.type === VALUE_SET) {
    const rows = n.outputs.filter((x) => x.id !== 'set');
    const sets = n.outputs.filter((x) => x.id === 'set');
    if (sets.length !== 1 || n.outputs[n.outputs.length - 1]?.id !== 'set' || sets[0].dataType !== 'set') mismatch(p.ports(i, 'outputs'), 'the last output must be the reserved "set" port of type set');
    const rowCfg = n.props.rows && typeof n.props.rows === 'object' ? n.props.rows : {};
    for (const k of Object.keys(rowCfg)) if (!rows.some((r) => r.id === k)) mismatch(`${p.prop(i, 'rows')}.${k}`, `rows has "${k}" but there is no such output port`);
    const wanted = rows.filter((r) => rowCfg[r.id]?.mode === 'input').map((r) => ({ id: r.id, name: r.name ?? r.id, dataType: r.dataType }));
    const got = n.inputs.map((x) => ({ id: x.id, name: x.name ?? x.id, dataType: x.dataType }));
    if (!same(got, wanted)) mismatch(p.ports(i, 'inputs'), `inputs must be one port per row with mode "input" (id:name:dataType): ${brief(wanted)}`);
  } else if (n.type === SWITCH) {
    const firstWired = n.inputs.map((x) => edges.find((e) => e.target === n.id && e.targetHandle === x.id)).find(Boolean);
    const src = firstWired && nodes.get(firstWired.source);
    const wanted = src?.type === VALUE_SET ? src.outputs.filter((x) => x.id !== 'set') : [];
    const norm = (l: any[]) => l.map((x) => ({ id: x.id, name: x.name ?? x.id, dataType: x.dataType }));
    if (!same(norm(n.outputs), norm(wanted))) mismatch(p.ports(i, 'outputs'), `outputs must copy the rows of the first connected ValueSet (id:name:dataType): ${brief(wanted)}`);
    const active = n.props.activeInput;
    if (active && !n.inputs.some((x) => x.id === active && edges.some((e) => e.target === n.id && e.targetHandle === active))) mismatch(p.prop(i, 'activeInput'), `activeInput "${active}" is not a connected input`);
  } else if (n.type === SCRIPT) {
    const taken: string[] = [];
    for (const side of ['inputs', 'outputs'] as const) {
      n[side].forEach((x, k) => {
        const problem = portIdProblem(String(x.id), taken);
        if (problem) mismatch(`${p.ports(i, side)}[${k}].id`, formatMsg(problem.message));
        else if ((x.name ?? x.id) !== x.id) mismatch(`${p.ports(i, side)}[${k}].name`, 'a Script port name is its id');
        taken.push(String(x.id));
      });
    }
  }
}

function checkWorkflow(nodes: CNode[], edges: Edge[], p: Paths, ctx: Ctx, strictLists: boolean): Issue[] {
  const out: Issue[] = [];
  const byId = new Map<string, CNode>();
  nodes.forEach((n, i) => {
    if (byId.has(n.id)) return void out.push(issue('NODE_ID_DUPLICATE', p.node(i), { id: n.id }));
    byId.set(n.id, n);
  });
  nodes.forEach((n, i) => {
    checkProps(n, i, p, ctx, out);
    checkPorts(n, i, p, byId, out, strictLists);
    checkDerived(n, i, p, byId, edges, out);
  });

  // Connections
  const seenTarget = new Set<string>();
  const connected = new Set<string>();
  edges.forEach((e, j) => {
    const src = byId.get(e.source);
    const dst = byId.get(e.target);
    if (!src) out.push(issue('EDGE_NODE_UNKNOWN', p.edge(j, 'from', 'node'), { node: e.source }));
    if (!dst) out.push(issue('EDGE_NODE_UNKNOWN', p.edge(j, 'to', 'node'), { node: e.target }));
    if (!src || !dst) return;
    const side = (node: CNode, handle: string, want: 'inputs' | 'outputs', end: 'from' | 'to'): any | null => {
      const port = node[want].find((x) => x.id === handle);
      if (port) return port;
      const other = want === 'inputs' ? 'outputs' : 'inputs';
      const path = p.edge(j, end, 'port');
      if (node[other].some((x) => x.id === handle)) {
        out.push(issue('EDGE_DIRECTION', path, { node: node.id, port: handle, expected: want === 'outputs' ? 'an output port' : 'an input port' }));
      } else {
        const ids = visiblePorts(node.def?.[want] ?? node[want], node.props).map((x) => x.id);
        out.push(issue('EDGE_PORT_UNKNOWN', path, { node: node.id, port: handle }, `${want === 'outputs' ? 'Output' : 'Input'} ports of "${node.id}": ${(ids.length ? ids : node[want].map((x) => x.id)).join(', ') || '(none)'}`));
      }
      return null;
    };
    const sp = side(src, e.sourceHandle, 'outputs', 'from');
    const dp = side(dst, e.targetHandle, 'inputs', 'to');
    if (!sp || !dp) return;

    let hidden = false;
    for (const [node, want, port, end] of [[src, 'outputs', sp, 'from'], [dst, 'inputs', dp, 'to']] as const) {
      const f = node.def?.[want].find((x) => x.id === port.id)?.showWhen;
      if (f && !f(node.props)) {
        hidden = true;
        out.push(issue('EDGE_PORT_HIDDEN', p.edge(j, end, 'port'), { node: node.id, port: port.id }, `"${port.id}" exists only when ${condition(node.def!, f)}`));
      }
    }
    if (hidden) return;

    const [a, b] = [sp.dataType, dp.dataType];
    if ((a === 'set') !== (b === 'set') || (a !== 'any' && b !== 'any' && a !== b)) {
      out.push(issue('EDGE_TYPE_MISMATCH', p.edge(j, 'to', 'port'), { from: `${e.source}.${sp.id} (${a})`, to: `${e.target}.${dp.id} (${b})` }));
    }
    const key = `${e.target}\n${e.targetHandle}`;
    if (seenTarget.has(key)) out.push(issue('EDGE_INPUT_MULTIPLE', p.edge(j, 'to', 'port'), { node: e.target, port: e.targetHandle }, 'An input port takes one connection'));
    seenTarget.add(key);
    connected.add(key);
  });

  // Links count as connections (links.ts); a Switch's inactive inputs still count here.
  const dag = nodes.map((n) => ({ id: n.id, type: n.type, properties: n.props }));
  const effective = getEffectiveEdges(dag as any, edges.map((e, j) => ({ id: String(j), ...e })), { includeInactive: true });
  for (const e of effective) connected.add(`${e.target}\n${e.targetHandle}`);
  const plan = DAGScheduler.schedule(nodes.map((n) => n.id), effective);
  if (plan.hasCycle) {
    const ids = plan.cycleNodes ?? [];
    out.push(issue('GRAPH_CYCLE', p.node(nodes.findIndex((n) => ids.includes(n.id))), { nodes: ids.join(', ') }));
  }

  nodes.forEach((n, i) => {
    if (!n.def) return;
    for (const port of visiblePorts(n.inputs.map((x) => ({ ...x, showWhen: n.def!.inputs.find((d) => d.id === x.id)?.showWhen })), n.props)) {
      if (port.required && !connected.has(`${n.id}\n${port.id}`)) {
        out.push(issue('INPUT_REQUIRED_MISSING', p.ports(i, 'inputs'), { node: n.id, port: port.id }, `Connect an edge to "${n.id}.${port.id}"`));
      }
    }
    // Existing design-time rules, the same function the canvas uses
    const reason: Msg | null = designErrorFor(n.id, nodes.map((x) => x.node), edges, (t) => ctx.registry.get(t));
    if (reason && n.type !== LINK_NODE_TYPE) out.push(issue('NODE_DESIGN_RULE', p.node(i), { node: n.id, reason }));
    if (ctx.strict && n.type === SCRIPT) out.push(...scriptIssues(n, i, p));
  });
  return out;
}

/** Syntax and type diagnostics of a Script node (authoring.md 4.4); at most this many are reported per node. */
const MAX_SCRIPT_ISSUES = 5;
function scriptIssues(n: CNode, i: number, p: Paths): Issue[] {
  const code = n.props.code;
  if (typeof code !== 'string') return [];
  const spec = (ports: any[]) => ports.map((x) => ({ id: x.id, dataType: x.dataType }));
  const { diagnostics } = compile(code, { inputs: spec(n.inputs), outputs: spec(n.outputs) });
  return diagnostics.slice(0, MAX_SCRIPT_ISSUES).map((d) =>
    issue('SCRIPT_DIAGNOSTIC', p.prop(i, 'code'), { node: n.id, line: d.line, column: d.column, detail: d.message }));
}

const isObj = (v: unknown): v is Record<string, any> => typeof v === 'object' && v !== null && !Array.isArray(v);

export function validate(input: unknown, registry: NodeRegistry = defaultNodeRegistry): ValidateResult {
  if (isObj(input) && 'draft' in input) return validateDraft(input, registry);
  if (isObj(input) && 'format' in input) return validatePackageFile(input, registry);
  return { ok: false, kind: 'draft', issues: [issue('DRAFT_BAD_STRUCTURE', '', { detail: 'neither a draft ("draft") nor a package ("format")' })] };
}

function validateDraft(draft: Record<string, any>, registry: NodeRegistry): ValidateResult {
  const r = expandDraft(draft, registry);
  if (!r.ok) return { ok: false, kind: 'draft', issues: r.issues };
  const nodes: CNode[] = r.workflow.nodes.map((n, i) => {
    const raw = draft.nodes[i];
    return {
      id: n.id,
      type: n.data.nodeType,
      def: registry.get(n.data.nodeType),
      props: n.data.properties,
      written: raw.props && isObj(raw.props) ? Object.keys(raw.props) : [],
      inputs: n.data.inputs,
      outputs: n.data.outputs,
      given: { inputs: raw.inputs, outputs: raw.outputs },
      node: n,
    };
  });
  const paths: Paths = {
    node: (i) => `nodes[${i}]`,
    prop: (i, k) => `nodes[${i}].props.${k}`,
    ports: (i, side) => `nodes[${i}].${side}`,
    edge: (j, end) => `edges[${j}].${end}`,
  };
  const issues = checkWorkflow(nodes, r.workflow.edges, paths, { registry, strict: true, variables: draft.variables }, true);
  const all = [...checkPortFields(draft), ...checkPortNames(draft, nodes), ...issues];
  return { ok: !all.length, kind: 'draft', issues: all };
}

/** `portNames` keys and values (authoring.md §2.2, §4.4). The loader has already applied the valid names to `inputs`/`outputs`. */
function checkPortNames(draft: Record<string, any>, nodes: CNode[]): Issue[] {
  const out: Issue[] = [];
  draft.nodes.forEach((raw: any, i: number) => {
    const def = nodes[i].def;
    if (!def || !isObj(raw.portNames)) return;
    const node = nodes[i];
    for (const [key, value] of Object.entries<any>(raw.portNames)) {
      const path = `nodes[${i}].portNames.${key}`;
      const { id, sides, hits } = portNameTargets(def, node.type, key);
      if (hits.length > 1) {
        out.push(issue('PORT_NAME_AMBIGUOUS', path, { node: node.id, key }, `"${id}" is both an input and an output; write "inputs.${id}" or "outputs.${id}"`));
        continue;
      }
      if (!hits.length) {
        const hidden = sides.map((s) => def[s].find((p) => p.id === id)).find((p) => p?.showWhen);
        const nameable = (['inputs', 'outputs'] as const).flatMap((s) => (s === 'inputs' ? !def.dynamicInputs : !def.dynamicOutputs) ? visiblePorts(def[s], node.props).map((p) => p.id) : []);
        const known = sides.some((s) => def[s].some((p) => p.id === id));
        out.push(issue('PORT_NAME_UNKNOWN_PORT', path, { node: node.id, key },
          hidden && !hidden.showWhen!(node.props) ? `"${id}" is shown only when ${condition(def, hidden.showWhen)}`
          : known ? 'A variable port is named by "name" in "inputs"/"outputs"; a derived port follows its properties'
          : `Ports that can be named: ${nameable.join(', ') || '(none)'}`));
        continue;
      }
      const side = hits[0];
      const hiddenPort = def[side].find((p) => p.id === id)!;
      if (hiddenPort.showWhen && !hiddenPort.showWhen(node.props)) {
        out.push(issue('PORT_NAME_UNKNOWN_PORT', path, { node: node.id, key }, `"${id}" is shown only when ${condition(def, hiddenPort.showWhen)}`));
        continue;
      }
      const err = typeof value === 'string' ? portNameError(node[side], id, value, true) : 'empty';
      if (err === 'duplicate') out.push(issue('PORT_NAME_DUPLICATE', path, { node: node.id, key, name: value.trim() }, 'Use a name no other port of the same direction has, including the default names of ports you did not rename'));
      else if (err) out.push(issue('PORT_NAME_INVALID', path, { node: node.id, key }, 'A name is a non-empty string without "/", ",", "(" or ")"'));
    }
  });
  return out;
}

/** `constraint`/`defaultValue`/`description` belong to Workflow Input/Output ports only (§2.3). */
function checkPortFields(draft: Record<string, any>): Issue[] {
  const out: Issue[] = [];
  draft.nodes.forEach((n: any, i: number) => {
    for (const side of ['inputs', 'outputs'] as const) {
      (n[side] ?? []).forEach((port: any, k: number) => {
        const isInputNode = n.type === WORKFLOW_INPUT && side === 'outputs';
        const isOutputNode = n.type === WORKFLOW_OUTPUT && side === 'inputs';
        for (const f of ['constraint', 'defaultValue', 'description']) {
          if (port[f] === undefined) continue;
          if (f === 'description' ? !(isInputNode || isOutputNode) : !isInputNode) {
            out.push(issue('PORT_FIELD_NOT_ALLOWED', `nodes[${i}].${side}[${k}].${f}`, { node: n.id, field: f }));
          }
        }
      });
    }
  });
  return out;
}

function validatePackageFile(pkg: Record<string, any>, registry: NodeRegistry): ValidateResult {
  const known = new Set(registry.getMap().keys());
  const bad = validatePackage(pkg, known);
  if (bad) return { ok: false, kind: 'package', issues: [{ code: bad.code, path: '', msg: bad.msg }] };

  const issues: Issue[] = [];
  const run = (w: { nodes: any[]; edges: any[] }, prefix: string, variables?: Record<string, { type: string }>) => {
    // Document nodes are skipped; `at` keeps the paths pointing at the original array index.
    const at: number[] = [];
    w.nodes.forEach((n, i) => { if (!isDocumentNode(n)) at.push(i); });
    const nodes: CNode[] = at.map((i) => w.nodes[i]).map((n) => {
      const type = n.data?.nodeType ?? n.data?.type;
      const def = registry.get(type);
      const props = n.data?.properties ?? {};
      return {
        id: n.id,
        type,
        def,
        props: def ? { ...Object.fromEntries(def.propertySchema.map((f) => [f.id, f.defaultValue])), ...props } : props,
        saved: props,
        inputs: n.data?.inputs ?? [],
        outputs: n.data?.outputs ?? [],
        node: n,
      };
    });
    const paths: Paths = {
      node: (i) => `${prefix}.nodes[${at[i]}]`,
      prop: (i, k) => `${prefix}.nodes[${at[i]}].data.properties.${k}`,
      ports: (i, side) => `${prefix}.nodes[${at[i]}].data.${side}`,
      edge: (j, end, part) => `${prefix}.edges[${j}].${end === 'from' ? 'source' : 'target'}${part === 'port' ? 'Handle' : ''}`,
    };
    const edges: Edge[] = w.edges.map((e) => ({ source: e.source, sourceHandle: e.sourceHandle, target: e.target, targetHandle: e.targetHandle }));
    // A saved file keeps values of properties that are hidden now, so those are not errors there (§4.4).
    issues.push(...checkWorkflow(nodes, edges, paths, { registry, strict: false, variables }, false));
  };
  run(pkg.workflow, 'workflow', isObj(pkg.variables) ? pkg.variables : undefined);
  for (const [id, d] of Object.entries<any>(pkg.definitions)) run(d.workflow, `definitions.${id}.workflow`);
  return { ok: !issues.length, kind: 'package', issues };
}
