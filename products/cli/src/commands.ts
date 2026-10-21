/**
 * Command handlers of the NodeCrypto CLI (cli-spec.md §4, §7).
 * No file system, process or console access here: input comes through `Deps`, output is a `CommandResult`
 * that `main.ts` writes out, so a later MCP server can call the same functions.
 */
import {
  DAGRunner,
  DRAFT_VERSION,
  PACKAGE_FORMAT_VERSION_VARIABLES,
  defaultNodeRegistry,
  draftToPackage,
  formatMsg,
  generateCatalog,
  isDraft,
  validate,
  type Issue,
  type NodePackage,
} from 'nodecrypto-engine';
import { nearest } from 'nodecrypto-engine/authoring/issues';
import { bytesToHex, hexToBytes } from 'nodecrypto-engine/crypto/utils/encoding';
import { WORKFLOW_INPUT, WORKFLOW_OUTPUT, nodeTypeOf, registerCustomNodes } from 'nodecrypto-engine/dag/customNode';
import { toVariableMap, type VariableMap } from 'nodecrypto-engine/variables/reference';
import { parseRegistryFile } from 'nodecrypto-engine/variables/registryFile';
import cliPkg from '../package.json';
import enginePkg from '../../engine/package.json';

export interface Deps {
  readFile(path: string): Promise<string>;
  readStdin(): Promise<string>;
}

/** `data` is the `--json` output, `text` the human output (stdout); `files` are written by the caller. */
export interface CommandResult {
  exitCode: number;
  data: unknown;
  text: string;
  stderr: string;
  files?: { path: string; content: string }[];
}

export interface Args {
  json?: boolean;
  file?: string;
  type?: string;
  list?: boolean;
  search?: string;
  output?: string;
  inputs?: string;
  vars?: string;
  expect?: string;
  trace?: boolean;
}

interface CliIssue {
  code: string;
  path: string;
  message: string;
  hint?: string;
}

const GUIDE = Object.values(import.meta.glob('../ai/guide.md', { query: '?raw', import: 'default', eager: true }))[0] as string | undefined;

// ─── helpers ───────────────────────────────────────────────────────────────

const result = (exitCode: number, data: unknown, text = '', stderr = ''): CommandResult => ({ exitCode, data, text, stderr });
const usage = (code: string, message: string) => result(64, { ok: false, issues: [{ code, path: '', message }] }, '', `error[${code}] ${message}\n`);
const toCli = (i: Issue): CliIssue => ({ code: i.code, path: i.path, message: formatMsg(i.msg), ...(i.hint ? { hint: i.hint } : {}) });
const own = (code: string, path: string, message: string, hint?: string): CliIssue => ({ code, path, message, ...(hint ? { hint } : {}) });
const isObj = (v: unknown): v is Record<string, any> => typeof v === 'object' && v !== null && !Array.isArray(v);

function formatIssues(issues: CliIssue[]): string {
  return issues.map((i) => `error[${i.code}]${i.path ? ' ' + i.path : ''}: ${i.message}\n${i.hint ? `  hint: ${i.hint}\n` : ''}`).join('');
}

/** An issue list as the output of a command that stopped on it (`stream`: where the text goes). */
function failed(kind: string | undefined, issues: CliIssue[], code = 1, stream: 'text' | 'stderr' = 'stderr'): CommandResult {
  const body = formatIssues(issues);
  return { exitCode: code, data: { ok: false, ...(kind ? { kind } : {}), issues }, text: stream === 'text' ? body : '', stderr: stream === 'stderr' ? body : '' };
}

type Loaded = { ok: true; json: unknown } | { ok: false; res: CommandResult };

async function load(src: string | undefined, deps: Deps): Promise<Loaded> {
  if (!src) return { ok: false, res: usage('CLI_USAGE', 'a file argument is required') };
  let text: string;
  try {
    text = src === '-' ? await deps.readStdin() : await deps.readFile(src);
  } catch (e) {
    return { ok: false, res: usage('CLI_FILE_UNREADABLE', `cannot read '${src}': ${(e as Error).message}`) };
  }
  try {
    return { ok: true, json: JSON.parse(text.replace(/^﻿/, '')) };
  } catch (e) {
    return { ok: false, res: failed('draft', [own('DRAFT_BAD_JSON', '', `the text is not valid JSON: ${(e as Error).message}`)]) };
  }
}

/** `--inputs` / `--expect`: a JSON object when it starts with `{`, otherwise a file path (cli-spec.md §5). */
async function loadObject(arg: string, what: string, deps: Deps): Promise<{ ok: true; value: Record<string, unknown> } | { ok: false; res: CommandResult }> {
  let text = arg.trim();
  if (!text.startsWith('{')) {
    try {
      text = await deps.readFile(arg);
    } catch (e) {
      return { ok: false, res: usage('CLI_FILE_UNREADABLE', `cannot read '${arg}': ${(e as Error).message}`) };
    }
  }
  try {
    const v = JSON.parse(text.replace(/^﻿/, ''));
    if (isObj(v)) return { ok: true, value: v };
  } catch {
    /* falls through to the issue below */
  }
  return { ok: false, res: failed(undefined, [own('RUN_INPUT_INVALID', what, `${what} must be a JSON object`)]) };
}

// ─── values (cli-spec.md §5) ───────────────────────────────────────────────

const MAX_SAFE = BigInt(Number.MAX_SAFE_INTEGER);
const MIN_SAFE = BigInt(Number.MIN_SAFE_INTEGER);

/** Notation → runtime value; a string is the reason it was refused. */
function parseValue(type: string, raw: unknown): { value: unknown } | string {
  switch (type) {
    case 'bytes': {
      const hex = typeof raw === 'string' ? raw.replace(/\s+/g, '') : undefined;
      return hex !== undefined && /^([0-9a-fA-F]{2})*$/.test(hex) ? { value: hexToBytes(hex) } : 'bytes must be a hex string with an even number of digits';
    }
    case 'int': {
      if (typeof raw !== 'string' || !/^-?\d+$/.test(raw.trim())) return 'int must be a decimal integer string';
      const n = BigInt(raw.trim());
      return { value: n >= MIN_SAFE && n <= MAX_SAFE ? Number(n) : n };
    }
    case 'string':
      return typeof raw === 'string' ? { value: raw } : 'string must be a JSON string';
    case 'bool':
      return typeof raw === 'boolean' ? { value: raw } : 'bool must be true or false';
    default:
      return `ports of type '${type}' cannot be given from the command line`;
  }
}

/** A Workflow Input `defaultValue` is stored as text (ND-1.5). */
function parseDefault(type: string, text: unknown): { value: unknown } | string {
  const s = String(text);
  if (type === 'bool') return s === 'true' || s === 'false' ? { value: s === 'true' } : 'bool must be true or false';
  return parseValue(type, type === 'bytes' ? s.replace(/^0x/i, '') : s);
}

/** Runtime value → notation. */
function format(value: unknown, type: string): unknown {
  if (value instanceof Uint8Array) return bytesToHex(value);
  if (typeof value === 'bigint') return value.toString();
  if (typeof value === 'number' && type === 'int') return String(value);
  return value;
}

/** Key of a port: its name, or its id when names collide (§5). */
function portKeys(ports: { id: string; name?: string }[]): string[] {
  const names = ports.map((p) => p.name ?? p.id);
  return ports.map((p, i) => (names.filter((n) => n === names[i]).length > 1 ? p.id : names[i]));
}

// ─── catalog / guide / version ─────────────────────────────────────────────

export function catalog(args: Args): CommandResult {
  const modes = [args.type !== undefined, args.list, args.search !== undefined].filter(Boolean).length;
  if (modes > 1) return usage('CLI_USAGE', '--type, --list and --search cannot be combined');
  const all = generateCatalog(defaultNodeRegistry);
  if (args.list || args.search !== undefined) {
    const words = (args.search ?? '').toLowerCase().split(/\s+/).filter(Boolean);
    if (args.search !== undefined && !words.length) return usage('CLI_USAGE', '--search needs at least one keyword');
    const rows = all.nodes
      .map((n) => ({ type: n.type, label: n.label, category: n.category, description: n.description.replace(/\s+/g, ' ').trim() }))
      .filter((r) => words.every((w) => `${r.type} ${r.label} ${r.category} ${r.description}`.toLowerCase().includes(w)));
    if (!rows.length) return failed(undefined, [own('CATALOG_NO_MATCH', '', `no node matches '${args.search}'`, 'use --list to see every node')]);
    return result(0, rows, rows.map((r) => `${r.type}\t${r.label}\t${r.description}\n`).join(''));
  }
  if (args.type === undefined) return result(0, all, JSON.stringify(all, null, 2) + '\n');
  const node = all.nodes.find((n) => n.type === args.type);
  if (node) return result(0, node, JSON.stringify(node, null, 2) + '\n');
  const types = all.nodes.map((n) => n.type);
  const similar = [...new Set([...nearest(args.type, types, 5), ...types.filter((t) => t.includes(args.type!)).slice(0, 5)])];
  const message = `unknown node type '${args.type}'${similar.length ? `. Did you mean: ${similar.join(', ')}` : ''}`;
  return failed(undefined, [own('CATALOG_TYPE_UNKNOWN', '', message)]);
}

export function guide(): CommandResult {
  if (GUIDE === undefined) return failed(undefined, [own('GUIDE_UNAVAILABLE', '', 'this build does not include the guide')]);
  return result(0, { guide: GUIDE }, GUIDE.endsWith('\n') ? GUIDE : GUIDE + '\n');
}

export function version(json: boolean): CommandResult {
  const data = { cli: cliPkg.version, engine: enginePkg.version, packageFormat: PACKAGE_FORMAT_VERSION_VARIABLES, draft: DRAFT_VERSION };
  const text = `nodecrypto ${data.cli} (engine ${data.engine}, package-format ${data.packageFormat}, draft ${data.draft})\n`;
  return result(0, data, json ? JSON.stringify(data) + '\n' : text);
}

// ─── validate / expand ─────────────────────────────────────────────────────

const counts = (json: any, kind: string) => {
  const w = kind === 'draft' ? json : json.workflow;
  return `${w.nodes.length} nodes, ${w.edges.length} edges\n`;
};

export async function validateCmd(args: Args, deps: Deps): Promise<CommandResult> {
  const l = await load(args.file, deps);
  if (!l.ok) return l.res;
  const v = validate(l.json);
  if (!v.ok) return failed(v.kind, v.issues.map(toCli), 1, 'text');
  return result(0, { ok: true, kind: v.kind, issues: [] }, `OK (${v.kind})\n${counts(l.json, v.kind)}`);
}

/** Validates and turns a draft or package file into a package. */
async function loadPackage(file: string | undefined, deps: Deps): Promise<{ ok: true; pkg: NodePackage } | { ok: false; res: CommandResult }> {
  const l = await load(file, deps);
  if (!l.ok) return l;
  const v = validate(l.json);
  if (!v.ok) return { ok: false, res: failed(v.kind, v.issues.map(toCli)) };
  if (!isDraft(l.json)) return { ok: true, pkg: l.json as NodePackage };
  const r = draftToPackage(l.json);
  return r.ok ? { ok: true, pkg: r.package } : { ok: false, res: failed('draft', r.issues.map(toCli)) };
}

export async function expand(args: Args, deps: Deps): Promise<CommandResult> {
  const p = await loadPackage(args.file, deps);
  if (!p.ok) return p.res;
  const content = JSON.stringify(p.pkg, null, 2) + '\n';
  if (args.output) return { exitCode: 0, data: { ok: true, output: args.output }, text: '', stderr: '', files: [{ path: args.output, content }] };
  return result(0, p.pkg, content);
}

// ─── run ───────────────────────────────────────────────────────────────────

interface PortRef {
  key: string;
  nodeId: string;
  port: { id: string; name?: string; dataType: string; defaultValue?: unknown };
}

const portsOf = (nodes: any[], type: string, side: 'inputs' | 'outputs'): PortRef[] =>
  nodes.filter((n) => nodeTypeOf(n) === type).flatMap((n) => {
    const ports: PortRef['port'][] = n.data[side] ?? [];
    const keys = portKeys(ports);
    return ports.map((port, i) => ({ key: keys[i], nodeId: n.id, port }));
  });

const sameValue = (type: string, a: unknown, b: unknown): boolean => {
  if (type === 'bytes' && typeof a === 'string' && typeof b === 'string') return a.replace(/\s+/g, '').toLowerCase() === b.replace(/\s+/g, '').toLowerCase();
  if (type === 'int' && typeof b !== 'object') {
    try {
      return BigInt(String(a)) === BigInt(String(b));
    } catch {
      return false;
    }
  }
  return JSON.stringify(a) === JSON.stringify(b);
};

interface NodeStatus {
  id: string;
  status: 'success' | 'error';
  code?: string;
  message?: string;
  skipped?: boolean;
}

export async function run(args: Args, deps: Deps): Promise<CommandResult> {
  const p = await loadPackage(args.file, deps);
  if (!p.ok) return p.res;
  const { pkg } = p;
  const issues: CliIssue[] = [];

  // variables: bundled values, overridden by --vars (§4.4)
  let variables: VariableMap = pkg.variables ? toVariableMap(pkg.variables) : {};
  if (args.vars) {
    const l = await load(args.vars, deps);
    if (!l.ok) return l.res;
    const f = parseRegistryFile(l.json);
    if (!f.ok) return failed(undefined, [own(f.code, 'vars', f.message)]);
    variables = { ...variables, ...toVariableMap(Object.fromEntries(Object.entries(f.value.variables).map(([rel, e]) => ['$' + rel, e]))) };
  }

  // input values
  const wf = pkg.workflow;
  const inPorts = portsOf(wf.nodes, WORKFLOW_INPUT, 'outputs');
  let given: Record<string, unknown> = {};
  if (args.inputs) {
    const o = await loadObject(args.inputs, '--inputs', deps);
    if (!o.ok) return o.res;
    given = o.value;
  }
  for (const k of Object.keys(given)) {
    if (!inPorts.some((x) => x.key === k)) issues.push(own('RUN_INPUT_UNKNOWN', `inputs.${k}`, `no Workflow Input port is named '${k}'`, `available: ${inPorts.map((x) => x.key).join(', ') || '(none)'}`));
  }
  const injected: Record<string, Record<string, unknown>> = {};
  for (const x of inPorts) {
    let r: { value: unknown } | string;
    if (x.key in given) r = parseValue(x.port.dataType, given[x.key]);
    else if (x.port.defaultValue !== undefined) r = parseDefault(x.port.dataType, x.port.defaultValue);
    else {
      issues.push(own('RUN_INPUT_MISSING', `inputs.${x.key}`, `no value for '${x.key}' and it has no default`, `pass it with --inputs '{"${x.key}": ...}'`));
      continue;
    }
    if (typeof r === 'string') issues.push(own('RUN_INPUT_INVALID', `inputs.${x.key}`, `${x.key}: ${r}`));
    else (injected[x.nodeId] ??= {})[x.port.id] = r.value;
  }
  let expected: Record<string, unknown> | undefined;
  if (args.expect) {
    const o = await loadObject(args.expect, '--expect', deps);
    if (!o.ok) return o.res;
    expected = o.value;
  }
  if (issues.length) return failed(undefined, issues);

  // execute
  if (pkg.definitions) registerCustomNodes(structuredClone(pkg.definitions));
  const done = await DAGRunner.execute(
    wf.nodes.map((n: any) => ({
      id: n.id,
      type: nodeTypeOf(n),
      label: n.data.label,
      properties: nodeTypeOf(n) === WORKFLOW_INPUT ? { injectedValues: injected[n.id] ?? {} } : n.data.properties,
      inputs: n.data.inputs,
      outputs: n.data.outputs,
    })),
    wf.edges.map((e: any) => ({ id: e.id, source: e.source, sourceHandle: e.sourceHandle || '', target: e.target, targetHandle: e.targetHandle || '' })),
    defaultNodeRegistry.getMap(),
    { variables }
  );

  const nodes = wf.nodes.flatMap((n: any): NodeStatus[] => {
    const st = done.nodeStates[n.id];
    if (!st || (st.status !== 'success' && st.status !== 'error')) return [];
    if (st.status === 'success') return [{ id: n.id, status: 'success' }];
    return [{ id: n.id, status: 'error', code: st.errorCode, message: st.errorMsg ? formatMsg(st.errorMsg) : st.errorMessage, ...(st.skipped ? { skipped: true } : {}) }];
  });

  // outputs: Workflow Output ports, else the ports of terminal nodes (§5)
  const outputs: Record<string, unknown> = {};
  const types: Record<string, string> = {};
  const put = (key: string, nodeId: string, port: { id: string; dataType: string }) => {
    const v = done.nodeOutputs[nodeId]?.[port.id];
    if (v === undefined) return;
    outputs[key] = format(v, port.dataType);
    types[key] = port.dataType;
  };
  if (wf.nodes.some((n: any) => nodeTypeOf(n) === WORKFLOW_OUTPUT)) {
    for (const x of portsOf(wf.nodes, WORKFLOW_OUTPUT, 'inputs')) put(x.key, x.nodeId, x.port);
  } else {
    const sources = new Set(wf.edges.map((e: any) => e.source));
    for (const n of wf.nodes.filter((n: any) => !sources.has(n.id))) {
      for (const port of n.data.outputs ?? []) put(`${n.id}.${port.id}`, n.id, port);
    }
  }

  const show = (k: string, v: unknown) => `${k}: ${typeof v === 'string' ? v : JSON.stringify(v)}\n`;
  // --trace: every successful node's outputs, in workflow order (cli-spec.md §4.4)
  const trace: Record<string, Record<string, unknown>> = {};
  if (args.trace) {
    for (const n of wf.nodes) {
      if (nodes.find((x) => x.id === n.id)?.status !== 'success') continue;
      const out: Record<string, unknown> = {};
      for (const port of n.data.outputs ?? []) {
        const v = done.nodeOutputs[n.id]?.[port.id];
        if (v !== undefined) out[port.id] = format(v, port.dataType);
      }
      trace[n.id] = out;
    }
  }
  const lines =
    Object.entries(outputs).map(([k, v]) => show(k, v)).join('') +
    Object.entries(trace).flatMap(([id, out]) => Object.entries(out).map(([p, v]) => show(`trace ${id}.${p}`, v))).join('');
  const extra = args.trace ? { trace } : {};
  const errors = nodes.filter((n) => n.status === 'error');
  if (errors.length || !done.success) {
    const code = errors.length ? 'RUN_NODE_ERROR' : 'RUN_ENGINE_FAILURE';
    const stderr = errors.length
      ? errors.map((n) => `error[${n.code}] ${n.id}: ${n.message}\n`).join('')
      : `error[${code}] ${done.error ?? 'the run failed'}\n`;
    return { exitCode: 2, data: { ok: false, code, outputs, nodes, ...extra, ...(!errors.length && done.error ? { error: done.error } : {}) }, text: lines, stderr };
  }

  if (!expected) return result(0, { ok: true, outputs, nodes, ...extra }, lines);
  const diffs = Object.entries(expected).flatMap(([key, exp]) =>
    key in outputs && sameValue(types[key], outputs[key], exp) ? [] : [{ key, expected: exp, actual: key in outputs ? outputs[key] : null }]
  );
  const stderr = diffs.map((d) => `mismatch ${d.key}: expected ${JSON.stringify(d.expected)}, actual ${JSON.stringify(d.actual)}\n`).join('');
  const match = diffs.length === 0;
  const n = Object.keys(expected).length;
  return {
    exitCode: match ? 0 : 1,
    data: { ok: match, ...(match ? {} : { code: 'RUN_EXPECT_MISMATCH' }), outputs, nodes, ...extra, expect: { match, diffs } },
    text: match ? `${lines}# expect: matched ${n} of ${n} keys\n` : lines,
    stderr,
  };
}
