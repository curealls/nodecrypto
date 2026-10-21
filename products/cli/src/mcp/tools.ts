/**
 * The five MCP tools (mcp-spec.md §4, §5): thin wrappers over the CLI command functions.
 * The only thing added is `expand`'s file save; file system access comes in through `McpDeps`.
 */
import { dirname, extname, join, resolve } from 'node:path';
import { catalog, expand, guide, run, validateCmd, version, type CommandResult, type Deps } from '../commands';
import type { McpInfo, McpTool } from './server';

export interface McpDeps extends Deps {
  writeFile(path: string, content: string): Promise<void>;
  mkdir(path: string): Promise<void>;
  exists(path: string): Promise<boolean>;
  homedir(): string;
  /** `--out-dir` or NODECRYPTO_OUT_DIR, already resolved by the entry point. */
  outDir?: string;
}

type Out = { text: string; isError?: boolean };
type Schema = { type?: string; anyOf?: { type: string }[]; description?: string };

export const INSTRUCTIONS = `NodeCrypto builds cryptographic workflows (node graphs) as JSON drafts that a person reviews on a canvas.
1. Call guide first and follow it.
2. Never guess node types, port ids or property values: use catalog (search, then type).
3. Check with validate, then run with expect (use published test vectors).
4. Only then call expand to save the .ncw file, and tell the person its path: they open it in the NodeCrypto web app (File > Open).
Do not put real secret keys into inputs: results pass through this conversation.`;

export const mcpInfo = (): McpInfo => ({ name: 'nodecrypto', title: 'NodeCrypto', version: (version(false).data as { cli: string }).cli, instructions: INSTRUCTIONS });

const DRAFT = '\0draft'; // virtual file names (no real file name can contain NUL)
const VARS = '\0vars';

const failure = (code: string, path: string, message: string): Out => ({ text: JSON.stringify({ ok: false, issues: [{ code, path, message }] }), isError: true });
const fromResult = (res: CommandResult, text = JSON.stringify(res.data)): Out => ({ text, isError: res.exitCode !== 0 });

const kind = (v: unknown) => (v === null ? 'null' : Array.isArray(v) ? 'array' : typeof v);

/** Checks the arguments against a flat `inputSchema`: known names, right types. Returns a failure or undefined. */
function checkArgs(properties: Record<string, Schema>, args: Record<string, unknown>): Out | undefined {
  for (const [k, v] of Object.entries(args)) {
    const p = properties[k];
    if (!p) return failure('MCP_ARGS_INVALID', k, `unknown argument '${k}' (allowed: ${Object.keys(properties).join(', ') || 'none'})`);
    const types = p.anyOf ? p.anyOf.map((a) => a.type) : [p.type];
    if (!types.includes(kind(v))) return failure('MCP_ARGS_INVALID', k, `'${k}' must be ${types.join(' or ')}`);
  }
}

const slug = (name: string) =>
  name
    .replace(/[\\/:*?"<>|\x00-\x1f]/g, '')
    .trim()
    .replace(/\s+/g, '-')
    .replace(/^[.-]+|[.-]+$/g, '')
    .slice(0, 80)
    .replace(/[.-]+$/, '') || 'workflow';

export function mcpTools(deps: McpDeps): McpTool[] {
  const draftOrPath = {
    draft: { type: 'object', description: 'The draft (or package) as a JSON object. Give exactly one of draft and path.' },
    path: { type: 'string', description: 'Path of a draft or package file. Give exactly one of draft and path.' },
  };
  const isObject = (v: unknown) => kind(v) === 'object';
  const objOrStr = (description: string): Schema => ({ anyOf: [{ type: 'object' }, { type: 'string' }], description });

  /** Defines a tool: validates the arguments, then runs `body`. `files` are virtual files this call reads. */
  const tool = (
    name: string,
    description: string,
    properties: Record<string, Schema>,
    annotations: Record<string, unknown>,
    body: (a: Record<string, any>, d: Deps) => Promise<Out>
  ): McpTool => ({
    name,
    description,
    inputSchema: { type: 'object', properties, additionalProperties: false },
    annotations,
    handler: async (a) => {
      const bad = checkArgs(properties, a);
      if (bad) return bad;
      const files: Record<string, string> = {};
      if (a.draft !== undefined) files[DRAFT] = JSON.stringify(a.draft);
      if (inlineVars(a.vars)) files[VARS] = text(a.vars)!;
      // stdin belongs to the protocol: `-` as a file name must not read it
      return body(a, { readFile: async (p) => files[p] ?? deps.readFile(p), readStdin: async () => { throw new Error('standard input is not available'); } });
    },
  });
  /** `inputs`, `expect`: an object becomes JSON text, a string stays (JSON text or a file path, cli-spec.md §4.4). */
  const text = (v: unknown) => (isObject(v) ? JSON.stringify(v) : (v as string | undefined));
  /** `vars` is a file in the CLI; here an object or JSON text is accepted too (mcp-spec.md §4.1). */
  const inlineVars = (v: unknown) => isObject(v) || (typeof v === 'string' && v.trimStart().startsWith('{'));
  const source = (a: Record<string, any>) => ((a.draft === undefined) === (a.path === undefined) ? failure('MCP_ARGS_INVALID', 'draft', 'give exactly one of draft and path') : undefined);
  const file = (a: Record<string, any>) => (a.draft !== undefined ? DRAFT : (a.path as string));
  const readOnly = { readOnlyHint: true };

  return [
    tool('guide', 'Print the NodeCrypto authoring guide (Markdown). Read it first: it explains the draft format, the procedure and common traps.', {}, readOnly, async () => {
      const r = guide();
      return fromResult(r, r.exitCode === 0 ? r.text : undefined);
    }),

    tool(
      'catalog',
      'Look up node types. Use search or list to find a node, then type to get its ports and properties. Calling it with no arguments returns the whole catalog, which is very large: avoid that.',
      {
        type: { type: 'string', description: 'Node type id: returns that node with its ports and properties.' },
        list: { type: 'boolean', description: 'One line per node.' },
        search: { type: 'string', description: 'Keywords separated by spaces; nodes matching all of them are listed.' },
      },
      readOnly,
      async (a) => fromResult(catalog(a))
    ),

    tool(
      'validate',
      'Check a draft or a package. Each issue has a code, a JSON path and a hint. Fix the issues and call again until it passes.',
      draftOrPath,
      readOnly,
      async (a, d) => source(a) ?? fromResult(await validateCmd({ file: file(a) }, d))
    ),

    tool(
      'expand',
      "Validate a draft, expand it into a .ncw package and SAVE it to a file. The person opens the file in the NodeCrypto web app (File > Open). output is the .ncw path to write: pass an absolute path inside the user's project when you know it; without it the file goes to the default folder under the draft name. An existing file is overwritten unless overwrite is false.",
      {
        ...draftOrPath,
        output: { type: 'string', description: 'Path of the .ncw file to write. Relative paths are resolved against the default folder.' },
        overwrite: { type: 'boolean', description: 'Default true. false refuses to replace an existing file.' },
      },
      { readOnlyHint: false, destructiveHint: true, idempotentHint: true },
      async (a, d) => {
        const bad = source(a);
        if (bad) return bad;
        const r = await expand({ file: file(a) }, d);
        if (r.exitCode !== 0) return fromResult(r);
        const pkg = r.data as { manifest: { label?: string }; workflow: { nodes: unknown[]; edges: unknown[] } };
        const target = resolve(deps.outDir ?? join(deps.homedir(), 'nodecrypto-workflows'), a.output ?? `${slug(pkg.manifest.label ?? '')}.ncw`);
        if (extname(target).toLowerCase() !== '.ncw') return failure('MCP_OUTPUT_EXTENSION', 'output', `the file must have the .ncw extension: ${target}`);
        const overwritten = await deps.exists(target);
        if (overwritten && a.overwrite === false) return failure('MCP_OUTPUT_EXISTS', 'output', `${target} already exists and overwrite is false`);
        try {
          await deps.mkdir(dirname(target));
          await deps.writeFile(target, r.text);
        } catch (e) {
          return failure('MCP_OUTPUT_WRITE_FAILED', 'output', `cannot write ${target}: ${(e as Error).message}`);
        }
        return {
          text: JSON.stringify({
            ok: true,
            path: target,
            overwritten,
            nodes: pkg.workflow.nodes.length,
            edges: pkg.workflow.edges.length,
            openHint: 'Open this file in the NodeCrypto web app: File > Open.',
          }),
        };
      }
    ),

    tool(
      'run',
      "Validate and run a workflow headless on this machine, optionally compare the outputs with expected values (use published test vectors) and show every node's outputs with trace. Inputs and results pass through the AI conversation: use test vectors, never real secret keys.",
      {
        ...draftOrPath,
        inputs: objOrStr('Values for the Workflow Input ports by port name: {"Key": "00ff…"} (bytes as hex, int as decimal string). A string is JSON text or a file path.'),
        vars: objOrStr('Variable registry (object or file path) for variable references.'),
        expect: objOrStr('Expected outputs by key, same notation as inputs. Mismatches come back as expect.diffs.'),
        trace: { type: 'boolean', description: "Also return every node's outputs." },
      },
      readOnly,
      async (a, d) =>
        source(a) ?? fromResult(await run({ file: file(a), inputs: text(a.inputs), vars: inlineVars(a.vars) ? VARS : a.vars, expect: text(a.expect), trace: a.trace }, d))
    ),
  ] satisfies McpTool[];
}

