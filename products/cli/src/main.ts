/** Process entry point: argument parsing, file/stdin access and exit code only (cli-spec.md §7). */
import { access, mkdir, readFile, writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { parseArgs } from 'node:util';
import { catalog, expand, guide, run, validateCmd, version, type Args, type CommandResult, type Deps } from './commands';
import { createServer, serve } from './mcp/server';
import { mcpInfo, mcpTools } from './mcp/tools';

const HELP = `Usage: nodecrypto <command> [args] [options]

Commands:
  catalog [--type <node type> | --list | --search <keyword…>]
                                  print the node catalog (or one node) as JSON, or list/search nodes
  validate <file|->               check a draft or package file
  expand <draft|-> [-o <file>]    expand a draft into a .ncw package
  run <file|-> [--inputs <JSON|file>] [--vars <file>] [--expect <JSON|file>] [--trace]
                                  validate and run, optionally compare with expected outputs
                                  and print every node's outputs (--trace)
  guide                           print the authoring guide
  mcp [--out-dir <folder>]        run as an MCP server for AI agents (see 'nodecrypto mcp --help')

Options:
  --json        machine-readable output
  --version     print versions
  -h, --help    show this help

Exit codes: 0 ok, 1 validation or expectation failure, 2 node/engine error, 64 usage error.
`;

const MCP_HELP = `Usage: nodecrypto mcp [--out-dir <folder>]

Run NodeCrypto as an MCP server on standard input/output, for AI agents (Claude Code, Claude Desktop, ...).
Tools: guide, catalog, validate, expand, run. expand saves a workflow as a .ncw file; open it in the web app (File > Open).

Options:
  --out-dir <folder>  where expand saves files by default
                      (env NODECRYPTO_OUT_DIR; default: ~/nodecrypto-workflows)
  -h, --help          show this help

Register it in your agent as a stdio server: command "npx", arguments "-y @curealls/nodecrypto mcp".
Standard output carries MCP messages only; logs go to standard error.
`;

const readStdin = async (): Promise<string> => {
  const chunks: Buffer[] = [];
  for await (const c of process.stdin) chunks.push(c as Buffer);
  return Buffer.concat(chunks).toString('utf8');
};
const deps: Deps = { readFile: (p) => readFile(p, 'utf8'), readStdin };

async function dispatch(argv: string[]): Promise<{ res: CommandResult; json: boolean }> {
  const json = argv.includes('--json');
  const usage = (message: string) => ({
    res: { exitCode: 64, data: { ok: false, issues: [{ code: 'CLI_USAGE', path: '', message }] }, text: '', stderr: `error[CLI_USAGE] ${message}\n` },
    json,
  });
  let parsed;
  try {
    parsed = parseArgs({
      args: argv,
      allowPositionals: true,
      options: {
        json: { type: 'boolean' },
        version: { type: 'boolean' },
        help: { type: 'boolean', short: 'h' },
        type: { type: 'string' },
        list: { type: 'boolean' },
        search: { type: 'string' },
        output: { type: 'string', short: 'o' },
        inputs: { type: 'string' },
        vars: { type: 'string' },
        expect: { type: 'string' },
        trace: { type: 'boolean' },
      },
    });
  } catch (e) {
    return usage((e as Error).message);
  }
  const { values, positionals } = parsed;
  const [command, ...tail] = positionals;
  // `catalog --search hash mac`: the words after the option are more keywords
  const words = command === 'catalog' && values.search !== undefined;
  const search = words ? [values.search, ...tail].join(' ') : values.search;
  const [file, ...rest] = words ? [] : tail;

  if (values.version) return { res: version(json), json: false };
  if (values.help || !command) return { res: { exitCode: 0, data: { help: HELP }, text: HELP, stderr: '' }, json: false };
  if (values.trace && command !== 'run') return usage('--trace is only valid for run');
  if (rest.length) return usage(`unexpected argument '${rest[0]}'`);
  if (!['validate', 'expand', 'run'].includes(command) && file !== undefined) return usage(`unexpected argument '${file}'`);
  const args: Args = { json, file, type: values.type, list: values.list, search, output: values.output, inputs: values.inputs, vars: values.vars, expect: values.expect, trace: values.trace };
  switch (command) {
    case 'catalog':
      return { res: catalog(args), json };
    case 'guide':
      return { res: guide(), json };
    case 'validate':
      return { res: await validateCmd(args, deps), json };
    case 'expand':
      return { res: await expand(args, deps), json };
    case 'run':
      return { res: await run(args, deps), json };
    default:
      return usage(`unknown command '${command}' (try --help)`);
  }
}

/** `nodecrypto mcp` (mcp-spec.md §2): serves until standard input closes. */
async function mcp(argv: string[]) {
  let values;
  try {
    values = parseArgs({ args: argv, options: { 'out-dir': { type: 'string' }, help: { type: 'boolean', short: 'h' } } }).values;
  } catch (e) {
    process.stderr.write(`error[CLI_USAGE] ${(e as Error).message}\n`);
    process.exitCode = 64;
    return;
  }
  if (values.help) return void process.stdout.write(MCP_HELP);
  process.stdout.on('error', () => process.exit(0)); // the agent went away
  const tools = mcpTools({
    ...deps,
    writeFile: (p, c) => writeFile(p, c, 'utf8'),
    mkdir: async (p) => void (await mkdir(p, { recursive: true })),
    exists: (p) => access(p).then(() => true, () => false),
    homedir,
    outDir: values['out-dir'] || process.env.NODECRYPTO_OUT_DIR || undefined,
  });
  await serve(process.stdin, (t) => process.stdout.write(t), createServer(mcpInfo(), tools));
}

if (process.argv[2] === 'mcp') await mcp(process.argv.slice(3));
else {
  const { res, json } = await dispatch(process.argv.slice(2));
  for (const f of res.files ?? []) await writeFile(f.path, f.content, 'utf8');
  if (json) {
    // the result JSON carries every problem, so nothing goes to stderr (§3.1)
    process.stdout.write(JSON.stringify(res.data, null, 2) + '\n');
  } else {
    if (res.text) process.stdout.write(res.text);
    if (res.stderr) process.stderr.write(res.stderr);
  }
  process.exitCode = res.exitCode;
}
