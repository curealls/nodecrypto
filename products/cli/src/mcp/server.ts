/**
 * MCP stdio server core (mcp-spec.md §3): JSON-RPC framing, the modern (2026-07-28, per-request `_meta`)
 * and legacy (`initialize`) protocol styles, and tool dispatch. No process, file or network access: lines in, lines out.
 */

export interface McpTool {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  annotations?: Record<string, unknown>;
  /** `isError` marks a tool execution error (the agent reads it and retries), not a protocol error. */
  handler(args: Record<string, unknown>): Promise<{ text: string; isError?: boolean }>;
}

export interface McpInfo {
  name: string;
  title: string;
  version: string;
  instructions: string;
}

/** One input line -> one output line (without the newline), or undefined for notifications. */
export type LineHandler = (line: string) => Promise<string | undefined>;

const V = 'io.modelcontextprotocol/protocolVersion';
const CAPS = 'io.modelcontextprotocol/clientCapabilities';
const SERVER_INFO = 'io.modelcontextprotocol/serverInfo';
const MODERN = ['2026-07-28'];
const LEGACY = ['2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];
// tools never change while the process runs
const CACHE = { ttlMs: 3_600_000, cacheScope: 'public' };

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);

class RpcError extends Error {
  constructor(readonly code: number, message: string, readonly data?: unknown) {
    super(message);
  }
}

export function createServer(info: McpInfo, tools: McpTool[]): LineHandler {
  let initialized = false; // legacy only: has `initialize` been seen
  const serverInfo = { name: info.name, version: info.version };
  const listed = tools.map(({ name, description, inputSchema, annotations }) => ({ name, description, inputSchema, ...(annotations && { annotations }) }));

  const callTool = async (params: Record<string, unknown>) => {
    const tool = tools.find((t) => t.name === params.name);
    if (!tool) throw new RpcError(-32602, `Unknown tool: ${String(params.name)}`);
    if (params.arguments !== undefined && !isObj(params.arguments)) throw new RpcError(-32602, 'arguments must be an object');
    try {
      const r = await tool.handler((params.arguments as Record<string, unknown> | undefined) ?? {});
      return { content: [{ type: 'text', text: r.text }], isError: r.isError === true };
    } catch (e) {
      return { content: [{ type: 'text', text: `internal error: ${(e as Error).message}` }], isError: true };
    }
  };

  const modern = async (method: string, params: Record<string, unknown>) => {
    const meta = params._meta as Record<string, unknown>;
    if (typeof meta[V] !== 'string' || !MODERN.includes(meta[V])) throw new RpcError(-32022, 'Unsupported protocol version', { supported: MODERN, requested: meta[V] });
    if (!isObj(meta[CAPS])) throw new RpcError(-32602, `Missing ${CAPS}`);
    let result: Record<string, unknown>;
    switch (method) {
      case 'ping':
        result = {};
        break;
      case 'server/discover':
        result = { supportedVersions: MODERN, capabilities: { tools: {} }, instructions: info.instructions, ...CACHE };
        break;
      case 'tools/list':
        result = { tools: listed, ...CACHE };
        break;
      case 'tools/call':
        result = await callTool(params);
        break;
      default:
        throw new RpcError(-32601, `Method not found: ${method}`);
    }
    return { resultType: 'complete', ...result, _meta: { [SERVER_INFO]: serverInfo } };
  };

  const legacy = async (method: string, params: Record<string, unknown>) => {
    switch (method) {
      case 'ping':
        return {};
      case 'initialize': {
        initialized = true;
        const asked = params.protocolVersion;
        return {
          protocolVersion: typeof asked === 'string' && LEGACY.includes(asked) ? asked : LEGACY[0],
          capabilities: { tools: {} },
          serverInfo: { name: info.name, title: info.title, version: info.version },
          instructions: info.instructions,
        };
      }
    }
    if (!initialized) throw new RpcError(-32600, `Send initialize first, or include ${V} in params._meta`);
    if (method === 'tools/list') return { tools: listed };
    if (method === 'tools/call') return callTool(params);
    throw new RpcError(-32601, `Method not found: ${method}`);
  };

  return async (line) => {
    const reply = (id: unknown, body: object) => JSON.stringify({ jsonrpc: '2.0', id, ...body });
    let msg: unknown;
    try {
      msg = JSON.parse(line);
    } catch {
      return reply(null, { error: { code: -32700, message: 'Parse error' } });
    }
    if (!isObj(msg) || typeof msg.method !== 'string') return reply(isObj(msg) && (typeof msg.id === 'string' || typeof msg.id === 'number') ? msg.id : null, { error: { code: -32600, message: 'Invalid request' } });
    if (msg.id === undefined) return undefined; // notification (incl. notifications/initialized, notifications/cancelled): nothing to do
    if (typeof msg.id !== 'string' && typeof msg.id !== 'number') return reply(null, { error: { code: -32600, message: 'Invalid request id' } });
    try {
      if (msg.params !== undefined && !isObj(msg.params)) throw new RpcError(-32602, 'params must be an object');
      const params = msg.params ?? {};
      const isModern = isObj(params._meta) && params._meta[V] !== undefined;
      return reply(msg.id, { result: await (isModern ? modern : legacy)(msg.method, params) });
    } catch (e) {
      if (e instanceof RpcError) return reply(msg.id, { error: { code: e.code, message: e.message, ...(e.data !== undefined && { data: e.data }) } });
      return reply(msg.id, { error: { code: -32603, message: 'Internal error' } });
    }
  };
}

/** Reads newline-delimited messages from `input` and writes each reply as one line. Returns when the input ends. */
export async function serve(input: AsyncIterable<string | Uint8Array>, write: (text: string) => void, handle: LineHandler): Promise<void> {
  const decoder = new TextDecoder();
  let buf = '';
  const run = async (raw: string) => {
    const line = raw.trim();
    const out = line ? await handle(line) : undefined;
    if (out) write(out + '\n');
  };
  for await (const chunk of input) {
    buf += typeof chunk === 'string' ? chunk : decoder.decode(chunk, { stream: true });
    for (let i = buf.indexOf('\n'); i >= 0; i = buf.indexOf('\n')) {
      const raw = buf.slice(0, i);
      buf = buf.slice(i + 1);
      await run(raw);
    }
  }
  await run(buf);
}
