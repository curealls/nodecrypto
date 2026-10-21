import { describe, expect, it } from 'vitest';
import { createServer, serve, type McpTool } from '../src/mcp/server';

const info = { name: 'nodecrypto', title: 'NodeCrypto', version: '9.9.9', instructions: 'read guide first' };
const echo: McpTool = {
  name: 'echo',
  description: 'echo',
  inputSchema: { type: 'object' },
  annotations: { readOnlyHint: true },
  handler: async (a) => ({ text: JSON.stringify(a) }),
};
const bad: McpTool = { name: 'bad', description: 'fails', inputSchema: { type: 'object' }, handler: async () => ({ text: 'nope', isError: true }) };
const boom: McpTool = { name: 'boom', description: 'throws', inputSchema: { type: 'object' }, handler: async () => { throw new Error('kaboom'); } };

const V = 'io.modelcontextprotocol/protocolVersion';
const meta = (version = '2026-07-28', caps: unknown = {}) => ({ _meta: { [V]: version, 'io.modelcontextprotocol/clientCapabilities': caps } });
const server = () => createServer(info, [echo, bad, boom]);
const send = async (h: ReturnType<typeof server>, msg: unknown) => {
  const out = await h(typeof msg === 'string' ? msg : JSON.stringify(msg));
  return out === undefined ? undefined : JSON.parse(out);
};
const rpc = (method: string, params?: unknown, id: string | number = 1) => ({ jsonrpc: '2.0', id, method, ...(params !== undefined && { params }) });

describe('modern protocol (2026-07-28)', () => {
  it('server/discover', async () => {
    const r = await send(server(), rpc('server/discover', meta()));
    expect(r.result).toMatchObject({
      resultType: 'complete',
      supportedVersions: ['2026-07-28'],
      capabilities: { tools: {} },
      instructions: 'read guide first',
      ttlMs: 3_600_000,
      cacheScope: 'public',
      _meta: { 'io.modelcontextprotocol/serverInfo': { name: 'nodecrypto', version: '9.9.9' } },
    });
  });

  it('tools/list keeps declaration order and carries the cache fields', async () => {
    const r = (await send(server(), rpc('tools/list', meta()))).result;
    expect(r.resultType).toBe('complete');
    expect(r.ttlMs).toBe(3_600_000);
    expect(r.tools.map((t: { name: string }) => t.name)).toEqual(['echo', 'bad', 'boom']);
    expect(r.tools[0].annotations).toEqual({ readOnlyHint: true });
    expect(r.tools[1]).not.toHaveProperty('annotations');
  });

  it('tools/call returns text content', async () => {
    const r = (await send(server(), rpc('tools/call', { ...meta(), name: 'echo', arguments: { a: 1 } }))).result;
    expect(r).toMatchObject({ resultType: 'complete', content: [{ type: 'text', text: '{"a":1}' }], isError: false });
  });

  it('tool errors stay results, handler exceptions too', async () => {
    const h = server();
    expect((await send(h, rpc('tools/call', { ...meta(), name: 'bad' }))).result).toMatchObject({ isError: true, content: [{ text: 'nope' }] });
    const r = (await send(h, rpc('tools/call', { ...meta(), name: 'boom' }))).result;
    expect(r).toMatchObject({ isError: true, content: [{ text: 'internal error: kaboom' }] });
    expect((await send(h, rpc('ping', meta()))).result.resultType).toBe('complete'); // still serving
  });

  it('unknown tool and bad arguments are protocol errors', async () => {
    const h = server();
    expect((await send(h, rpc('tools/call', { ...meta(), name: 'nope' }))).error).toMatchObject({ code: -32602, message: 'Unknown tool: nope' });
    expect((await send(h, rpc('tools/call', { ...meta(), name: 'echo', arguments: [] }))).error.code).toBe(-32602);
  });

  it('rejects an unsupported version with the supported list', async () => {
    const r = await send(server(), rpc('tools/list', meta('1900-01-01')));
    expect(r.error).toEqual({ code: -32022, message: 'Unsupported protocol version', data: { supported: ['2026-07-28'], requested: '1900-01-01' } });
  });

  it('rejects a request without clientCapabilities', async () => {
    const r = await send(server(), rpc('tools/list', { _meta: { [V]: '2026-07-28' } }));
    expect(r.error.code).toBe(-32602);
  });

  it('unknown method', async () => {
    expect((await send(server(), rpc('resources/list', meta()))).error.code).toBe(-32601);
  });

  it('works without initialize and keeps no state between requests', async () => {
    const h = server();
    await send(h, rpc('server/discover', meta()));
    expect((await send(h, rpc('tools/list', { _meta: { [V]: '2026-07-28' } }))).error.code).toBe(-32602);
  });
});

describe('legacy protocol (initialize)', () => {
  const init = (protocolVersion: unknown) => rpc('initialize', { protocolVersion, capabilities: {}, clientInfo: { name: 'c', version: '1' } });

  it('echoes a supported version and answers capabilities and instructions', async () => {
    const r = (await send(server(), init('2025-06-18'))).result;
    expect(r).toEqual({
      protocolVersion: '2025-06-18',
      capabilities: { tools: {} },
      serverInfo: { name: 'nodecrypto', title: 'NodeCrypto', version: '9.9.9' },
      instructions: 'read guide first',
    });
  });

  it('answers the latest legacy version for an unknown one', async () => {
    expect((await send(server(), init('1.0.0'))).result.protocolVersion).toBe('2025-11-25');
    expect((await send(server(), init(42))).result.protocolVersion).toBe('2025-11-25');
  });

  it('rejects tools before initialize, serves them after, without modern-only fields', async () => {
    const h = server();
    const early = await send(h, rpc('tools/list'));
    expect(early.error.code).toBe(-32600);
    expect(early.error.message).toContain('initialize');
    await send(h, init('2025-11-25'));
    expect(await send(h, { jsonrpc: '2.0', method: 'notifications/initialized' })).toBeUndefined();
    const list = (await send(h, rpc('tools/list'))).result;
    expect(Object.keys(list)).toEqual(['tools']);
    const call = (await send(h, rpc('tools/call', { name: 'echo', arguments: { x: 'y' } }))).result;
    expect(call).toEqual({ content: [{ type: 'text', text: '{"x":"y"}' }], isError: false });
  });

  it('ping works before initialize', async () => {
    expect((await send(server(), rpc('ping'))).result).toEqual({});
  });

  it('unknown method after initialize', async () => {
    const h = server();
    await send(h, init('2025-11-25'));
    expect((await send(h, rpc('prompts/list'))).error.code).toBe(-32601);
  });
});

describe('framing and malformed input', () => {
  it('parse error answers id null', async () => {
    expect(await send(server(), '{nope')).toEqual({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
  });

  it('invalid requests', async () => {
    const h = server();
    expect((await send(h, [rpc('ping')])).error.code).toBe(-32600); // batches are not part of MCP
    expect((await send(h, { jsonrpc: '2.0', id: 3 })).error).toMatchObject({ code: -32600 });
    expect((await send(h, { jsonrpc: '2.0', id: 3 })).id).toBe(3);
    expect((await send(h, { jsonrpc: '2.0', id: null, method: 'ping' })).error.code).toBe(-32600);
    expect((await send(h, { jsonrpc: '2.0', id: 1, method: 'ping', params: [] })).error.code).toBe(-32602);
  });

  it('notifications get no reply, even unknown ones', async () => {
    const h = server();
    expect(await send(h, { jsonrpc: '2.0', method: 'notifications/cancelled', params: { requestId: 1 } })).toBeUndefined();
    expect(await send(h, { jsonrpc: '2.0', method: 'whatever' })).toBeUndefined();
  });

  it('serve() splits lines across chunks, handles CRLF, blank lines, multibyte splits and a missing final newline', async () => {
    const h = createServer(info, [echo]);
    const lines = [JSON.stringify(rpc('tools/call', { ...meta(), name: 'echo', arguments: { s: '키' } }, 1)), '', JSON.stringify(rpc('ping', meta(), 2)), JSON.stringify(rpc('ping', meta(), 3))];
    const bytes = new TextEncoder().encode(lines[0] + '\r\n' + lines[1] + '\n' + lines[2] + '\n' + lines[3]);
    const cut = (n: number) => bytes.slice(0, n);
    const hangul = lines[0].indexOf('키'); // split in the middle of a 3-byte character
    const first = new TextEncoder().encode(lines[0].slice(0, hangul)).length + 1;
    async function* chunks() {
      yield cut(first);
      yield bytes.slice(first, first + 40);
      yield bytes.slice(first + 40);
    }
    const out: string[] = [];
    await serve(chunks(), (t) => out.push(t), h);
    expect(out).toHaveLength(3);
    expect(out.every((l) => l.endsWith('\n') && !l.slice(0, -1).includes('\n'))).toBe(true);
    const msgs = out.map((l) => JSON.parse(l));
    expect(msgs.map((m) => m.id)).toEqual([1, 2, 3]);
    expect(msgs[0].result.content[0].text).toBe('{"s":"키"}');
    expect(out.every((l) => JSON.parse(l).jsonrpc === '2.0')).toBe(true); // nothing but protocol messages
  });

  it('serve() ends cleanly on empty input and accepts string chunks', async () => {
    const out: string[] = [];
    async function* none() {}
    await serve(none(), (t) => out.push(t), server());
    async function* one() {
      yield JSON.stringify(rpc('ping', meta())) + '\n';
    }
    await serve(one(), (t) => out.push(t), server());
    expect(out).toHaveLength(1);
  });
});
