# nodecrypto

Headless CLI for NodeCrypto workflows: validate, expand and run a workflow without the web app.

```
npx @curealls/nodecrypto guide                 # how to write a workflow draft
npx @curealls/nodecrypto catalog --search aes gcm   # find nodes (all keywords); --list prints every node
npx @curealls/nodecrypto catalog --type symmetric-aes-encrypt
npx @curealls/nodecrypto validate draft.json
npx @curealls/nodecrypto expand draft.json -o flow.ncw
npx @curealls/nodecrypto run flow.ncw --inputs '{"Key":"00..."}' --expect '{"Ciphertext":"..."}'
npx @curealls/nodecrypto run flow.ncw --inputs '{"Key":"00..."}' --trace   # also print every node's outputs
```

A matching `--expect` ends the text output with `# expect: matched <n> of <n> keys`. Add `--json` for machine-readable output. Exit codes: 0 ok, 1 validation or expectation failure, 2 node error, 64 usage error.
Requires Node.js 20 or later.

## MCP server (for AI agents)

`nodecrypto mcp` runs the same commands as a local [MCP](https://modelcontextprotocol.io) server on standard input/output, so an agent such as Claude Code or Claude Desktop can author, check and save workflows for you. It opens no port and makes no network access.

Register it as a stdio server with command `npx` and arguments `-y @curealls/nodecrypto mcp`:

```
claude mcp add --transport stdio nodecrypto -- npx -y @curealls/nodecrypto mcp
```

```json
{ "mcpServers": { "nodecrypto": { "command": "npx", "args": ["-y", "@curealls/nodecrypto", "mcp"] } } }
```

The JSON form goes in `claude_desktop_config.json` (Claude Desktop, then restart it) or `.cursor/mcp.json` (Cursor); VS Code's `.vscode/mcp.json` uses the top-level key `servers` instead of `mcpServers`.

Tools: `guide`, `catalog`, `validate`, `run` (same arguments as the commands above; `draft` takes the JSON object, `path` a file) and `expand`, which saves the workflow as a `.ncw` file and returns its absolute path. Open that file in the web app (https://nodecrypto.dev/) with File > Open.

`expand` saves to `~/nodecrypto-workflows` by default. Change the folder with `nodecrypto mcp --out-dir <folder>` or the environment variable `NODECRYPTO_OUT_DIR`, or pass `output` (a `.ncw` path) per call. An existing file is overwritten unless `overwrite` is `false`.

Do not put real secret keys into tool inputs: they pass through the agent conversation. Verify with published test vectors.

## License

Apache License 2.0, see `LICENSE`. The bundle includes `@noble/*` (MIT), see `THIRD-PARTY-NOTICES`.
