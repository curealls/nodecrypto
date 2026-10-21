# NodeCrypto

NodeCrypto turns a cryptographic procedure into a graph of nodes: AES, HMAC, HKDF, X25519, Ed25519, ML-KEM and more. You connect the nodes, run the graph and read every intermediate value.

- Website, workflow gallery and help: <https://nodecrypto.dev/>
- Web app (free to use): <https://app.nodecrypto.dev/>

## What is in this repository

| Path | Content | License |
| --- | --- | --- |
| `products/engine` | The workflow engine: node registry, runner, package format, built-in script | Apache-2.0 |
| `products/cli` | `@curealls/nodecrypto`: validate, run and expand workflows from the command line, or serve them to AI agents as an MCP server | Apache-2.0 |
| `examples/workflows` | Workflows and drafts, each checked against a published test vector or an independent implementation | Apache-2.0 |

The web app itself is not part of this repository.

## Command line

```
npx @curealls/nodecrypto guide
npx @curealls/nodecrypto catalog --search hmac
npx @curealls/nodecrypto run examples/workflows/drafts/hmac-sha256.json --expect examples/workflows/hmac-sha256.expect.json
```

To use it from an AI agent, register `npx -y @curealls/nodecrypto mcp` as a local stdio MCP server.

## Build and test

```
npm install
npm test
npm run build
```

Node.js 20 or later is required.

## Contributing

This repository is a snapshot published from the maintainers' internal source and is not edited directly. Please open an issue to report a problem or suggest a change.

## License

Apache-2.0. See `LICENSE`.
