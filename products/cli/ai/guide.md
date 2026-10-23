# NodeCrypto authoring guide for AI agents

NodeCrypto is a visual tool for cryptographic workflows: nodes (AES, HMAC, HKDF, ...) wired into a graph and run in the browser.
You write the graph as a small JSON **draft**, check it with the CLI, and hand the verified result to the user, who opens it on the canvas.

- Node types, ports and properties live in the **catalog** (`ai/catalog.json`, or `npx @curealls/nodecrypto catalog --type <type>`). Find a node with `npx @curealls/nodecrypto catalog --search <keywords>` (all keywords must match; `--list` prints every node, one line each), then read it with `--type`. This guide does not repeat the catalog: it covers concepts, procedure and traps.
- Never guess a node type, port `id` or property value. Look it up in the catalog, then validate.

## 1. Concepts

- A workflow is a **DAG**: nodes with input and output ports, connected by edges. No cycles. Each input port takes at most one edge.
- **Ids are keys, names are labels.** Nodes are addressed by node `id` (you choose it, e.g. `aes`), ports by port `id` (e.g. `plaintext`). A port `name` is only a display label and may repeat. Rename a fixed port with `portNames` (section 3); never change its `id`. Edges are written `"<node id>.<port id>"`.
- **Data types**:

| Type | Meaning | CLI notation |
| --- | --- | --- |
| `bytes` | octet string (keys, IVs, ciphertext, digests) | hex string, even length, no `0x` |
| `string` | UTF-8 text | JSON string |
| `int` | mathematical integer, no overflow (bigint) | decimal **string**, e.g. `"-42"` |
| `bool` | true / false | JSON `true` / `false` |
| `any` | accepts any one type except `set`; used by comparators and sinks | |
| `set` | a whole `ValueSet` row list passed as one value | only between `ValueSet.set` and `Switch` inputs |

- **Edge rule**: source and target types must be equal. `any` matches every type except `set`; `set` connects only to `set`. There is no implicit conversion: insert a converter node (`converter-hex-to-bytes`, `converter-string-to-bytes`, `utility-bytes-to-int`, ...).
- **Visible ports.** Many nodes show different ports depending on a property (AES `mode` shows `iv`, or `nonce` + `aad` + `tag`). The catalog marks this with `visibleWhen`. An edge to a hidden port is an error, and so is setting a hidden property to a non-default value.
- Execution order follows the edges. A node runs when its inputs are ready; if a node fails, everything downstream is skipped.

## 2. Procedure

1. **Pick nodes.** Search with `nodecrypto catalog --search <keywords>` (or search `ai/catalog.json` by `description`, `category` and `type`). Use standard nodes for the cryptographic steps (cipher, MAC, KDF, hash, signature, key agreement) and one `utility-script` node for the byte plumbing between them (see section 6).
2. **Write the draft** (section 3). Put inputs the user may change in `workflow-input`, results in `workflow-output`. Add a short `note` to every node whose role, source or parameters a reviewer would otherwise have to guess (section 3, *Notes*).
3. **Validate**: `npx @curealls/nodecrypto validate draft.json`. Exit 0 = OK. Each issue has a `code`, a JSON `path` and usually a `hint`.
4. **Run and compare**: `npx @curealls/nodecrypto run draft.json --expect expect.json`. Use a published test vector for the expected values and cite where it comes from.
5. **Read the problem list and fix**, then go back to step 3. Use `--json` for machine-readable output.
6. **Hand over** only a result that passed validation and the expected-value comparison: the draft (`.json`) or the expanded package (`npx @curealls/nodecrypto expand draft.json -o name.ncw`). The user opens either with *File > Open* or *Open as text* in the web app.

When you are connected through MCP (`nodecrypto mcp`), call the tool of the same name instead of the command (`guide`, `catalog`, `validate`, `run`); `expand` saves the `.ncw` file and returns its path, which you tell the user.

Other commands: `nodecrypto catalog [--type <type> | --list | --search <keywords>]`, `nodecrypto guide` (prints this guide), `nodecrypto --version`.
`--inputs`, `--vars` and `--expect` take a JSON object or a file path. `--trace` also prints the outputs of every node. When `--expect` matches, the last text line is `# expect: matched <n> of <n> keys`. Exit codes: 0 ok, 1 validation or expectation failed, 2 a node failed at run time, 64 usage error.

## 3. Draft format

A draft is a workflow with everything optional left out. Top level: `draft` (always `1`), `name`, `description?`, `nodes`, `edges?`, `variables?`. Unknown fields are errors.

- **Node**: `{ "id", "type", "label"?, "note"?, "props"?, "portNames"?, "inputs"?, "outputs"?, "position"? }`.
  - `id`: unique, `[A-Za-z0-9_-]`, 1-64 chars, no `.`.
  - `note`: a memo for the person who reviews the workflow (see *Notes* below).
  - `props`: only values that differ from the catalog default.
  - `position`: omit it; nodes are laid out automatically.
- **Notes**: use `note` generously; a person opens the workflow on the canvas and reads it node by node, so the memo is where your reasoning survives. Good notes say what the step does in the protocol, where a value comes from (RFC section, test vector, standard), why a parameter was chosen, and any caveat (a zero IV that is intended, a value that is random on every run). Plain markdown, at most 20,000 characters, but keep each note short (a few lines to a short list): headings (`#`), lists (`-`, `1.`), `**bold**`, `*italic*`, `` `code` ``, code blocks, quotes (`>`) and rules (`---`). Links, tables, images and HTML are not rendered and show as written. A note never affects execution or the validation result, and an empty or blank `note` is dropped.
- **Ports**: omit `inputs`/`outputs` for fixed-port nodes. For nodes with `dynamicInputs` / `dynamicOutputs` in the catalog (`workflow-input`, `workflow-output`, `utility-concat`, `utility-bitwise`, `utility-script`, `input-value-set`, `switch`) you must list that side: `{ "id", "dataType", "name"? }`.
- **Port names (`portNames`)**: `{ "<port id>": "<name>" }` renames ports of a fixed side (the fixed ports of any node, the fixed side of a variable-port node). List only the ports you rename; the `id` is the key and never changes. Variable ports are named in `inputs`/`outputs` instead; a variable port's `id` here is an error. Use `inputs.<id>` / `outputs.<id>` when the same `id` exists on both sides (`symmetric-chacha20-stream` `data`).
  - Name a port by the **role** it plays in this workflow (`Session Key`, `Packet Payload`), in one consistent style (capitalised words, no abbreviations). Leave the default when it is already clear. Put length and encoding in `note`, not in the name.
  - A name must not be empty, contain `/ , ( )`, or repeat another name on the same side of that node.
  - Set `mode` first: a hidden port (AES `iv` under `ECB`) cannot be renamed.
- **Workflow Input port** may also carry `constraint` (`{"lengths":[16,32]}`, `{"lengths":["16*N"]}`, `{"min":"0","max":"255"}`), `defaultValue` (string) and `description`.
- **Edge**: `{ "from": "node.port", "to": "node.port" }`.

Minimal example: AES-256-GCM encryption (also shows that `tag` exists only because `mode` is `GCM`).

```json
{
  "draft": 1,
  "name": "AES-256-GCM Encrypt",
  "description": "Encrypts a message with AES-256-GCM and returns the ciphertext and the tag.",
  "nodes": [
    { "id": "in", "type": "workflow-input",
      "outputs": [
        { "id": "key", "dataType": "bytes", "name": "Key", "constraint": { "lengths": [32] } },
        { "id": "nonce", "dataType": "bytes", "name": "Nonce", "constraint": { "lengths": [12] } },
        { "id": "pt", "dataType": "bytes", "name": "Plaintext" }
      ] },
    { "id": "aes", "type": "symmetric-aes-encrypt", "props": { "mode": "GCM" },
      "note": "# AES-256-GCM\n- Key: 32 bytes, nonce: 12 bytes (the 96-bit size GCM is designed for)\n- Never reuse a nonce with the same key\n- `tag` exists only because `mode` is `GCM`" },
    { "id": "out", "type": "workflow-output",
      "inputs": [
        { "id": "ct", "dataType": "bytes", "name": "Ciphertext" },
        { "id": "tag", "dataType": "bytes", "name": "Tag" }
      ] }
  ],
  "edges": [
    { "from": "in.key", "to": "aes.key" },
    { "from": "in.nonce", "to": "aes.nonce" },
    { "from": "in.pt", "to": "aes.plaintext" },
    { "from": "aes.ciphertext", "to": "out.ct" },
    { "from": "aes.tag", "to": "out.tag" }
  ]
}
```

With role names on the fixed ports of the AES node (the edges stay on the port `id`s):

```json
{ "id": "aes", "type": "symmetric-aes-encrypt", "props": { "mode": "GCM" },
  "portNames": { "plaintext": "Packet Payload", "ciphertext": "Encrypted Payload", "tag": "Authentication Tag" } }
```

Verified drafts with published test vectors (each has a `.expect.json` next to its `.ncw`) are in `examples/workflows/drafts/` of the repository, <https://github.com/curealls/nodecrypto/tree/main/examples/workflows/drafts>:

| Draft | What it does | Test vector |
| --- | --- | --- |
| [aes-gcm](https://github.com/curealls/nodecrypto/blob/main/examples/workflows/drafts/aes-gcm.json) | AES-GCM with tag | RFC 7714 |
| [aes-gcm-named](https://github.com/curealls/nodecrypto/blob/main/examples/workflows/drafts/aes-gcm-named.json) | the same with `portNames` | RFC 7714 |
| [hmac-sha256](https://github.com/curealls/nodecrypto/blob/main/examples/workflows/drafts/hmac-sha256.json) | HMAC-SHA-256 | RFC 4231 |
| [hkdf-sha256](https://github.com/curealls/nodecrypto/blob/main/examples/workflows/drafts/hkdf-sha256.json) | HKDF extract and expand | RFC 5869 |
| [pbkdf2-sha256](https://github.com/curealls/nodecrypto/blob/main/examples/workflows/drafts/pbkdf2-sha256.json) | PBKDF2 | RFC 7914 |
| [x25519-ecdh](https://github.com/curealls/nodecrypto/blob/main/examples/workflows/drafts/x25519-ecdh.json) | X25519 shared secret | RFC 7748 |
| [x25519-hkdf](https://github.com/curealls/nodecrypto/blob/main/examples/workflows/drafts/x25519-hkdf.json) | X25519 then HKDF session key | RFC 7748 + RFC 5869 |
| [x25519-hkdf-named](https://github.com/curealls/nodecrypto/blob/main/examples/workflows/drafts/x25519-hkdf-named.json) | the same with `portNames` on both nodes | RFC 7748 + RFC 5869 |
| [ed25519-sign](https://github.com/curealls/nodecrypto/blob/main/examples/workflows/drafts/ed25519-sign.json) | Ed25519 signature | RFC 8032 |
| [seed-ecb](https://github.com/curealls/nodecrypto/blob/main/examples/workflows/drafts/seed-ecb.json) | SEED-128 ECB (Korean standard) | RFC 4269 |
| [cmac-aes](https://github.com/curealls/nodecrypto/blob/main/examples/workflows/drafts/cmac-aes.json) | AES-CMAC | RFC 4493 |
| [mlkem-768-decaps](https://github.com/curealls/nodecrypto/blob/main/examples/workflows/drafts/mlkem-768-decaps.json) | ML-KEM-768 decapsulation with the 2400-byte secret key | C2SP CCTV |
| [mlkem-roundtrip](https://github.com/curealls/nodecrypto/blob/main/examples/workflows/mlkem-roundtrip.ncw) | ML-KEM keygen, encaps, decaps, shared secrets equal (`bool`); a saved workflow, there is no draft file | random: only the `bool` is compared |

## 4. Workflow Input and Output

- Anything the user may want to change goes into a `workflow-input` port (give it a `name`, a `defaultValue` so it runs as is, and a `constraint` when the length is fixed). Final results go into `workflow-output` ports.
- Do not bake changeable values into `input-static-value` nodes. Fixed constants (a label, a protocol constant) may stay there.
- CLI keys are **port names** (the port `id` if two names collide). Without a `workflow-output`, results are reported as `<node id>.<port id>` for nodes that have no outgoing edge.
- Give every Workflow Input/Output port a distinct `name`; two ports with the same key are rejected (`PORT_KEY_AMBIGUOUS`).

## 5. Traps

- **IV and nonce default to zeros.** Leaving `iv` / `nonce` unconnected does not fail: the node uses all-zero bytes. This is deterministic and almost never what the user wants. Always connect a real IV or nonce, or say explicitly that zeros are intended (test vectors).
- **Mode changes ports.** `ECB` has no `iv`; `CBC`/`CTR`/`CFB`/`OFB`/`XTS` have `iv`; `GCM`/`CCM` have `nonce`, `aad` and the `tag` output. Set `mode` first, then wire. Hidden ports and hidden property values are errors (`EDGE_PORT_HIDDEN`, `PROP_HIDDEN`).
- **Renaming does not change keys.** `--expect` and `--inputs` keys are `workflow-input`/`workflow-output` port names; the names in `portNames` never appear there. Naming a hidden port is `PORT_NAME_UNKNOWN_PORT`: fix `mode` or drop the entry. A draft with `portNames` is rejected by CLI versions before 0.2.1 (`DRAFT_UNKNOWN_FIELD`).
- **Padding defaults to `None`.** Block-cipher ECB/CBC then require input whose length is a multiple of the block size, otherwise the node fails (`..._NOT_BLOCK_ALIGNED`). Set `padding` (e.g. `PKCS7`) for arbitrary lengths. Decrypt must use the same padding, and a wrong key typically ends in `INVALID_PADDING`.
- **`int` is arbitrary precision.** Write `int` values in the CLI and in `Workflow Input` `defaultValue` as decimal strings. JSON numbers beyond 2^53 lose precision when parsed, so always use strings for large values. `int` is never wrapped to a width: use `utility-int-to-bytes` (length, endian, signed) to get bytes.
- **Random values change every run.** `input-random`, key-generation nodes and anything fed by them (ML-KEM, RSA/ECC key generation) give different output on each run. Compare only deterministic outputs or a `bool` verdict (e.g. `utility-compare` on two derived secrets).
- **Verification nodes report, they do not throw.** Verify and compare nodes return a `bool` (port with `errorProfile.kind = "judgement"`). Check that bool in `--expect`; a `false` is not an exit-code failure by itself.
- **ValueSet and Switch.** `input-value-set` lists its rows as outputs and **must end with the reserved port** `{ "id": "set", "dataType": "set" }`. Row ports are `out_1`, `out_2`, ... and `props.rows.<port id>` holds `{ "mode": "fixed", "value": ... }`, `{ "mode": "random", "length": n }` (`int`: `min`/`max`) or `{ "mode": "input" }`. `switch` has one `set` input per set (`in_1`, `in_2`, ...); its outputs must repeat the rows (`id`, `name`, `dataType`) of the first connected ValueSet; `props.activeInput` names the input that is used. Only the active input is evaluated, an inactive set may even be broken.
- **Variable references (`$var`).** Properties that allow variables (catalog `variable`) accept `{ "$var": "$group.name" }` instead of a literal. Use them only for a value that the user keeps in the NodeCrypto *Value Registry* and shares between workflows. Do not use them for ordinary one-off constants: write the literal. A reference needs a value: add a `variables` block to the draft (the file becomes self-contained) or pass `--vars <registry file>`; otherwise the node fails with `VARIABLE_UNRESOLVED`. Ports, names and script code cannot take references.
- **Hex properties** (`hex` type) are plain hex, even number of digits, whitespace allowed, no `0x`.
- **Omitted optional inputs have defaults.** `kdf-pbkdf2` `salt` defaults to 16 zero bytes; `kdf-hkdf` `salt` defaults to the RFC 5869 zero salt and `info` to empty. Connect a real salt unless a test vector says otherwise.
- **Property value types.** Catalog `number` properties take plain JSON numbers (`"iterations": 1000`); only `text` properties (e.g. `utility-slicer` `length`) take strings. The "decimal string" rule above is for `int` data ports and `Workflow Input` values.
- **Dynamic-port ids are free.** For `utility-concat` and other `dynamicInputs` nodes, you choose the port ids (`a`, `b`, ...); the order of the `inputs` list is the order of concatenation. A non-bytes input is encoded as: `string` UTF-8, `bool` one byte (`00`/`01`), `int` its minimal big-endian unsigned bytes. For a fixed width or endianness, convert in a script (`to_bytes(n, 4)`) or insert `utility-int-to-bytes`.
- **RSA keys are DER `bytes` only.** RSA key ports take SPKI (public) or PKCS#8 (private) DER; PEM text and PKCS#1 are not accepted. `asymmetric-rsa-key-decode` splits a key into `n`, `e` (and `d`, `p`, `q`, `dp`, `dq`, `qInv` for `keyType` `Private`); `asymmetric-rsa-key-encode` builds a key from `n`, `e` (and `d`). Components are big-endian `bytes`. `saltLength` of `asymmetric-rsa-sign`/`-verify` is visible only with the `PSS` scheme (`visibleWhen`) and must match on both sides. PSS signatures are randomized: with `--expect`, compare the `bool` of the verification, not the signature.

## Common patterns

- **Two or more values from one derivation.** `kdf-hkdf` has a single output. Set `keyLength` to the total (e.g. 44 = 32-byte key + 12-byte nonce) and cut it in one script: `key = okm[0, 32]` and `nonce = okm[32, 12]`. For an encryption key and a separate MAC key from one password, use two `kdf-pbkdf2` nodes with different salts, or one derivation and a script that cuts two keys.
- **Encrypt-then-MAC.** `kdf-*` (keys), then `symmetric-aes-encrypt` (`mode: CBC`, `padding: PKCS7`, real IV), then `mac-hmac` over `iv + ciphertext`. Build `iv + ciphertext` with a one-line script (`out = iv + ct`). Verify the MAC before decrypting.
- **Checksum then encrypt.** `utility-crc` outputs an `int`. One script appends it: `framed = msg + to_bytes(crc, 4)` (big endian), then encrypt `framed`. The example below does exactly this.
- **X25519 public key from a private key.** There is no dedicated node (`asymmetric-x25519-keygen` is random). Use `asymmetric-x25519-ecdh` with the peer public key set to the base point `09` followed by 31 zero bytes.
- **Hybrid KEM.** `pqc-hybridkem-*` is a ready-made X25519 + ML-KEM-768 KEM. To compose it yourself, use `pqc-mlkem-*` and `asymmetric-x25519-*`, `utility-concat` the two shared secrets and run `kdf-hkdf` (or a hash) over them. The ML-KEM secret key is the expanded 2400-byte form, not a 64-byte seed.
- **Seeing intermediate values.** `run` prints only `workflow-output` ports. Add `--trace` to also get every successful node's outputs (`trace <node id>.<port id>: <value>` lines, or `trace` in `--json`), including when a later node fails. Trace values include secrets such as keys: do not share the log.
- **Independent checking has limits.** Node's `crypto` has no SEED, and the ML-KEM full-size secret key (2400 bytes for ML-KEM-768) can only be compared with published vectors. ML-KEM encapsulation and decapsulation are checked against the C2SP CCTV vectors (`examples/workflows/drafts/mlkem-768-decaps.json`); ML-KEM key generation and SEED modes other than ECB have no standard vector here, so a round trip is the only check for them.

A closed draft with a variable reference:

```json
{
  "draft": 1,
  "name": "AES-128-ECB with a stored key",
  "nodes": [
    { "id": "in", "type": "workflow-input",
      "outputs": [ { "id": "pt", "dataType": "bytes", "name": "Plaintext", "defaultValue": "00112233445566778899aabbccddeeff" } ] },
    { "id": "key", "type": "input-static-value", "props": { "type": "bytes", "valueBytes": { "$var": "$demo.key" } } },
    { "id": "aes", "type": "symmetric-aes-encrypt" },
    { "id": "out", "type": "workflow-output", "inputs": [ { "id": "ct", "dataType": "bytes", "name": "Ciphertext" } ] }
  ],
  "edges": [
    { "from": "in.pt", "to": "aes.plaintext" },
    { "from": "key.value", "to": "aes.key" },
    { "from": "aes.ciphertext", "to": "out.ct" }
  ],
  "variables": {
    "$demo.key": { "name": "Demo key", "type": "bytes", "default": "000102030405060708090a0b0c0d0e0f" }
  }
}
```

A ValueSet with a Switch (the first set is inactive here):

```json
{
  "draft": 1,
  "name": "Pick a key set",
  "nodes": [
    { "id": "a", "type": "input-value-set",
      "props": { "rows": { "out_1": { "mode": "fixed", "value": "aa" }, "out_2": { "mode": "fixed", "value": 1 } } },
      "outputs": [ { "id": "out_1", "dataType": "bytes", "name": "Key" }, { "id": "out_2", "dataType": "int", "name": "Id" }, { "id": "set", "dataType": "set" } ] },
    { "id": "b", "type": "input-value-set",
      "props": { "rows": { "out_1": { "mode": "fixed", "value": "bb" }, "out_2": { "mode": "fixed", "value": 2 } } },
      "outputs": [ { "id": "out_1", "dataType": "bytes", "name": "Key" }, { "id": "out_2", "dataType": "int", "name": "Id" }, { "id": "set", "dataType": "set" } ] },
    { "id": "sw", "type": "switch", "props": { "activeInput": "in_2" },
      "inputs": [ { "id": "in_1", "dataType": "set", "name": "A" }, { "id": "in_2", "dataType": "set", "name": "B" } ],
      "outputs": [ { "id": "out_1", "dataType": "bytes", "name": "Key" }, { "id": "out_2", "dataType": "int", "name": "Id" } ] },
    { "id": "out", "type": "workflow-output",
      "inputs": [ { "id": "key", "dataType": "bytes", "name": "Key" }, { "id": "id", "dataType": "int", "name": "Id" } ] }
  ],
  "edges": [
    { "from": "a.set", "to": "sw.in_1" },
    { "from": "b.set", "to": "sw.in_2" },
    { "from": "sw.out_1", "to": "out.key" },
    { "from": "sw.out_2", "to": "out.id" }
  ]
}
```

A checksum appended by one script instead of `utility-int-to-bytes` + `utility-concat`:

```json
{
  "draft": 1,
  "name": "Message + CRC-32, encrypted with SEED-CBC",
  "nodes": [
    { "id": "in", "type": "workflow-input",
      "outputs": [
        { "id": "key", "dataType": "bytes", "name": "Key", "constraint": { "lengths": [16] }, "defaultValue": "000102030405060708090a0b0c0d0e0f" },
        { "id": "iv", "dataType": "bytes", "name": "IV", "constraint": { "lengths": [16] }, "defaultValue": "f0e1d2c3b4a5968778695a4b3c2d1e0f" },
        { "id": "msg", "dataType": "bytes", "name": "Message", "defaultValue": "434152442d4d53473a48454c4c4f" }
      ] },
    { "id": "crc", "type": "utility-crc" },
    { "id": "frame", "type": "utility-script",
      "props": { "code": "framed = msg + to_bytes(crc, 4)\n" },
      "inputs": [ { "id": "msg", "dataType": "bytes" }, { "id": "crc", "dataType": "int" } ],
      "outputs": [ { "id": "framed", "dataType": "bytes" } ] },
    { "id": "seed", "type": "symmetric-seed-encrypt", "props": { "mode": "CBC", "padding": "PKCS7" } },
    { "id": "out", "type": "workflow-output", "inputs": [ { "id": "ct", "dataType": "bytes", "name": "Ciphertext" } ] }
  ],
  "edges": [
    { "from": "in.msg", "to": "crc.data" },
    { "from": "in.msg", "to": "frame.msg" },
    { "from": "crc.checksum", "to": "frame.crc" },
    { "from": "frame.framed", "to": "seed.plaintext" },
    { "from": "in.key", "to": "seed.key" },
    { "from": "in.iv", "to": "seed.iv" },
    { "from": "seed.ciphertext", "to": "out.ct" }
  ]
}
```

## 6. Script node (`utility-script`)

**Rule: cryptographic operations (ciphers, MACs, KDFs, hashes, signatures, key agreement) are standard nodes. Byte plumbing between them (slicing, concatenating, type and width conversion, length fields, small bit tweaks, a conditional branch) belongs in a `utility-script` node: a few lines of script are shorter and easier to review than a chain of slicer, concatenator and converter nodes.** Do not hide the cryptographic operations themselves in a script (no hand-written AES or HMAC): the graph must still show which algorithms run.

- Script inputs are `utility-script` `inputs`, outputs are `outputs`; port ids are variable names (identifier rules apply, no duplicates, only `bytes`/`int`/`bool`/`string`). The code is `props.code`.
- Every output variable must be assigned on every path. Inputs are read-only.
- Python-like subset: `def`, `if/elif/else`, `for x in range(n)` / over `bytes` or lists, `and/or/not`, no `while`, no recursion, no imports. Indentation is 4 spaces, no tabs.
- Literals: `255`, `0xFF`, `h"87 23 af"` (hex bytes), `b"1010 0001"` (bits), `s"text"` (UTF-8 bytes), `"str"`, `True`/`False`.
- `bytes` operators: `+` concat, `*` repeat, `& | ^ ~` bitwise (equal lengths), `<< >>` shift (keeps length), `x[i]` byte, `x[a:b]` slice, `x[offset, length]` slice by length, `==`, `<`. `int` is unbounded; `//` and `%` floor like Python.
- Built-ins: `len`, `zeros`, `fill`, `concat`, `reverse`, `blocks`, `to_ints`, `from_ints`, `rol`, `ror`, `ct_equals`, `compare`, `to_int`, `to_bytes`, `from_hex`, `to_hex`, `from_utf8`, `to_utf8`, `str`, `abs`, `min`, `max`, `pow`, `bit_length`, `range`, `fail(code, message)`.
- `fail("MY_CODE", "message")` stops the node with your error. Codes may not start with `SCRIPT_` or `BYTES_`.
- Limits: 10 million steps, 16 MiB per bytes value, 1 Mi list items. The full language reference is in the in-app help (Script section).

```json
{
  "draft": 1,
  "name": "GF(2^128) doubling",
  "nodes": [
    { "id": "in", "type": "workflow-input",
      "outputs": [ { "id": "x", "dataType": "bytes", "name": "X", "constraint": { "lengths": [16] }, "defaultValue": "80000000000000000000000000000001" } ] },
    { "id": "dbl", "type": "utility-script",
      "props": { "code": "y = x << 1\nif x[0] & 0x80 != 0:\n    y ^= h\"00000000000000000000000000000087\"\n" },
      "inputs": [ { "id": "x", "dataType": "bytes" } ],
      "outputs": [ { "id": "y", "dataType": "bytes" } ] },
    { "id": "out", "type": "workflow-output", "inputs": [ { "id": "y", "dataType": "bytes", "name": "Y" } ] }
  ],
  "edges": [
    { "from": "in.x", "to": "dbl.x" },
    { "from": "dbl.y", "to": "out.y" }
  ]
}
```

## 7. Errors

**Validation issues** (`validate`, and the first stage of `run`/`expand`; exit 1). Fix the draft; each issue names a `path` and a `hint`.

| Code | Meaning |
| --- | --- |
| `DRAFT_BAD_JSON`, `DRAFT_BAD_STRUCTURE`, `DRAFT_UNSUPPORTED_VERSION`, `DRAFT_UNKNOWN_FIELD` | not JSON, wrong shape, `draft` is not `1`, a field the format does not have |
| `NODE_ID_INVALID`, `NODE_ID_DUPLICATE`, `NODE_TYPE_UNKNOWN`, `NODE_TYPE_NOT_ALLOWED` | bad or repeated node id; type not in the catalog; custom/Link types are not allowed in drafts |
| `PROP_UNKNOWN`, `PROP_INVALID_VALUE`, `PROP_HIDDEN` | no such property; value not allowed (see `options`); property hidden under the current mode |
| `PORT_NAME_UNKNOWN_PORT`, `PORT_NAME_AMBIGUOUS`, `PORT_NAME_INVALID`, `PORT_NAME_DUPLICATE` | `portNames` key is no renamable port (unknown, hidden or variable); bare `id` exists on both sides (use `inputs.<id>`/`outputs.<id>`); empty or forbidden character or not a string; name repeated on one side |
| `PORT_LIST_REQUIRED`, `PORT_MISMATCH`, `PORTS_DERIVATION_MISMATCH`, `PORT_TYPE_INVALID` | variable-port node without its port list; written ports differ from the definition; ValueSet/Switch/Script ports do not follow from their properties; type not allowed |
| `EDGE_BAD_REFERENCE`, `EDGE_NODE_UNKNOWN`, `EDGE_PORT_UNKNOWN`, `EDGE_PORT_HIDDEN`, `EDGE_DIRECTION` | bad `node.port` text, no such node, no such port, port hidden by the mode, from/to reversed |
| `EDGE_TYPE_MISMATCH`, `EDGE_INPUT_MULTIPLE`, `GRAPH_CYCLE` | types differ, two edges into one input, a cycle |
| `INPUT_REQUIRED_MISSING` | a visible required input has no edge |
| `VARIABLE_NOT_ALLOWED`, `VARIABLE_UNDEFINED`, `VARIABLE_TYPE_MISMATCH` | reference not allowed here; not in the `variables` block; wrong type |
| `NODE_DESIGN_RULE` | the node's own design-time check failed (message says why) |
| `SCRIPT_DIAGNOSTIC` | a `utility-script` `code` has a syntax or type error; the message gives line:column and what is wrong (up to 5 per node). Fix the code, validate again |

**Run input issues** (exit 1): `RUN_INPUT_MISSING` (no value and no default), `RUN_INPUT_UNKNOWN` (no such port key), `RUN_INPUT_INVALID` (bad notation, e.g. odd hex), `RUN_EXPECT_MISMATCH` (output differs from `--expect`; `diffs` lists key, expected, actual).

**Run errors** (exit 2; the first failing node is the cause, downstream nodes show "Skipped due to upstream node failure"):

| Code | Meaning |
| --- | --- |
| `INVALID_KEY_LENGTH`, `INVALID_IV_LENGTH`, `INVALID_NONCE_LENGTH`, `INVALID_TAG_LENGTH` | wrong length for the algorithm or mode |
| `PLAINTEXT_NOT_BLOCK_ALIGNED`, `CIPHERTEXT_NOT_BLOCK_ALIGNED`, `INVALID_PADDING` | block alignment or padding problem (see padding default) |
| `AUTH_TAG_MISMATCH` | AEAD decryption: wrong key, nonce, AAD, tag or modified data |
| `INPUT_CONSTRAINT_VIOLATION` | a `Workflow Input` value breaks its declared `constraint` |
| `VARIABLE_UNRESOLVED` | a `$var` reference has no value (add `variables` or `--vars`) |
| `BYTES_*` | byte-operation misuse: `BYTES_OUT_OF_RANGE`, `BYTES_LENGTH_MISMATCH` (xor/and of unequal lengths), `BYTES_INT_OVERFLOW`, `BYTES_INVALID_HEX`, `BYTES_SIZE_LIMIT` |
| `SCRIPT_*` | script runtime: `SCRIPT_DIVISION_BY_ZERO`, `SCRIPT_INDEX_OUT_OF_RANGE`, `SCRIPT_STEP_LIMIT`, `SCRIPT_TIMEOUT`, `SCRIPT_SIZE_LIMIT`, `SCRIPT_COMPILE_ERROR` |
| `SET_SCHEMA_MISMATCH` | the active `switch` set does not match the base set |
| any other code | the node's own `errorProfile.codes`, or a code from a script `fail(...)` |

If a node sets `errorUnify`, all its errors are reported under the user's chosen code and message; look at the node properties before trusting the code.
