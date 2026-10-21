import { describe, expect, it } from 'vitest';
import { existsSync, readFileSync } from 'node:fs';
import { catalog, guide, validateCmd, type Deps } from '../src/commands';

// products/cli/ai/guide.md (T09): every draft in the guide validates, and the node types and
// example drafts it names exist.
const root = new URL('../../../', import.meta.url);
const local = (p: string) => new URL(p, root).pathname.replace(/^\/([A-Za-z]:)/, '$1');
const text = readFileSync(local('products/cli/ai/guide.md'), 'utf8');

const blocks = [...text.matchAll(/```json\r?\n([\s\S]*?)```/g)].map((m) => m[1]).filter((b) => b.includes('"draft"'));
const deps: Deps = { readFile: async () => '', readStdin: async () => '' };
const types = new Set((catalog({}).data as { nodes: { type: string }[] }).nodes.map((n) => n.type));

describe('ai/guide.md', () => {
  it('has draft examples', () => expect(blocks.length).toBeGreaterThanOrEqual(4));

  it.each(blocks.map((b, i) => [i, b] as const))('draft block %i passes validate', async (_i, block) => {
    const r = await validateCmd({ file: '-' }, { ...deps, readStdin: async () => block });
    expect(r.text + r.stderr).toMatch(/^OK \(draft\)/);
    expect(r.exitCode).toBe(0);
  });

  it('every node type it names is in the catalog', () => {
    const named = [...text.matchAll(/`([a-z0-9]+(?:-[a-z0-9]+)+)`/g)].map((m) => m[1]);
    const nodeLike = named.filter((t) => /^(symmetric|asymmetric|pqc|mac|hash|kdf|utility|converter|padding|input|workflow)-/.test(t) || t === 'switch');
    expect(nodeLike.length).toBeGreaterThan(5);
    expect(nodeLike.filter((t) => !types.has(t))).toEqual([]);
  });

  it('linked example drafts exist', () => {
    const linked = [...text.matchAll(/examples\/workflows\/drafts\/([\w-]+)\.json/g)].map((m) => m[1]);
    expect(linked.length).toBeGreaterThan(0);
    expect(linked.filter((n) => !existsSync(local(`examples/workflows/drafts/${n}.json`)))).toEqual([]);
  });

  it('is bundled into the CLI (nodecrypto guide)', () => {
    expect(guide().exitCode).toBe(0);
  });
});
