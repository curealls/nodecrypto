import { describe, expect, it } from 'vitest';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { run, validateCmd, type Deps } from '../src/commands';

// examples/workflows/try: the "Try this node" examples of the node help pages (help-docs.md §8.1.2).
// The .ncw is the source (the user fixes the layout in the app), so these tests run it instead of comparing it with its draft.
const dir = new URL('../../../examples/workflows/try/', import.meta.url);
const path = (name: string) => new URL(name, dir).pathname.replace(/^\/([A-Za-z]:)/, '$1');
const deps: Deps = { readFile: async (p) => readFileSync(p, 'utf8'), readStdin: async () => '' };

type Example = { slug: string; title: Record<string, string>; description: Record<string, string> };
const list: Record<string, Example[]> = JSON.parse(readFileSync(path('try.json'), 'utf8'));
const cases = Object.entries(list).flatMap(([node, examples]) => examples.map((e) => ({ node, slug: e.slug, name: `${node}/${e.slug}` })));

// Only these examples have no Workflow Output: the node itself is what shows the value (D-06).
const NO_OUTPUT_NODE = new Set(['output-inspector']);
// Pure notation converters must not pad an example (D-06 rule 5) unless the converter is the node on show.
const CONVERTERS = ['converter-bytes-to-hex', 'converter-bytes-to-string', 'converter-string-to-bytes'];
const nodeTypes = (file: string): string[] => JSON.parse(readFileSync(file, 'utf8')).workflow.nodes.map((n: any) => n.data.nodeType);

describe('examples/workflows/try', () => {
  it('lists at least one example and keeps the lists well formed', () => {
    expect(cases.length).toBeGreaterThan(0);
    for (const [node, examples] of Object.entries(list)) {
      expect(examples.length, node).toBeGreaterThan(0);
      expect(examples.length, `${node}: at most 4 examples`).toBeLessThanOrEqual(4);
      expect(new Set(examples.map((e) => e.slug)).size, `${node}: slugs are unique`).toBe(examples.length);
      for (const e of examples) {
        expect(e.slug, node).toMatch(/^[a-z0-9]+(-[a-z0-9]+)*$/);
        for (const l of ['en', 'ko']) {
          expect(e.title[l]?.trim(), `${node}/${e.slug} title ${l}`).toBeTruthy();
          expect(e.description[l]?.trim(), `${node}/${e.slug} description ${l}`).toBeTruthy();
        }
      }
    }
  });

  // The app names a tab after the file, so two examples with one file name cannot be told apart once both are open.
  it('gives every example a file name no other example has', () => {
    const slugs = cases.map((c) => c.slug);
    expect(slugs.filter((s, i) => slugs.indexOf(s) !== i)).toEqual([]);
    for (const c of cases) expect(c.slug === c.node || c.slug.startsWith(`${c.node}-`), c.name).toBe(true);
  });

  it('has exactly the files try.json lists, no stray ones', () => {
    const want = cases.flatMap((c) => [`${c.node}/${c.slug}.ncw`, `${c.node}/${c.slug}.expect.json`]).sort();
    const have = readdirSync(dir, { withFileTypes: true })
      .filter((e) => e.isDirectory())
      .flatMap((e) => readdirSync(new URL(`${e.name}/`, dir)).filter((f) => /\.(ncw|expect\.json)$/.test(f)).map((f) => `${e.name}/${f}`))
      .sort();
    expect(have).toEqual(want);
  });

  it.each(cases)('$name runs and matches the expected outputs', async ({ node, slug }) => {
    const e = JSON.parse(readFileSync(path(`${node}/${slug}.expect.json`), 'utf8'));
    expect(e.source, 'source of the values').toBeTruthy();
    expect(e.inputs, 'an example asks the user for nothing').toEqual({});
    const file = path(`${node}/${slug}.ncw`);
    expect((await validateCmd({ file }, deps)).exitCode).toBe(0);
    const r = await run({ file, inputs: '{}', expect: JSON.stringify(e.outputs) }, deps);
    expect(r.stderr).toBe('');
    expect(r.exitCode).toBe(0);
    expect((r.data as any).expect).toEqual({ match: true, diffs: [] });
  });

  // Saving in the app puts the user's own custom category into the manifest; an example is public and must carry none.
  it.each(cases)('$name has no manifest category', ({ node, slug }) => {
    expect(JSON.parse(readFileSync(path(`${node}/${slug}.ncw`), 'utf8')).manifest.category).toBe('');
  });

  it.each(cases)('$name follows the authoring rules (D-06)', ({ node, slug }) => {
    const types = nodeTypes(path(`${node}/${slug}.ncw`));
    expect(types, 'uses the node it explains').toContain(node);
    if (NO_OUTPUT_NODE.has(node)) expect(types).not.toContain('workflow-output');
    else expect(types.filter((t) => t === 'workflow-output'), 'exactly one Workflow Output (the app allows one per workflow)').toHaveLength(1);
    if (node !== 'workflow-input') expect(types, 'no Workflow Input').not.toContain('workflow-input');
    for (const c of CONVERTERS) if (node !== c) expect(types, `no padding ${c}`).not.toContain(c);
  });

  it.each(cases.filter((c) => existsSync(path(`${c.node}/drafts/${c.slug}.json`))))('draft $name is a valid draft', async ({ node, slug }) => {
    expect((await validateCmd({ file: path(`${node}/drafts/${slug}.json`) }, deps)).exitCode).toBe(0);
  });
});
