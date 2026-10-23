import { describe, expect, it } from 'vitest';
import { readdirSync, readFileSync } from 'node:fs';
import { expand, run, validateCmd, type Deps } from '../src/commands';

// examples/workflows: every .ncw has an .expect.json (D-15); the CLI runs it the way a user would.
const dir = new URL('../../../examples/workflows/', import.meta.url);
const path = (name: string) => new URL(name, dir).pathname.replace(/^\/([A-Za-z]:)/, '$1');
const deps: Deps = { readFile: async (p) => readFileSync(p, 'utf8'), readStdin: async () => '' };

const names = (ext: string) => readdirSync(dir).filter((f) => f.endsWith(ext)).map((f) => f.slice(0, -ext.length)).sort();
const workflows = names('.ncw');
const drafts = readdirSync(new URL('drafts/', dir)).filter((f) => f.endsWith('.json')).map((f) => f.slice(0, -5)).sort();

describe('examples/workflows', () => {
  it('every workflow has an expect file and the other way round', () => {
    expect(names('.expect.json')).toEqual(workflows);
    expect(workflows.length).toBeGreaterThan(0);
  });

  it.each(workflows)('%s runs and matches the expected outputs', async (name) => {
    const e = JSON.parse(readFileSync(path(`${name}.expect.json`), 'utf8'));
    expect(e.source, 'source of the test vector').toBeTruthy();
    const r = await run({ file: path(`${name}.ncw`), inputs: JSON.stringify(e.inputs), expect: JSON.stringify(e.outputs) }, deps);
    expect(r.stderr).toBe('');
    expect(r.exitCode).toBe(0);
    expect((r.data as any).expect).toEqual({ match: true, diffs: [] });
  });

  it.each(workflows)('%s Workflow Input defaults equal the expect inputs', (name) => {
    const e = JSON.parse(readFileSync(path(`${name}.expect.json`), 'utf8'));
    const nodes = JSON.parse(readFileSync(path(`${name}.ncw`), 'utf8')).workflow.nodes as { data: { nodeType: string; outputs: { name: string; defaultValue?: string }[] } }[];
    const ports = nodes.filter((n) => n.data.nodeType === 'workflow-input').flatMap((n) => n.data.outputs);
    expect(Object.fromEntries(ports.map((p) => [p.name, p.defaultValue])), 'default values the Run dialog starts with').toEqual(e.inputs);
  });

  it.each(drafts)('draft %s expands to the committed .ncw', async (name) => {
    const r = await expand({ file: path(`drafts/${name}.json`) }, deps);
    expect(r.exitCode).toBe(0);
    expect(r.data).toEqual(JSON.parse(readFileSync(path(`${name}.ncw`), 'utf8')));
  });

  it('sha256-link keeps its Link node through validate (B11)', async () => {
    const file = path('sha256-link.ncw');
    expect(JSON.parse(readFileSync(file, 'utf8')).workflow.nodes.some((n: any) => n.data.nodeType === 'link')).toBe(true);
    const r = await validateCmd({ file }, deps);
    expect(r.exitCode).toBe(0);
  });

  it('drafts keep the script node for short glue logic only (D-14)', () => {
    for (const name of drafts) {
      const nodes = JSON.parse(readFileSync(path(`drafts/${name}.json`), 'utf8')).nodes as { type: string }[];
      expect(nodes.filter((n) => n.type === 'utility-script'), name).toEqual([]);
    }
  });
});
