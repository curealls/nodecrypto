import { describe, expect, it } from 'vitest';
import { readdirSync, readFileSync } from 'node:fs';
import { expand, run, type Deps } from '../src/commands';

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

  it.each(drafts)('draft %s expands to the committed .ncw', async (name) => {
    const r = await expand({ file: path(`drafts/${name}.json`) }, deps);
    expect(r.exitCode).toBe(0);
    expect(r.data).toEqual(JSON.parse(readFileSync(path(`${name}.ncw`), 'utf8')));
  });

  it('drafts keep the script node for short glue logic only (D-14)', () => {
    for (const name of drafts) {
      const nodes = JSON.parse(readFileSync(path(`drafts/${name}.json`), 'utf8')).nodes as { type: string }[];
      expect(nodes.filter((n) => n.type === 'utility-script'), name).toEqual([]);
    }
  });
});
