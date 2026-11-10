import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { normalizeGroupData, withoutNonExecuting } from 'nodecrypto-engine/dag/groupNode';
import { computeDefinitionId } from 'nodecrypto-engine/dag/customNode';
import { validatePackage } from 'nodecrypto-engine/dag/package';
import { validate } from 'nodecrypto-engine/authoring/validate';
import { defaultNodeRegistry } from 'nodecrypto-engine/registry/nodeRegistry';

const cmac = () => JSON.parse(readFileSync(new URL('../../../../examples/workflows/cmac-subkey.ncw', import.meta.url), 'utf-8'));
const group = (data: object = {}) => ({
  id: 'group-1',
  type: 'groupNode',
  position: { x: -100, y: -100 },
  data: { nodeType: 'group', label: 'Group', width: 2000, height: 1200, captionSide: 'left', captionScale: 'lg', color: 'blue', borderStyle: 'dashed', fill: true, ...data },
});
/** Puts the first two nodes inside the group (group first, children parent-relative). */
const grouped = (pkg: any) => {
  const [a, b, ...rest] = pkg.workflow.nodes;
  const inside = (n: any) => ({ ...n, parentId: 'group-1', position: { x: n.position.x + 100, y: n.position.y + 100 } });
  pkg.workflow.nodes = [group(), inside(a), inside(b), ...rest];
  return pkg;
};
const known = new Set(defaultNodeRegistry.getMap().keys());

describe('Group node', () => {
  it('normalizes unknown values and sizes when reading', () => {
    expect(normalizeGroupData({})).toEqual({
      label: undefined, width: 640, height: 320, captionSide: 'top', captionScale: 'md',
      color: undefined, borderStyle: 'dotted', fill: false,
    });
    expect(normalizeGroupData({ width: 10, height: 'x', captionSide: 'middle', captionScale: 'huge', color: 'red', borderStyle: 'wavy', fill: 'yes' }))
      .toMatchObject({ width: 160, height: 320, captionSide: 'top', captionScale: 'md', color: undefined, borderStyle: 'dotted', fill: false });
    expect(normalizeGroupData({ width: 99999, height: 96 })).toMatchObject({ width: 99999, height: 96 }); // no maximum
    expect(normalizeGroupData(group().data)).toMatchObject({ captionSide: 'left', captionScale: 'lg', color: 'blue', borderStyle: 'dashed', fill: true });
    // files from before the colors were merged: borderColor wins, else captionBg
    expect(normalizeGroupData({ captionBg: 'yellow', borderColor: 'green' }).color).toBe('green');
    expect(normalizeGroupData({ captionBg: 'yellow' }).color).toBe('yellow');
    expect(normalizeGroupData({ color: 'pink', borderColor: 'green' }).color).toBe('pink');
  });

  it('a group with children passes the package check and the strict validator, and survives unchanged', () => {
    const pkg = grouped(cmac());
    const before = JSON.stringify(pkg);
    expect(validatePackage(pkg, known)).toBeNull();
    expect(validate(pkg).ok).toBe(true);
    expect(JSON.stringify(pkg)).toBe(before); // parentId, relative positions and group data all kept
    expect(withoutNonExecuting(pkg.workflow.nodes)).toHaveLength(pkg.workflow.nodes.length - 1);
  });

  it('keeps validator paths pointing at the original node index', () => {
    const pkg = grouped(cmac());
    pkg.workflow.nodes[1].data.properties = { ...pkg.workflow.nodes[1].data.properties, mode: 'NOPE' };
    const r = validate(pkg);
    if (!r.ok) expect(r.issues.every((i) => !i.path.startsWith('workflow.nodes[0]'))).toBe(true);
  });

  it('putting nodes in a group (or editing the group) does not change the definition identifier', () => {
    const manifest = { label: 'x', version: '', description: '', category: 'c', inputs: [], outputs: [] };
    const id = (wf: any) => computeDefinitionId({ manifest, workflow: wf } as any);
    const plain = id(cmac().workflow);
    expect(id(grouped(cmac()).workflow)).toBe(plain);
    const edited = grouped(cmac());
    edited.workflow.nodes[0] = group({ label: 'Other', width: 900, color: 'gray' });
    expect(id(edited.workflow)).toBe(plain);
  });
});
