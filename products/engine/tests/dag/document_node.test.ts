import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { normalizeDocumentData, withoutDocuments } from 'nodecrypto-engine/dag/documentNode';
import { computeDefinitionId } from 'nodecrypto-engine/dag/customNode';
import { validatePackage } from 'nodecrypto-engine/dag/package';
import { validate } from 'nodecrypto-engine/authoring/validate';
import { defaultNodeRegistry } from 'nodecrypto-engine/registry/nodeRegistry';

const cmac = () => JSON.parse(readFileSync(new URL('../../../../examples/workflows/cmac-subkey.ncw', import.meta.url), 'utf-8'));
const doc = (data: object = {}) => ({ id: 'doc-1', type: 'documentNode', position: { x: 0, y: 0 }, data: { label: 'Document', note: '# hi', scale: 'lg', width: 400, height: 300, ...data } });
const known = new Set(defaultNodeRegistry.getMap().keys());

describe('Document node', () => {
  it('normalizes scale, size and note when reading', () => {
    expect(normalizeDocumentData({ scale: 'huge', width: -5, height: 'x', note: '   ' })).toMatchObject({ scale: 'md', width: 320, height: 240, note: undefined });
    expect(normalizeDocumentData({ width: 10, height: 99999 })).toMatchObject({ width: 160, height: 2048 });
    expect(normalizeDocumentData({ scale: 'xl', width: 500, height: 100, note: 'a' })).toMatchObject({ scale: 'xl', width: 500, height: 100, note: 'a' });
  });

  it('is accepted by the package check and the strict validator, and survives unchanged', () => {
    const pkg = cmac();
    pkg.workflow.nodes.push(doc());
    const before = JSON.stringify(pkg);
    expect(validatePackage(pkg, known)).toBeNull();
    expect(validate(pkg).ok).toBe(true);
    expect(JSON.stringify(pkg)).toBe(before);
    expect(withoutDocuments(pkg.workflow.nodes)).toHaveLength(pkg.workflow.nodes.length - 1);
  });

  it('keeps validator paths pointing at the original node index', () => {
    const pkg = cmac();
    pkg.workflow.nodes.unshift(doc());
    pkg.workflow.nodes[1].data.properties = { ...pkg.workflow.nodes[1].data.properties, mode: 'NOPE' };
    const r = validate(pkg);
    if (!r.ok) expect(r.issues.every((i) => !i.path.startsWith('workflow.nodes[0]'))).toBe(true);
  });

  it('does not change the definition identifier', () => {
    const body = cmac().workflow;
    const manifest = { label: 'x', version: '', description: '', category: 'c', inputs: [], outputs: [] };
    const a = computeDefinitionId({ manifest, workflow: body } as any);
    const b = computeDefinitionId({ manifest, workflow: { ...body, nodes: [...body.nodes, doc(), doc({ id: 'x', note: 'changed' })] } } as any);
    expect(b).toBe(a);
  });
});
