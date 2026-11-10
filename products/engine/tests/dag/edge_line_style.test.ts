import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { computeDefinitionId } from 'nodecrypto-engine/dag/customNode';
import { contentSignature, validatePackage } from 'nodecrypto-engine/dag/package';
import { validate } from 'nodecrypto-engine/authoring/validate';
import { defaultNodeRegistry } from 'nodecrypto-engine/registry/nodeRegistry';

const cmac = () => JSON.parse(readFileSync(new URL('../../../../examples/workflows/cmac-subkey.ncw', import.meta.url), 'utf-8'));
const known = new Set(defaultNodeRegistry.getMap().keys());

describe('edge data.lineType / data.route', () => {
  it('are accepted by the package check and the strict validator and kept as they are', () => {
    const pkg = cmac();
    pkg.workflow.edges[0].data = { ...pkg.workflow.edges[0].data, lineType: 'orthogonal', route: { a: 40, m: -20, b: 30 } };
    const before = JSON.stringify(pkg);
    expect(validatePackage(pkg, known)).toBeNull();
    expect(validate(pkg).ok).toBe(true);
    expect(JSON.stringify(pkg)).toBe(before);
  });

  it('do not change the definition identifier but do change the saved-content signature', () => {
    const plain = cmac().workflow;
    const styled = cmac().workflow;
    styled.edges[0].data = { ...styled.edges[0].data, lineType: 'orthogonal' };
    const manifest = { label: 'x', version: '', description: '', category: 'c', inputs: [], outputs: [] };
    expect(computeDefinitionId({ manifest, workflow: styled } as any)).toBe(computeDefinitionId({ manifest, workflow: plain } as any));
    expect(contentSignature(styled.nodes, styled.edges)).not.toBe(contentSignature(plain.nodes, plain.edges));
  });
});
