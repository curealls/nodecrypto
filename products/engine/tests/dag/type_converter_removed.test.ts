import { describe, it, expect } from 'vitest';
import { defaultNodeRegistry } from 'nodecrypto-engine/registry/nodeRegistry';
import { buildPackage, validatePackage } from 'nodecrypto-engine/dag/package';

describe('Type Converter (Legacy) removal (bytes-nodes-migration D-08)', () => {
  it('is no longer registered or offered in the palette', () => {
    expect(defaultNodeRegistry.get('utility-type-converter')).toBeUndefined();
    expect(defaultNodeRegistry.getAll().some((d) => d.label.includes('Type Converter'))).toBe(false);
  });

  it('opening a saved workflow that still has it is rejected with PKG_UNKNOWN_NODE_TYPE, without throwing', () => {
    const node = {
      id: 't', type: 'cryptoNode', position: { x: 0, y: 0 },
      data: { nodeType: 'utility-type-converter', label: 'Type Converter (Legacy)', inputs: [], outputs: [], properties: {} },
    };
    const pkg = buildPackage({ name: 'w', nodes: [node], edges: [] } as any, { label: 'w', version: '', description: '', category: '' }, () => undefined);
    const known = new Set(defaultNodeRegistry.getAll().map((d) => d.type));
    const err = validatePackage(JSON.parse(JSON.stringify(pkg)), known);
    expect(err?.code).toBe('PKG_UNKNOWN_NODE_TYPE');
    expect(err?.message).toContain('utility-type-converter');
  });
});
