import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { defaultNodeRegistry } from '../../src/registry/nodeRegistry';
import { generateCatalog, visibleWhen } from '../../src/authoring/catalog';
import type { NodeDefinition } from '../../src/dag/types';

const committed = JSON.parse(readFileSync(new URL('../../../cli/ai/catalog.json', import.meta.url), 'utf8'));
const catalog = generateCatalog(defaultNodeRegistry);

describe('catalog (authoring.md §3)', () => {
  it('committed catalog.json matches the registry', () => {
    expect(committed, 'run `npm run gen:catalog` in products/cli').toEqual(JSON.parse(JSON.stringify(catalog)));
  });

  it('AES Encrypt iv/nonce/aad visibility follows node-catalog.md §2.2-2', () => {
    const aes = catalog.nodes.find((n) => n.type === 'symmetric-aes-encrypt')!;
    const vis = (id: string) => aes.inputs.find((p) => p.id === id)!.visibleWhen;
    expect(vis('iv')).toEqual([{ mode: ['CBC', 'CTR', 'CFB', 'OFB', 'XTS'] }]);
    expect(vis('nonce')).toEqual([{ mode: ['GCM', 'CCM'] }]);
    expect(vis('aad')).toEqual([{ mode: ['GCM', 'CCM'] }]);
  });

  it('every select defaultValue is one of its options', () => {
    for (const n of catalog.nodes)
      for (const p of n.properties)
        if (p.type === 'select') expect(p.options, `${n.type}.${p.id}`).toContain(p.defaultValue);
  });

  it('is English only (D-13)', () => {
    expect(JSON.stringify(catalog)).not.toMatch(/[가-힣]/);
  });

  it('excludes hidden and custom nodes and function fields', () => {
    expect(catalog.nodes.some((n) => n.type === 'link')).toBe(false);
    expect(JSON.stringify(catalog)).not.toMatch(/showWhen|execute/);
  });

  it('visibleWhen merges terms and rejects more than 256 combinations', () => {
    const sel = (id: string, values: string[]) => ({ id, label: id, type: 'select' as const, defaultValue: values[0], options: values.map((v) => ({ label: v, value: v })) });
    const def = { type: 't', propertySchema: [sel('a', ['x', 'y', 'z']), { id: 'b', label: 'b', type: 'boolean', defaultValue: false }] } as unknown as NodeDefinition;
    expect(visibleWhen(def, (p) => p.a !== 'y')).toEqual([{ a: ['x', 'z'] }]);
    expect(visibleWhen(def, (p) => p.a === 'x' && p.b === true)).toEqual([{ a: ['x'], b: [true] }]);
    expect(visibleWhen(def, () => true)).toBeUndefined();
    const big = { type: 'big', propertySchema: Array.from({ length: 9 }, (_, i) => sel(`s${i}`, ['p', 'q'])) } as unknown as NodeDefinition;
    expect(() => visibleWhen(big, () => false)).toThrow(/exceed 256/);
  });
});
