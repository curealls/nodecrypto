import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { defaultNodeRegistry } from 'nodecrypto-engine/registry/nodeRegistry';
import { hexToBytes } from 'nodecrypto-engine/crypto/utils/encoding';

const hex = (h: string) => hexToBytes(h.replace(/\s/g, ''));
const kat = (op: string) => JSON.parse(readFileSync(`../../examples/kat/bytes-ops/${op}.json`, 'utf-8'));
const node = defaultNodeRegistry.get('utility-byte-length')!;
const len = async (v: unknown) => (await node.execute({ inputs: { in: v }, properties: {}, log: () => {} })).length;
const code = async (p: Promise<unknown>) => p.then(() => 'ok', (e) => e.code);

describe('Byte Length node', () => {
  it('matches length KAT vectors', async () => {
    for (const v of kat('length')) expect(await len(hex(v.args[0].hex))).toBe(Number(v.result));
  });

  it('counts string as UTF-8 bytes', async () => {
    expect(await len('')).toBe(0);
    expect(await len('abc')).toBe(3);
    expect(await len('가')).toBe(3);
    expect(await len('😀')).toBe(4);
  });

  it('counts int as the minimal unsigned length, including bigint', async () => {
    expect(await len(0)).toBe(1);
    expect(await len(255)).toBe(1);
    expect(await len(256)).toBe(2);
    expect(await len(2 ** 53 - 1)).toBe(7);
    expect(await len(2n ** 64n)).toBe(9);
    expect(await code(len(-1))).toBe('BYTES_INT_OVERFLOW');
  });

  it('counts bool as exactly 1 byte', async () => {
    expect(await len(true)).toBe(1);
    expect(await len(false)).toBe(1);
  });

  it('rejects values that cannot become bytes', async () => {
    expect(await code(len(1.5))).toBe('BYTES_INVALID_ARGUMENT');
    expect(await code(len(undefined))).toBe('BYTES_INVALID_ARGUMENT');
    expect(await code(len({ a: 1 }))).toBe('BYTES_INVALID_ARGUMENT');
  });

  it('is registered right after Value Comparator with one any input and one int output', () => {
    expect(node.category).toBe('utility');
    expect(node.hidden).toBeFalsy();
    expect(node.inputs).toEqual([{ id: 'in', name: 'Value', dataType: 'any', required: true }]);
    expect(node.outputs).toEqual([{ id: 'length', name: 'Length', dataType: 'int' }]);
    expect(node.propertySchema).toEqual([]);
    expect(node.errorProfile?.kind).toBe('fixed');
    const types = defaultNodeRegistry.getAll().map((d) => d.type);
    expect(types.indexOf('utility-byte-length')).toBe(types.indexOf('utility-compare') + 1);
  });
});
