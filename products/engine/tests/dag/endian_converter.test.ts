import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { defaultNodeRegistry } from 'nodecrypto-engine/registry/nodeRegistry';
import { hexToBytes, bytesToHex } from 'nodecrypto-engine/crypto/utils/encoding';

const hex = (h: string) => hexToBytes(h.replace(/\s/g, ''));
const kat = (op: string) => JSON.parse(readFileSync(`../../examples/kat/bytes-ops/${op}.json`, 'utf-8'));

describe('Endian Converter node', () => {
  const node = defaultNodeRegistry.get('utility-endian')!;
  const run = (data: Uint8Array) => node.execute({ inputs: { data }, properties: {}, log: () => {} });

  it('matches reverse KAT vectors', async () => {
    for (const v of kat('reverse')) {
      expect(bytesToHex((await run(hex(v.args[0].hex))).result)).toBe(v.result.hex.replace(/\s/g, ''));
    }
  });

  it('is its own inverse and does not modify the input', async () => {
    const data = hex('01 02 03 04');
    const once = (await run(data)).result;
    expect(bytesToHex(data)).toBe('01020304');
    expect(bytesToHex((await run(once)).result)).toBe('01020304');
  });

  it('has one input, one output, no properties, and is registered after Bit Inversion', () => {
    expect(node.inputs.map((i) => i.id)).toEqual(['data']);
    expect(node.outputs.map((o) => o.id)).toEqual(['result']);
    expect(node.propertySchema).toEqual([]);
    expect(node.errorProfile).toEqual({ kind: 'none' });
    expect(node.category).toBe('utility');
    expect(node.hidden).toBeFalsy();
    const types = defaultNodeRegistry.getAll().map((d) => d.type);
    expect(types.indexOf('utility-endian')).toBe(types.indexOf('utility-bitwise-not') + 1);
  });
});

describe('Bit Inversion node', () => {
  const node = defaultNodeRegistry.get('utility-bitwise-not')!;

  it('matches not KAT vectors', async () => {
    for (const v of kat('not')) {
      const out = await node.execute({ inputs: { data: hex(v.args[0].hex) }, properties: {}, log: () => {} });
      expect(bytesToHex(out.inverted)).toBe(v.result.hex.replace(/\s/g, ''));
    }
  });

  it('has no properties (mask removed)', () => {
    expect(node.propertySchema).toEqual([]);
    expect(node.inputs.map((i) => i.id)).toEqual(['data']);
    expect(node.outputs.map((o) => o.id)).toEqual(['inverted']);
  });
});
