import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { defaultNodeRegistry } from 'nodecrypto-engine/registry/nodeRegistry';
import { hexToBytes, bytesToHex } from 'nodecrypto-engine/crypto/utils/encoding';

describe('Bit Shift & Rotate node', () => {
  const node = defaultNodeRegistry.get('utility-bitshift')!;
  const hex = (h: string) => hexToBytes(h.replace(/\s/g, ''));
  const run = (operation: string, data: Uint8Array, bits: unknown) =>
    node.execute({ inputs: { data }, properties: { operation, bits }, log: () => {} });

  for (const op of ['shl', 'shr', 'rol', 'ror']) {
    it(`matches ${op} KAT vectors`, async () => {
      const kat = JSON.parse(readFileSync(`../../examples/kat/bytes-ops/${op}.json`, 'utf-8'));
      for (const v of kat) {
        const p = run(op.toUpperCase(), hex(v.args[0].hex), v.args[1]);
        if (v.error) await expect(p).rejects.toMatchObject({ code: v.error });
        else expect(bytesToHex((await p).result)).toBe(v.result.hex.replace(/\s/g, ''));
      }
    });
  }

  it('carries bits across byte boundaries (CMAC L << 1)', async () => {
    expect(bytesToHex((await run('SHL', hex('01 80'), 1)).result)).toBe('0300');
  });

  it('rejects negative, fractional and NaN bit counts', async () => {
    for (const bits of [-1, 1.5, NaN, 'x']) {
      await expect(run('SHL', hex('01'), bits)).rejects.toMatchObject({ code: 'BYTES_INVALID_ARGUMENT' });
    }
  });

  it('rejects an unknown operation', async () => {
    await expect(run('NAND', hex('01'), 1)).rejects.toMatchObject({ code: 'BYTES_INVALID_ARGUMENT' });
  });

  it('has one input, no dynamic ports, and is registered after Bitwise Logic', () => {
    expect(node.inputs.map((i) => i.id)).toEqual(['data']);
    expect(node.dynamicInputs).toBeUndefined();
    expect(node.propertySchema!.map((f) => f.id)).toEqual(['operation', 'bits']);
    expect(node.category).toBe('utility');
    expect(node.hidden).toBeFalsy();
    const types = defaultNodeRegistry.getAll().map((d) => d.type);
    expect(types.indexOf('utility-bitshift')).toBe(types.indexOf('utility-bitwise') + 1);
  });
});
