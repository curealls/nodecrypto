import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { defaultNodeRegistry } from 'nodecrypto-engine/registry/nodeRegistry';
import { hexToBytes, bytesToHex } from 'nodecrypto-engine/crypto/utils/encoding';

const node = defaultNodeRegistry.get('utility-slicer')!;
const hex = (h: string) => hexToBytes(h.replace(/\s/g, ''));
const run = (data: Uint8Array, offset: unknown, length: unknown = '') =>
  node.execute({ inputs: { data }, properties: { offset, length }, log: () => {} });

describe('Byte Slicer node', () => {
  it('matches slice KAT vectors (length >= 0)', async () => {
    const kat = JSON.parse(readFileSync('../../examples/kat/bytes-ops/slice.json', 'utf-8'));
    let ran = 0;
    for (const v of kat) {
      const [data, offset, length] = v.args;
      if (Number(length) < 0) continue; // node-only convention, not part of bytesOps.slice (kat-conformance.md §4.3)
      const p = run(hex(data.hex), Number(offset), String(length));
      if (v.error) await expect(p).rejects.toMatchObject({ code: v.error });
      else expect(bytesToHex((await p).sliced)).toBe(v.result.hex.replace(/\s/g, ''));
      ran++;
    }
    expect(ran).toBeGreaterThan(5);
  });

  // examples of builtin-script.md §4.7: a[o, n]
  const a = hex('00 11 22 33 44 55 66 77 88');
  const cases: [number, string, string][] = [
    [1, '3', '112233'], // a[1, 3]
    [6, '', '667788'], // a[6,]
    [6, '-1', '6677'], // a[6, -1]
    [6, '-2', '66'], // a[6, -2]
    [-3, '3', '667788'], // a[-3, 3]
    [-3, '', '667788'],
    [0, '-9', ''], // end = 0
  ];
  for (const [offset, length, expected] of cases) {
    it(`a[${offset}, ${length || ''}] = ${expected || '(empty)'}`, async () => {
      expect(bytesToHex((await run(a, offset, length)).sliced)).toBe(expected);
    });
  }

  it('fails instead of clamping when the range is outside', async () => {
    for (const [o, l] of [[0, '10'], [10, ''], [-10, ''], [6, '-4'], [0, '-10']] as const) {
      await expect(run(a, o, l)).rejects.toMatchObject({ code: 'BYTES_OUT_OF_RANGE' });
    }
  });

  it('rejects non-integer offset and length', async () => {
    await expect(run(a, 1.5, '')).rejects.toMatchObject({ code: 'BYTES_INVALID_ARGUMENT' });
    await expect(run(a, NaN, '')).rejects.toMatchObject({ code: 'BYTES_INVALID_ARGUMENT' });
    await expect(run(a, 0, 'x')).rejects.toMatchObject({ code: 'BYTES_INVALID_ARGUMENT' });
    await expect(run(a, 0, '1.5')).rejects.toMatchObject({ code: 'BYTES_INVALID_ARGUMENT' });
  });

  it('handles empty input', async () => {
    expect((await run(new Uint8Array(0), 0, '')).sliced.length).toBe(0);
    await expect(run(new Uint8Array(0), 0, '1')).rejects.toMatchObject({ code: 'BYTES_OUT_OF_RANGE' });
  });

  it('has the sliced output, offset/length properties and a fixed error profile', () => {
    expect(node.outputs.map((o) => o.id)).toEqual(['sliced']);
    expect(node.propertySchema!.map((f) => f.id)).toEqual(['offset', 'length']);
    expect(node.propertySchema!.find((f) => f.id === 'length')!.defaultValue).toBe('');
    expect(node.errorProfile).toMatchObject({ kind: 'fixed' });
  });
});
