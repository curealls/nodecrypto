import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { defaultNodeRegistry } from 'nodecrypto-engine/registry/nodeRegistry';
import { hexToBytes, bytesToHex } from 'nodecrypto-engine/crypto/utils/encoding';

const hex = (h: string) => hexToBytes(h.replace(/\s/g, ''));
const kat = (op: string) => JSON.parse(readFileSync(`../../examples/kat/bytes-ops/${op}.json`, 'utf-8'));

const toBytes = defaultNodeRegistry.get('utility-int-to-bytes')!;
const toInt = defaultNodeRegistry.get('utility-bytes-to-int')!;
// length 0 = minimal length (lengthMode 'min'); otherwise a fixed length
const i2b = (v: unknown, length: number, endian = 'big') =>
  toBytes.execute({
    inputs: { in: v },
    properties: { lengthMode: length === 0 ? 'min' : 'fixed', length, endian },
    log: () => {},
  });
const i2bPort = (v: unknown, length: unknown, endian = 'big') =>
  toBytes.execute({ inputs: { in: v, length }, properties: { lengthMode: 'port', length: 9, endian }, log: () => {} });
const b2i = (b: Uint8Array, endian = 'big') =>
  toInt.execute({ inputs: { in: b }, properties: { endian }, log: () => {} });
const code = async (p: Promise<unknown>) => p.then(() => 'ok', (e) => e.code);

describe('Int to Bytes / Bytes to Int nodes', () => {
  it('match unsigned toInt/fromInt KAT vectors', async () => {
    for (const v of kat('toInt')) {
      if (v.args[2] !== false || v.error) continue;
      expect(String((await b2i(hex(v.args[0].hex), v.args[1])).out)).toBe(v.result);
    }
    for (const v of kat('fromInt')) {
      if (v.args[3] !== false) continue;
      const len = Number(v.args[1]);
      const n = BigInt(v.args[0]);
      if (len === 0) continue; // node length 0 means "minimal", unlike bytesOps' empty result
      const run = i2b(n, len, v.args[2]);
      if (v.error) expect(await code(run)).toBe(v.error);
      else expect(bytesToHex((await run).out)).toBe(v.result.hex.replace(/\s/g, ''));
    }
  });

  it('uses minimal length when length is 0', async () => {
    expect(bytesToHex((await i2b(0, 0)).out)).toBe('00');
    expect(bytesToHex((await i2b(255, 0)).out)).toBe('ff');
    expect(bytesToHex((await i2b(256, 0)).out)).toBe('0100');
    expect(bytesToHex((await i2b(256, 0, 'little')).out)).toBe('0001');
    expect(bytesToHex((await i2b(2n ** 64n, 0)).out)).toBe('010000000000000000');
    expect(bytesToHex((await i2b(1, 3)).out)).toBe('000001');
  });

  it('rejects too-short length, negative and invalid values', async () => {
    expect(await code(i2b(256, 1))).toBe('BYTES_INT_OVERFLOW');
    expect(await code(i2b(-1, 0))).toBe('BYTES_INT_OVERFLOW');
    expect(await code(i2b(-1n, 4))).toBe('BYTES_INT_OVERFLOW');
    expect(await code(i2b(1.5, 0))).toBe('BYTES_INVALID_ARGUMENT');
    expect(await code(i2b(1, -1))).toBe('BYTES_INVALID_ARGUMENT');
  });

  it('takes the length from the port in port mode and ignores it in other modes', async () => {
    expect(bytesToHex((await i2bPort(1, 3)).out)).toBe('000001');
    expect(bytesToHex((await i2bPort(1, 3n, 'little')).out)).toBe('010000');
    expect(bytesToHex((await i2bPort(0, 0)).out)).toBe('');
    expect(await code(i2bPort(256, 1))).toBe('BYTES_INT_OVERFLOW');
    expect(await code(i2bPort(1, undefined))).toBe('BYTES_INVALID_ARGUMENT');
    expect(await code(i2bPort(1, -1))).toBe('BYTES_INVALID_ARGUMENT');
    expect(await code(i2bPort(1, 1.5))).toBe('BYTES_INVALID_ARGUMENT');
    const r = await toBytes.execute({ inputs: { in: 1, length: 5 }, properties: { lengthMode: 'min', endian: 'big' }, log: () => {} });
    expect(bytesToHex(r.out)).toBe('01');
  });

  it('Bytes to Int returns number when safe, bigint beyond, and 0 for empty', async () => {
    expect((await b2i(new Uint8Array(0))).out).toBe(0);
    expect((await b2i(hex('0100'))).out).toBe(256);
    expect((await b2i(hex('0100'), 'little')).out).toBe(1);
    expect((await b2i(hex('01 00 00 00 00 00 00 00 00'))).out).toBe(2n ** 64n);
  });

  it('round-trips values through both nodes', async () => {
    for (const v of [0, 1, 255, 256, 2 ** 53 - 1, 2n ** 64n, 2n ** 130n + 5n]) {
      for (const e of ['big', 'little']) {
        const b = (await i2b(v, 0, e)).out;
        expect((await b2i(b, e)).out).toBe(v);
      }
    }
  });

  it('is registered right before Bytes to Multibase with the expected ports and properties', () => {
    expect(toBytes.inputs).toEqual([
      { id: 'in', name: 'Value', dataType: 'int', required: true },
      { id: 'length', name: 'Length', dataType: 'int', required: false },
    ]);
    expect(toBytes.category).toBe('converter');
    expect(toInt.category).toBe('converter');
    const lengthField = toBytes.propertySchema.find((f) => f.id === 'length')!;
    expect(lengthField.showWhen!({ lengthMode: 'fixed' })).toBe(true);
    expect(lengthField.showWhen!({ lengthMode: 'min' })).toBe(false);
    expect(toBytes.outputs).toEqual([{ id: 'out', name: 'Bytes', dataType: 'bytes' }]);
    expect(toBytes.propertySchema.map((f) => f.id)).toEqual(['lengthMode', 'length', 'endian']);
    expect(toBytes.errorProfile.kind).toBe('fixed');
    expect(toInt.inputs.map((i) => i.id)).toEqual(['in']);
    expect(toInt.outputs).toEqual([{ id: 'out', name: 'Value', dataType: 'int' }]);
    expect(toInt.propertySchema.map((f) => f.id)).toEqual(['endian']);
    expect(toInt.errorProfile).toEqual({ kind: 'none' });
    const types = defaultNodeRegistry.getAll().map((d) => d.type);
    const mb = types.indexOf('converter-bytes-to-multibase');
    expect(types.indexOf('utility-int-to-bytes')).toBe(mb - 2);
    expect(types.indexOf('utility-bytes-to-int')).toBe(mb - 1);
  });
});
