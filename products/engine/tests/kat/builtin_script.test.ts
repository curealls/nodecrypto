import { describe, it, expect } from 'vitest';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { compile, runScript } from 'nodecrypto-engine/script';
import type { ScriptValue } from 'nodecrypto-engine/script';
import { hexToBytes, bytesToHex } from 'nodecrypto-engine/crypto/utils/encoding';

// 벡터 형식: kat-conformance.md §4.1
const KAT_DIR = join(__dirname, '../../../../examples/kat/builtin-script');

type Json = any;

function decode(type: string, v: Json): ScriptValue {
  switch (type) {
    case 'bytes': return hexToBytes(v.hex);
    case 'int': return BigInt(v);
    default: return v;
  }
}

function encode(v: ScriptValue): Json {
  if (v instanceof Uint8Array) return { hex: bytesToHex(v) };
  if (typeof v === 'bigint') return v.toString();
  return v;
}

const norm = (v: Json): Json => (v && typeof v === 'object' ? { hex: String(v.hex).replace(/\s+/g, '').toLowerCase() } : v);

const files = readdirSync(KAT_DIR).filter((f) => f.endsWith('.json')).sort();

describe('내장 스크립트 KAT', () => {
  it('벡터 파일이 있다', () => {
    expect(files.length).toBeGreaterThan(0);
  });

  for (const file of files) {
    const vectors: Json[] = JSON.parse(readFileSync(join(KAT_DIR, file), 'utf8'));
    describe(file.replace('.json', ''), () => {
      for (const v of vectors) {
        it(v.name, () => {
          const ports = {
            inputs: Object.entries(v.ports.inputs).map(([id, dataType]) => ({ id, dataType: dataType as string })),
            outputs: Object.entries(v.ports.outputs).map(([id, dataType]) => ({ id, dataType: dataType as string })),
          };
          const r = compile(v.script, ports);

          if ('error' in v) {
            // error: 정적 오류이면 첫 진단의 code, 실행 오류이면 오류 코드 (kat-conformance.md §4.1)
            if (r.diagnostics.length) {
              expect(r.diagnostics[0].code).toBe(v.error);
              return;
            }
            const inputs = Object.fromEntries(Object.entries(v.inputs).map(([id, x]) => [id, decode(v.ports.inputs[id], x)]));
            try {
              runScript(r.typed!, inputs);
            } catch (e: any) {
              expect(e.code).toBe(v.error);
              return;
            }
            throw new Error(`오류 ${v.error}가 발생해야 한다`);
          }

          expect(r.diagnostics).toEqual([]);
          const inputs = Object.fromEntries(Object.entries(v.inputs).map(([id, x]) => [id, decode(v.ports.inputs[id], x)]));
          const out = runScript(r.typed!, inputs);
          expect(Object.keys(out).sort()).toEqual(Object.keys(v.outputs).sort());
          for (const id of Object.keys(v.outputs)) expect(norm(encode(out[id]))).toEqual(norm(v.outputs[id]));
        });
      }
    });
  }
});
