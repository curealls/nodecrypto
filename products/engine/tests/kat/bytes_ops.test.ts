import { describe, it, expect } from 'vitest';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import * as ops from 'nodecrypto-engine/crypto/utils/bytesOps';
import { hexToBytes, bytesToHex } from 'nodecrypto-engine/crypto/utils/encoding';

// 벡터 형식: kat-conformance.md §4.1
const KAT_DIR = join(__dirname, '../../../../examples/kat/bytes-ops');

// 인자 종류: b=bytes, n=number(인덱스·길이·개수), i=bigint(int), s=string, t=bool, e=endian
// B=bytes 목록, N=number 목록
type Kind = 'b' | 'n' | 'i' | 's' | 't' | 'e' | 'B' | 'N';
const SIG: Record<string, Kind[]> = {
  zeros: ['n'], fill: ['n', 'n'], fromHex: ['s'], toHex: ['b', 't'], fromUtf8: ['s'], toUtf8: ['b'],
  length: ['b'], get: ['b', 'n'], slice: ['b', 'n', 'n'], replace: ['b', 'n', 'b'], concat: ['B'],
  reverse: ['b'], repeat: ['b', 'n'], toInts: ['b'], fromInts: ['N'], blocks: ['b', 'n'],
  and: ['b', 'b'], or: ['b', 'b'], xor: ['b', 'b'], not: ['b'],
  shl: ['b', 'n'], shr: ['b', 'n'], rol: ['b', 'n'], ror: ['b', 'n'],
  equals: ['b', 'b'], ctEquals: ['b', 'b'], compare: ['b', 'b'],
  toInt: ['b', 'e', 't'], fromInt: ['i', 'n', 'e', 't'],
};

type Json = any;
const hex = (v: Json) => hexToBytes(v.hex);

function decodeArg(kind: Kind, v: Json): unknown {
  switch (kind) {
    case 'b': return hex(v);
    case 'B': return (v as Json[]).map(hex);
    case 'n': return Number(v);
    case 'N': return (v as string[]).map(Number);
    case 'i': return BigInt(v);
    default: return v;
  }
}

/** 실제 결과를 벡터 표기(§4.1)로 변환한다. */
function encodeResult(r: unknown): Json {
  if (r instanceof Uint8Array) return { hex: bytesToHex(r) };
  if (Array.isArray(r)) return r.map(encodeResult);
  if (typeof r === 'number' || typeof r === 'bigint') return String(r);
  return r;
}

/** 정규화: 기대값의 hex 공백 제거, 소문자화. */
function normalize(v: Json): Json {
  if (v && typeof v === 'object' && !Array.isArray(v)) return { hex: String(v.hex).replace(/\s+/g, '').toLowerCase() };
  if (Array.isArray(v)) return v.map(normalize);
  return v;
}

const files = readdirSync(KAT_DIR).filter((f) => f.endsWith('.json')).sort();
const allErrors = new Set<string>();

describe('bytesOps KAT', () => {
  it('모든 연산(bytes-ops.md §3)에 벡터 파일이 있다', () => {
    expect(files.map((f) => f.replace('.json', '')).sort()).toEqual(Object.keys(SIG).sort());
    for (const name of Object.keys(SIG)) expect(typeof (ops as any)[name]).toBe('function');
  });

  for (const file of files) {
    const name = file.replace('.json', '');
    const vectors: Json[] = JSON.parse(readFileSync(join(KAT_DIR, file), 'utf8'));
    describe(name, () => {
      vectors.forEach((v, idx) => {
        it(`#${idx} ${JSON.stringify(v.args).slice(0, 80)}`, () => {
          expect(v.op).toBe(name);
          const fn = (ops as any)[v.op] as (...a: unknown[]) => unknown;
          const kinds = SIG[v.op];
          const args = v.args.map((a: Json, i: number) => decodeArg(kinds[i], a));
          // 입력 불변 검사용 사본
          const snapshot = args.map((a: unknown) => JSON.stringify(encodeResult(a as any), (_, x) => (typeof x === 'bigint' ? String(x) : x)));
          if ('error' in v) {
            allErrors.add(v.error);
            try {
              fn(...args);
            } catch (e: any) {
              expect(e.code).toBe(v.error);
              return;
            }
            throw new Error(`오류 ${v.error}가 발생해야 한다`);
          }
          const actual = fn(...args);
          expect(normalize(encodeResult(actual))).toEqual(normalize(v.result));
          // 불변성(규칙 1): 입력이 바뀌지 않았다
          const after = args.map((a: unknown) => JSON.stringify(encodeResult(a as any), (_, x) => (typeof x === 'bigint' ? String(x) : x)));
          expect(after).toEqual(snapshot);
          // 반환 배열이 입력과 버퍼를 공유하지 않는다
          if (actual instanceof Uint8Array) for (const a of args) if (a instanceof Uint8Array) expect(actual.buffer).not.toBe(a.buffer);
        });
      });
    });
  }

  it('bytes-ops.md §4의 모든 오류 코드가 벡터 또는 아래 테스트에서 발생한다', () => {
    // BYTES_SIZE_LIMIT(concat)은 큰 입력이 필요해 벡터 파일 대신 코드에서 검사한다.
    const half = new Uint8Array(ops.MAX_BYTES / 2 + 1);
    expect(() => ops.concat([half, half])).toThrowError(expect.objectContaining({ code: 'BYTES_SIZE_LIMIT' }));
    allErrors.add('BYTES_SIZE_LIMIT');
    expect([...allErrors].sort()).toEqual([
      'BYTES_INT_OVERFLOW', 'BYTES_INVALID_ARGUMENT', 'BYTES_INVALID_HEX', 'BYTES_INVALID_UTF8',
      'BYTES_LENGTH_MISMATCH', 'BYTES_OUT_OF_RANGE', 'BYTES_SIZE_LIMIT',
    ]);
  });

  it('ctEquals와 equals는 항상 같은 결과이다', () => {
    const samples = [[], [0], [1], [0, 0], [255, 1], [1, 2, 3], [1, 2, 4], [1, 2, 3, 4]].map((a) => new Uint8Array(a));
    for (const a of samples) for (const b of samples) expect(ops.ctEquals(a, b)).toBe(ops.equals(a, b));
  });

  it('shl/shr/rol/ror는 이동량이 커도 즉시 끝난다', () => {
    const b = new Uint8Array(16).fill(0xa5);
    const t = Date.now();
    ops.shl(b, 10 ** 15); ops.shr(b, 10 ** 15); ops.rol(b, 10 ** 15); ops.ror(b, 10 ** 15);
    expect(Date.now() - t).toBeLessThan(100);
  });
});
