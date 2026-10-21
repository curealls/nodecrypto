/**
 * 내장 함수의 평가 함수 (builtin-script.md §7).
 * 시그니처와 타입은 builtins.ts 표가 정의하고, 여기서는 bytesOps(T03)와 int 연산으로 실행한다.
 * 자동 완성(T08)이 해석기와 bytesOps를 끌어오지 않도록 표와 분리했다. 표의 모든 이름(range 제외)이 구현됐는지는 테스트가 보장한다.
 */

import * as B from '../crypto/utils/bytesOps';
import { BUILTINS } from './builtins';
import { EvalCtx, ScriptValue, bitLength, checkBytes, checkInt, checkListLen, clampNum, fail } from './runtime';
import { tmsg } from '../messages';

type Impl = (a: ScriptValue[], ctx: EvalCtx) => ScriptValue;

const bytes = (v: ScriptValue) => v as Uint8Array;
const int = (v: ScriptValue) => v as bigint;
const endian = (v: ScriptValue) => v as B.Endian; // 잘못된 값은 bytesOps가 BYTES_INVALID_ARGUMENT로 거부한다

/** 모듈러 거듭제곱(제곱-곱셈). 지수의 비트마다 단계와 시간을 검사해 큰 수에서도 중단할 수 있다. */
function modPow(base: bigint, exp: bigint, mod: bigint, ctx: EvalCtx): bigint {
  if (exp < 0n) fail('SCRIPT_INVALID_ARGUMENT', tmsg('script:eval.powExponent'));
  if (mod < 1n) fail('SCRIPT_INVALID_ARGUMENT', tmsg('script:eval.powModulus'));
  let result = 1n % mod;
  let b = ((base % mod) + mod) % mod;
  const bits = exp.toString(2);
  for (let i = bits.length - 1; i >= 0; i--) {
    ctx.tick();
    ctx.checkTime();
    if (bits[i] === '1') result = (result * b) % mod;
    if (i > 0) b = (b * b) % mod;
  }
  return result;
}

export const BUILTIN_IMPL: Readonly<Record<string, Impl>> = {
  len: (a) => BigInt((a[0] as { length: number }).length),
  zeros: (a, c) => checkBytes(c, B.zeros(clampNum(int(a[0])))),
  fill: (a, c) => checkBytes(c, B.fill(clampNum(int(a[0])), clampNum(int(a[1])))),
  concat: (a, c) => checkBytes(c, B.concat(a[0] as Uint8Array[])),
  reverse: (a) => B.reverse(bytes(a[0])),
  blocks: (a, c) => {
    const b = bytes(a[0]);
    const size = clampNum(int(a[1]));
    if (size > 0) checkListLen(c, Math.ceil(b.length / size));
    return B.blocks(b, size);
  },
  to_ints: (a, c) => {
    checkListLen(c, bytes(a[0]).length);
    return B.toInts(bytes(a[0])).map((x) => BigInt(x));
  },
  from_ints: (a, c) => checkBytes(c, B.fromInts((a[0] as bigint[]).map(clampNum))),
  rol: (a) => B.rol(bytes(a[0]), clampNum(int(a[1]))),
  ror: (a) => B.ror(bytes(a[0]), clampNum(int(a[1]))),
  ct_equals: (a) => B.ctEquals(bytes(a[0]), bytes(a[1])),
  compare: (a) => BigInt(B.compare(bytes(a[0]), bytes(a[1]))),
  to_int: (a, c) => checkInt(c, B.toInt(bytes(a[0]), endian(a[1]), a[2] as boolean)),
  to_bytes: (a, c) => checkBytes(c, B.fromInt(int(a[0]), clampNum(int(a[1])), endian(a[2]), a[3] as boolean)),
  from_hex: (a, c) => checkBytes(c, B.fromHex(a[0] as string)),
  to_hex: (a) => B.toHex(bytes(a[0]), a[1] as boolean),
  from_utf8: (a, c) => checkBytes(c, B.fromUtf8(a[0] as string)),
  to_utf8: (a) => B.toUtf8(bytes(a[0])),
  str: (a) => int(a[0]).toString(10),
  abs: (a) => (int(a[0]) < 0n ? -int(a[0]) : int(a[0])),
  min: (a) => (int(a[0]) <= int(a[1]) ? int(a[0]) : int(a[1])),
  max: (a) => (int(a[0]) >= int(a[1]) ? int(a[0]) : int(a[1])),
  pow: (a, c) => modPow(int(a[0]), int(a[1]), int(a[2]), c),
  bit_length: (a) => BigInt(bitLength(int(a[0]))),
  fail: (a) => {
    const code = a[0] as string;
    if (code.startsWith('SCRIPT_') || code.startsWith('BYTES_')) {
      return fail('SCRIPT_INVALID_ERROR_CODE', tmsg('script:eval.failReservedCode', { code }));
    }
    return fail(code, a[1] as string);
  },
};

/** 표(builtins.ts)에 있는데 구현이 없는 이름(range 제외). 테스트용 */
export function missingImpls(): string[] {
  return Object.keys(BUILTINS).filter((n) => BUILTINS[n].special !== 'range' && !(n in BUILTIN_IMPL));
}
