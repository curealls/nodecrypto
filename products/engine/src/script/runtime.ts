/**
 * 내장 스크립트 실행 공통 부분: 값 표현, 옵션, 자원 한도 검사 (builtin-script.md §9).
 */

import { NodeError } from '../dag/errors';
import { MAX_BYTES, MAX_INT_BITS, MAX_LIST_LEN, MAX_STEPS } from './limits';
import { Msg, tmsg } from '../messages';

/** int는 bigint, bytes는 Uint8Array, list는 배열(원소는 int/bool/bytes/string) */
export type ScriptValue = bigint | boolean | string | Uint8Array | ScriptValue[];

export interface RunOptions {
  maxSteps?: number;
  /** bytesOps의 상한(MAX_BYTES)보다 낮추는 방향으로만 바꿀 수 있다 */
  maxBytes?: number;
  maxListLen?: number;
  maxIntBits?: number;
  /** 시간 상한(ms). 기본 10초(API Container). 웹은 스크립트 노드가 3초를 넘긴다(§9) */
  timeLimitMs?: number;
  /** 경과 시간 측정(테스트용). 기본 performance.now */
  now?: () => number;
}

export const DEFAULT_TIME_LIMIT_MS = 10_000;
/** 이 단계 수마다 경과 시간을 검사한다 */
export const TIME_CHECK_INTERVAL = 1024;

/** 내장 함수와 연산이 쓰는 실행 문맥 */
export interface EvalCtx {
  maxBytes: number;
  maxListLen: number;
  maxIntBits: number;
  /** 1단계를 센다 (SCRIPT_STEP_LIMIT, 주기적인 SCRIPT_TIMEOUT 검사) */
  tick(): void;
  /** 경과 시간을 즉시 검사한다 (SCRIPT_TIMEOUT) */
  checkTime(): void;
}

export function resolveLimits(o: RunOptions) {
  return {
    maxSteps: o.maxSteps ?? MAX_STEPS,
    maxBytes: Math.min(o.maxBytes ?? MAX_BYTES, MAX_BYTES),
    maxListLen: o.maxListLen ?? MAX_LIST_LEN,
    maxIntBits: o.maxIntBits ?? MAX_INT_BITS,
    timeLimitMs: o.timeLimitMs ?? DEFAULT_TIME_LIMIT_MS,
  };
}

export function fail(code: string, message: string | Msg): never {
  throw new NodeError(code, message);
}

const SAFE = BigInt(Number.MAX_SAFE_INTEGER);
const SMALL = 1n << 53n;

/** bytesOps의 인덱스·개수·이동량은 number이다. 안전 정수를 넘는 값은 끝값으로 잘라 넘긴다(어차피 범위·한도 오류가 되는 값). */
export function clampNum(n: bigint): number {
  if (n > SAFE) return Number.MAX_SAFE_INTEGER;
  if (n < -SAFE) return -Number.MAX_SAFE_INTEGER;
  return Number(n);
}

/** |v|를 나타내는 데 필요한 최소 비트 수. 0은 0 */
export function bitLength(v: bigint): number {
  if (v < 0n) v = -v;
  if (v < SMALL) return v === 0n ? 0 : Number(v).toString(2).length;
  const h = v.toString(16);
  return (h.length - 1) * 4 + (32 - Math.clz32(parseInt(h[0], 16)));
}

export function checkInt(ctx: EvalCtx, v: bigint): bigint {
  if (v > -SMALL && v < SMALL) return v;
  const bits = bitLength(v);
  if (bits > ctx.maxIntBits) fail('SCRIPT_SIZE_LIMIT', tmsg('script:limit.intTooLarge', { bits, maxIntBits: ctx.maxIntBits }));
  return v;
}

export function checkBytes(ctx: EvalCtx, b: Uint8Array): Uint8Array {
  if (b.length > ctx.maxBytes) fail('BYTES_SIZE_LIMIT', tmsg('script:limit.bytesTooLong', { length: b.length, maxBytes: ctx.maxBytes }));
  return b;
}

export function checkListLen(ctx: EvalCtx, n: number): void {
  if (n > ctx.maxListLen) fail('SCRIPT_SIZE_LIMIT', tmsg('script:limit.listTooLong', { n, maxListLen: ctx.maxListLen }));
}
