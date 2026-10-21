/**
 * 내장 스크립트 자원 한도 (builtin-script.md §9).
 * 2026-10-03 측정으로 확정했다(U-03, D-22).
 */

export { MAX_BYTES } from '../crypto/utils/bytesOps';

/** 실행할 수 있는 연산 단계(문장과 연산자 평가) 수 */
export const MAX_STEPS = 10_000_000;
/** 목록 하나의 최대 길이, `for` 한 번의 최대 반복 횟수 */
export const MAX_LIST_LEN = 1_048_576;
/** `int` 하나의 최대 비트 수 */
export const MAX_INT_BITS = 1_048_576;
/** f-string 서식 지정의 너비 */
export const MAX_FORMAT_WIDTH = 4096;
/** 스크립트 소스 크기(UTF-8 바이트) */
export const MAX_SOURCE = 64 * 1024;
