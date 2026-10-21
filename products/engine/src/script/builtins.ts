/**
 * 내장 함수 표 (builtin-script.md §7). 단일 원천.
 * 타입 검사(checker), 에디터 자동 완성(T08), 평가기(T06)가 이 표를 함께 쓴다.
 * 내장 함수는 이 표에서만 늘어난다. 늘릴 때는 scriptVersion을 올린다(§11).
 */

import type { Ty } from './ast';
import { Msg, tmsg } from '../messages';

/** 매개변수 타입. 'sized'는 bytes 또는 모든 list[T] (`len` 전용) */
export type ParamType = Ty | 'sized';

export interface BuiltinParam {
  name: string;
  type: ParamType;
  /** 기본값이 있으면 생략할 수 있다(키워드 인자 지정도 가능) */
  default?: bigint | boolean | string;
}

export interface BuiltinSig {
  name: string;
  params: BuiltinParam[];
  /** void: 값이 없음(fail), range: for 전용 */
  ret: Ty | 'void' | 'range';
  /** `range`는 인자 1~3개 int이며 for의 반복 대상으로만 쓴다 */
  special?: 'range';
  /** 자동 완성 등에 보이는 한 줄 설명 */
  doc: Msg;
}

const P = (name: string, type: ParamType, def?: BuiltinParam['default']): BuiltinParam =>
  def === undefined ? { name, type } : { name, type, default: def };

const list: BuiltinSig[] = [
  { name: 'len', params: [P('x', 'sized')], ret: 'int', doc: tmsg('script:builtin.len') },
  { name: 'zeros', params: [P('n', 'int')], ret: 'bytes', doc: tmsg('script:builtin.zeros') },
  { name: 'fill', params: [P('value', 'int'), P('n', 'int')], ret: 'bytes', doc: tmsg('script:builtin.fill') },
  { name: 'concat', params: [P('parts', 'list[bytes]')], ret: 'bytes', doc: tmsg('script:builtin.concat') },
  { name: 'reverse', params: [P('b', 'bytes')], ret: 'bytes', doc: tmsg('script:builtin.reverse') },
  { name: 'blocks', params: [P('b', 'bytes'), P('size', 'int')], ret: 'list[bytes]', doc: tmsg('script:builtin.blocks') },
  { name: 'to_ints', params: [P('b', 'bytes')], ret: 'list[int]', doc: tmsg('script:builtin.to_ints') },
  { name: 'from_ints', params: [P('xs', 'list[int]')], ret: 'bytes', doc: tmsg('script:builtin.from_ints') },
  { name: 'rol', params: [P('b', 'bytes'), P('n', 'int')], ret: 'bytes', doc: tmsg('script:builtin.rol') },
  { name: 'ror', params: [P('b', 'bytes'), P('n', 'int')], ret: 'bytes', doc: tmsg('script:builtin.ror') },
  { name: 'ct_equals', params: [P('a', 'bytes'), P('b', 'bytes')], ret: 'bool', doc: tmsg('script:builtin.ct_equals') },
  { name: 'compare', params: [P('a', 'bytes'), P('b', 'bytes')], ret: 'int', doc: tmsg('script:builtin.compare') },
  { name: 'to_int', params: [P('b', 'bytes'), P('endian', 'string', 'big'), P('signed', 'bool', false)], ret: 'int', doc: tmsg('script:builtin.to_int') },
  { name: 'to_bytes', params: [P('n', 'int'), P('length', 'int'), P('endian', 'string', 'big'), P('signed', 'bool', false)], ret: 'bytes', doc: tmsg('script:builtin.to_bytes') },
  { name: 'from_hex', params: [P('s', 'string')], ret: 'bytes', doc: tmsg('script:builtin.from_hex') },
  { name: 'to_hex', params: [P('b', 'bytes'), P('upper', 'bool', false)], ret: 'string', doc: tmsg('script:builtin.to_hex') },
  { name: 'from_utf8', params: [P('s', 'string')], ret: 'bytes', doc: tmsg('script:builtin.from_utf8') },
  { name: 'to_utf8', params: [P('b', 'bytes')], ret: 'string', doc: tmsg('script:builtin.to_utf8') },
  { name: 'str', params: [P('n', 'int')], ret: 'string', doc: tmsg('script:builtin.str') },
  { name: 'abs', params: [P('n', 'int')], ret: 'int', doc: tmsg('script:builtin.abs') },
  { name: 'min', params: [P('a', 'int'), P('b', 'int')], ret: 'int', doc: tmsg('script:builtin.min') },
  { name: 'max', params: [P('a', 'int'), P('b', 'int')], ret: 'int', doc: tmsg('script:builtin.max') },
  { name: 'pow', params: [P('base', 'int'), P('exp', 'int'), P('mod', 'int')], ret: 'int', doc: tmsg('script:builtin.pow') },
  { name: 'bit_length', params: [P('n', 'int')], ret: 'int', doc: tmsg('script:builtin.bit_length') },
  { name: 'range', params: [], ret: 'range', special: 'range', doc: tmsg('script:builtin.range') },
  { name: 'fail', params: [P('code', 'string'), P('message', 'string')], ret: 'void', doc: tmsg('script:builtin.fail') },
];

export const BUILTINS: Readonly<Record<string, BuiltinSig>> = Object.fromEntries(list.map((s) => [s.name, s]));

export function isBuiltin(name: string): boolean {
  return Object.prototype.hasOwnProperty.call(BUILTINS, name);
}
