/**
 * 내장 스크립트 평가기 (builtin-script.md §4.3~4.8, §6, §9).
 * 타입 검사(checker)를 통과한 TypedProgram만 실행한다. AST를 직접 순회하며 eval/Function을 쓰지 않는다.
 *
 * 값 의미론(§4.3): bytes와 string, int는 불변이다. 목록은 이름에서 이름으로 저장·전달될 때만 복사하고
 * 식의 결과(임시값)는 복사 없이 넘기므로, 변수가 목록을 단독으로 가지며 `xs += [v]`는 제자리에서 추가된다.
 */

import * as B from '../crypto/utils/bytesOps';
import { NodeError } from '../dag/errors';
import type { BinOp, Expr, IndexSpec, Stmt, TopItem } from './ast';
import { BUILTIN_IMPL } from './builtinImpl';
import { formatValue } from './format';
import type { TypedProgram } from './checker';
import { formatMsg, tmsg } from '../messages';
import {
  EvalCtx, RunOptions, ScriptValue, TIME_CHECK_INTERVAL, bitLength, checkBytes, checkInt, checkListLen, clampNum, fail,
  resolveLimits,
} from './runtime';

export type { RunOptions, ScriptValue } from './runtime';

const enum Flow { Normal, Break, Continue, Return }

interface Frame {
  vars: Map<string, ScriptValue>;
  ret?: ScriptValue;
}

/**
 * 스크립트를 실행해 출력 포트 값을 돌려준다. 오류는 NodeError로 던진다.
 * 입력은 포트 타입대로 int=bigint, bytes=Uint8Array, bool, string이어야 한다.
 * 해석기 내부의 예상치 못한 예외는 SCRIPT_INTERNAL_ERROR로 감싼다.
 */
export function runScript(typed: TypedProgram, inputs: Record<string, ScriptValue>, options: RunOptions = {}): Record<string, ScriptValue> {
  try {
    return new Interp(typed, options).run(inputs);
  } catch (e) {
    if (e instanceof NodeError) throw e;
    throw new NodeError('SCRIPT_INTERNAL_ERROR', tmsg('script:eval.internal', { detail: e instanceof Error ? e.message : String(e) }));
  }
}

function typeMatches(t: string, v: unknown): boolean {
  switch (t) {
    case 'int': return typeof v === 'bigint';
    case 'bool': return typeof v === 'boolean';
    case 'string': return typeof v === 'string';
    case 'bytes': return v instanceof Uint8Array;
    default: return false;
  }
}

const isList = (v: ScriptValue): v is ScriptValue[] => Array.isArray(v);

function deepEq(a: ScriptValue, b: ScriptValue): boolean {
  if (a instanceof Uint8Array) return B.equals(a, b as Uint8Array);
  if (isList(a)) {
    const bl = b as ScriptValue[];
    return a.length === bl.length && a.every((x, i) => deepEq(x, bl[i]));
  }
  return a === b;
}

class Interp implements EvalCtx {
  maxBytes: number;
  maxListLen: number;
  maxIntBits: number;
  private maxSteps: number;
  private steps = 0;
  private now: () => number;
  private deadline: number;
  private consts = new Map<string, ScriptValue>();

  constructor(private typed: TypedProgram, options: RunOptions) {
    const l = resolveLimits(options);
    this.maxBytes = l.maxBytes;
    this.maxListLen = l.maxListLen;
    this.maxIntBits = l.maxIntBits;
    this.maxSteps = l.maxSteps;
    this.now = options.now ?? (() => performance.now());
    this.deadline = this.now() + l.timeLimitMs;
  }

  // ---- 자원 한도 ----

  tick(): void {
    if (++this.steps > this.maxSteps) fail('SCRIPT_STEP_LIMIT', tmsg('script:eval.stepLimit', { maxSteps: this.maxSteps }));
    if (this.steps % TIME_CHECK_INTERVAL === 0) this.checkTime();
  }

  checkTime(): void {
    if (this.now() > this.deadline) fail('SCRIPT_TIMEOUT', tmsg('script:eval.timeout'));
  }

  // ---- 진입 ----

  run(inputs: Record<string, ScriptValue>): Record<string, ScriptValue> {
    const f: Frame = { vars: new Map() };
    for (const [id, t] of this.typed.inputs) {
      if (!typeMatches(t, inputs[id])) fail('SCRIPT_INTERNAL_ERROR', tmsg('script:eval.inputType', { id, t }));
      f.vars.set(id, inputs[id]);
    }
    this.block(this.typed.program.body, f);
    const out: Record<string, ScriptValue> = {};
    for (const id of this.typed.outputs.keys()) {
      const v = f.vars.get(id);
      if (v === undefined) fail('SCRIPT_INTERNAL_ERROR', tmsg('script:eval.outputUnassigned', { id }));
      out[id] = v as ScriptValue;
    }
    return out;
  }

  // ---- 문장 ----

  private block(items: TopItem[], f: Frame): Flow {
    for (const s of items) {
      if (s.kind === 'FuncDef') continue; // 함수는 심볼 표로 호출한다
      const flow = this.stmt(s, f);
      if (flow !== Flow.Normal) return flow;
    }
    return Flow.Normal;
  }

  private setVar(name: string, v: ScriptValue, f: Frame) {
    if (this.typed.consts.has(name)) this.consts.set(name, v);
    else f.vars.set(name, v);
  }

  private stmt(s: Stmt, f: Frame): Flow {
    this.tick();
    switch (s.kind) {
      case 'Assign': case 'AnnAssign':
        this.setVar(s.target.name, this.owned(s.value, f), f);
        return Flow.Normal;
      case 'AugAssign': {
        const name = s.target.name;
        const cur = f.vars.get(name) as ScriptValue;
        const rhs = this.ev(s.value, f);
        if (s.op === '+' && isList(cur)) {
          const r = rhs as ScriptValue[];
          const n = r.length;
          checkListLen(this, cur.length + n);
          for (let i = 0; i < n; i++) cur.push(r[i]); // 변수가 목록을 단독으로 가지므로 제자리 추가
        } else {
          f.vars.set(name, this.binop(s.op, cur, rhs));
        }
        return Flow.Normal;
      }
      case 'SubAssign': this.subAssign(s, f); return Flow.Normal;
      case 'Unpack': {
        const v = s.value;
        const vals = v.kind === 'Tuple' ? v.elements.map((e) => this.owned(e, f)) : (this.ev(v, f) as ScriptValue[]);
        s.targets.forEach((t, i) => this.setVar(t.name, vals[i], f));
        return Flow.Normal;
      }
      case 'If': {
        for (const b of s.branches) {
          if (this.ev(b.test, f) === true) return this.block(b.body, f);
        }
        return s.orelse ? this.block(s.orelse, f) : Flow.Normal;
      }
      case 'For': return this.forStmt(s, f);
      case 'Return':
        if (s.value) f.ret = this.moved(s.value, f);
        return Flow.Return;
      case 'Break': return Flow.Break;
      case 'Continue': return Flow.Continue;
      case 'Pass': return Flow.Normal;
      case 'ExprStmt': this.ev(s.call, f); return Flow.Normal;
    }
  }

  private forStmt(s: Extract<Stmt, { kind: 'For' }>, f: Frame): Flow {
    const name = s.target.name;
    const it = s.iter;
    let items: Iterable<ScriptValue>;
    let count: number;

    if (it.kind === 'Call' && it.name === 'range') {
      const a = it.args.map((x) => this.ev(x.value, f) as bigint);
      const start = a.length >= 2 ? a[0] : 0n;
      const stop = a.length >= 2 ? a[1] : a[0];
      const step = a.length === 3 ? a[2] : 1n;
      if (step === 0n) fail('SCRIPT_INVALID_ARGUMENT', tmsg('script:eval.rangeStepZero'));
      let n = 0n;
      if (step > 0n) { if (stop > start) n = (stop - start + step - 1n) / step; }
      else if (start > stop) n = (start - stop - step - 1n) / -step;
      if (n > BigInt(this.maxListLen)) fail('SCRIPT_SIZE_LIMIT', tmsg('script:eval.loopLimit', { maxListLen: this.maxListLen }));
      count = Number(n);
      items = (function* () { for (let i = 0n, v = start; i < n; i++, v += step) yield v; })();
    } else {
      const v = this.ev(it, f);
      if (v instanceof Uint8Array) {
        count = v.length;
        items = (function* () { for (let i = 0; i < v.length; i++) yield BigInt(v[i]); })();
      } else {
        const list = v as ScriptValue[];
        count = list.length;
        // 반복이 시작될 때 값이 정해진다: 본문에서 같은 목록 변수를 바꿔도 영향이 없다
        items = it.kind === 'Name' ? list.slice() : list;
      }
      if (count > this.maxListLen) fail('SCRIPT_SIZE_LIMIT', tmsg('script:eval.loopLimit', { maxListLen: this.maxListLen }));
    }

    let result = Flow.Normal;
    for (const x of items) {
      this.tick();
      f.vars.set(name, x);
      const flow = this.block(s.body, f);
      if (flow === Flow.Break) break;
      if (flow === Flow.Return) { result = Flow.Return; break; }
    }
    f.vars.delete(name); // 반복 변수는 반복문 밖에서 볼 수 없다
    return result;
  }

  private subAssign(s: Extract<Stmt, { kind: 'SubAssign' }>, f: Frame) {
    const name = s.target.name;
    const cur = f.vars.get(name) as ScriptValue;
    const idx = s.index;
    if (idx.kind === 'item') {
      const i = this.ev(idx.index, f) as bigint;
      const v = this.ev(s.value, f);
      if (cur instanceof Uint8Array) {
        const part = B.fromInts([clampNum(v as bigint)]);
        f.vars.set(name, B.replace(cur, clampNum(i), part));
      } else {
        const list = cur as ScriptValue[];
        const k = this.listIndex(i, list.length);
        list[k] = v; // 변수가 목록을 단독으로 가진다
      }
      return;
    }
    // 구간 대입은 bytes만(문법 §3.4)
    const b = cur as Uint8Array;
    const [from, to] = this.range(idx, b.length, 'BYTES_OUT_OF_RANGE', f);
    const part = this.ev(s.value, f) as Uint8Array;
    if (part.length !== to - from) {
      fail('BYTES_LENGTH_MISMATCH', tmsg('script:eval.sliceLengthMismatch', { sliceLength: to - from, length: part.length }));
    }
    f.vars.set(name, B.replace(b, from, part));
  }

  // ---- 값 소유 (§4.3) ----

  /** 저장·전달용으로 평가한다. 이름이 가리키는 목록은 복사한다(bytes는 불변이라 복사하지 않음). */
  private owned(e: Expr, f: Frame): ScriptValue {
    if (e.kind === 'Name') {
      const v = this.lookup(e, f);
      return isList(v) ? v.slice() : v;
    }
    if (e.kind === 'Cond') {
      this.tick();
      return this.owned(this.ev(e.test, f) === true ? e.then : e.otherwise, f);
    }
    return this.ev(e, f);
  }

  /** return 값: 함수의 지역 변수는 틀이 사라지므로 복사 없이 넘기고, 상수는 복사한다. */
  private moved(e: Expr, f: Frame): ScriptValue {
    if (e.kind === 'Tuple') return e.elements.map((x) => this.owned(x, f)); // 같은 변수를 두 번 담을 수 있으므로 복사한다
    if (e.kind === 'Name' && e.ref === 'var') return this.lookup(e, f);
    if (e.kind === 'Cond') {
      this.tick();
      return this.moved(this.ev(e.test, f) === true ? e.then : e.otherwise, f);
    }
    return this.owned(e, f);
  }

  private lookup(e: Extract<Expr, { kind: 'Name' }>, f: Frame): ScriptValue {
    const v = e.ref === 'const' ? this.consts.get(e.name) : f.vars.get(e.name);
    if (v === undefined) throw new Error(formatMsg(tmsg('script:eval.noValue', { name: e.name })));
    return v;
  }

  // ---- 식 ----

  private ev(e: Expr, f: Frame): ScriptValue {
    switch (e.kind) {
      case 'IntLit': case 'BoolLit': case 'StrLit': case 'BytesLit': return e.value;
      case 'FString': {
        let out = '';
        for (const p of e.parts) {
          if (typeof p === 'string') { out += p; continue; }
          this.tick();
          out += formatValue(this.ev(p.expr, f) as bigint | string | boolean | Uint8Array, p.spec);
        }
        return out;
      }
      case 'Name': return this.lookup(e, f);
      case 'ListLit': {
        const xs = e.elements.map((x) => this.ev(x, f));
        checkListLen(this, xs.length);
        return xs;
      }
      case 'Tuple': return e.elements.map((x) => this.ev(x, f));
      case 'Unary': {
        this.tick();
        const v = this.ev(e.operand, f);
        if (e.op === 'not') return !(v as boolean);
        if (e.op === '-') return checkInt(this, -(v as bigint));
        return v instanceof Uint8Array ? B.not(v) : ~(v as bigint);
      }
      case 'Binary': {
        this.tick();
        if (e.op === 'and') return this.ev(e.left, f) === true && this.ev(e.right, f) === true;
        if (e.op === 'or') return this.ev(e.left, f) === true || this.ev(e.right, f) === true;
        return this.binop(e.op, this.ev(e.left, f), this.ev(e.right, f));
      }
      case 'Cond': {
        this.tick();
        return this.ev(this.ev(e.test, f) === true ? e.then : e.otherwise, f);
      }
      case 'Index': {
        this.tick();
        return this.index(this.ev(e.target, f), e.index, f);
      }
      case 'Call': return this.call(e, f);
    }
  }

  private call(e: Extract<Expr, { kind: 'Call' }>, f: Frame): ScriptValue {
    this.tick();
    if (e.callee === 'builtin') {
      const args = e.args.map((a) => this.ev(a.value, f)); // 내장 함수는 인자를 바꾸거나 간직하지 않으므로 복사하지 않는다
      return BUILTIN_IMPL[e.name](args, this);
    }
    const sig = this.typed.funcs.get(e.name);
    if (!sig) throw new Error(formatMsg(tmsg('script:eval.noFunction', { name: e.name })));
    const nf: Frame = { vars: new Map() };
    sig.params.forEach((p, i) => nf.vars.set(p.name, this.owned(e.args[i].value, f)));
    this.block(sig.def.body, nf);
    return nf.ret as ScriptValue;
  }

  private binop(op: BinOp, a: ScriptValue, b: ScriptValue): ScriptValue {
    if (op === '==') return deepEq(a, b);
    if (op === '!=') return !deepEq(a, b);

    if (a instanceof Uint8Array || b instanceof Uint8Array) return this.bytesBinop(op, a, b);

    if (typeof a === 'bigint') return this.intBinop(op, a, b as bigint);

    if (typeof a === 'string') return (a as string) + (b as string); // '+'만 가능(검사기 보장)

    const la = a as ScriptValue[];
    const lb = b as ScriptValue[];
    checkListLen(this, la.length + lb.length);
    return la.concat(lb); // '+'만 가능
  }

  private bytesBinop(op: BinOp, a: ScriptValue, b: ScriptValue): ScriptValue {
    if (op === '*') {
      const [bs, n] = a instanceof Uint8Array ? [a, b as bigint] : [b as Uint8Array, a as bigint];
      return checkBytes(this, B.repeat(bs, clampNum(n)));
    }
    const x = a as Uint8Array;
    switch (op) {
      case '&': return B.and(x, b as Uint8Array);
      case '|': return B.or(x, b as Uint8Array);
      case '^': return B.xor(x, b as Uint8Array);
      case '<<': return B.shl(x, clampNum(b as bigint));
      case '>>': return B.shr(x, clampNum(b as bigint));
      case '+': return checkBytes(this, B.concat([x, b as Uint8Array]));
      case '<': return B.compare(x, b as Uint8Array) < 0;
      case '<=': return B.compare(x, b as Uint8Array) <= 0;
      case '>': return B.compare(x, b as Uint8Array) > 0;
      case '>=': return B.compare(x, b as Uint8Array) >= 0;
      default: throw new Error(formatMsg(tmsg('script:eval.bytesOperator', { op })));
    }
  }

  private intBinop(op: BinOp, a: bigint, b: bigint): ScriptValue {
    switch (op) {
      case '+': return checkInt(this, a + b);
      case '-': return checkInt(this, a - b);
      case '*': return checkInt(this, a * b);
      case '//': {
        if (b === 0n) fail('SCRIPT_DIVISION_BY_ZERO', tmsg('script:eval.divByZero'));
        const q = a / b;
        return a % b !== 0n && a < 0n !== b < 0n ? q - 1n : q; // 내림 나눗셈
      }
      case '%': {
        if (b === 0n) fail('SCRIPT_DIVISION_BY_ZERO', tmsg('script:eval.divByZero'));
        const r = a % b;
        return r !== 0n && r < 0n !== b < 0n ? r + b : r; // 나머지의 부호는 제수를 따른다
      }
      case '&': return a & b;
      case '|': return a | b;
      case '^': return a ^ b;
      case '<<': {
        if (b < 0n) fail('SCRIPT_INVALID_ARGUMENT', tmsg('script:eval.shiftNegative'));
        if (a === 0n) return 0n;
        if (b > BigInt(this.maxIntBits) || bitLength(a) + Number(b) > this.maxIntBits) {
          fail('SCRIPT_SIZE_LIMIT', tmsg('script:eval.shiftTooLarge', { maxIntBits: this.maxIntBits })); // 계산 전에 거부한다
        }
        return a << b;
      }
      case '>>': {
        if (b < 0n) fail('SCRIPT_INVALID_ARGUMENT', tmsg('script:eval.shiftNegative'));
        if (b > BigInt(bitLength(a) + 1)) return a < 0n ? -1n : 0n;
        return a >> b;
      }
      case '<': return a < b;
      case '<=': return a <= b;
      case '>': return a > b;
      case '>=': return a >= b;
      default: throw new Error(formatMsg(tmsg('script:eval.intOperator', { op })));
    }
  }

  // ---- 첨자 (§4.7) ----

  private listIndex(i: bigint, len: number): number {
    const k = i < 0n ? BigInt(len) + i : i;
    if (k < 0n || k >= BigInt(len)) fail('SCRIPT_INDEX_OUT_OF_RANGE', tmsg('script:eval.listIndex', { i, len }));
    return Number(k);
  }

  /** 구간의 [시작, 끝)을 정한다. 0 ≤ 시작 ≤ 끝 ≤ 길이가 아니면 code 오류. 자르거나 보정하지 않는다. */
  private range(idx: Exclude<IndexSpec, { kind: 'item' }>, len: number, code: string, f: Frame): [number, number] {
    const L = BigInt(len);
    const neg = (v: bigint) => (v < 0n ? L + v : v);
    let s: bigint;
    let e: bigint;
    if (idx.kind === 'slice') {
      s = idx.start ? neg(this.ev(idx.start, f) as bigint) : 0n;
      e = idx.stop ? neg(this.ev(idx.stop, f) as bigint) : L;
    } else {
      const o = this.ev(idx.offset, f) as bigint;
      s = neg(o);
      if (!idx.length) e = L; // b[o,]
      else {
        const n = this.ev(idx.length, f) as bigint;
        e = n >= 0n ? s + n : L + n; // n < 0은 b[a:c]의 c처럼 뒤에서부터의 끝 위치(제외)
      }
    }
    if (s < 0n || s > e || e > L) fail(code, tmsg('script:eval.sliceOutOfRange', { s, e, len }));
    return [Number(s), Number(e)];
  }

  private index(target: ScriptValue, idx: IndexSpec, f: Frame): ScriptValue {
    if (idx.kind === 'item') {
      const i = this.ev(idx.index, f) as bigint;
      if (target instanceof Uint8Array) return BigInt(B.get(target, clampNum(i)));
      const list = target as ScriptValue[];
      return list[this.listIndex(i, list.length)];
    }
    if (target instanceof Uint8Array) {
      const [s, e] = this.range(idx, target.length, 'BYTES_OUT_OF_RANGE', f);
      return B.slice(target, s, e - s);
    }
    const list = target as ScriptValue[];
    const [s, e] = this.range(idx, list.length, 'SCRIPT_INDEX_OUT_OF_RANGE', f);
    return list.slice(s, e);
  }
}
