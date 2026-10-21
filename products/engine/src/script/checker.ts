/**
 * 내장 스크립트 타입 검사와 정적 분석 (builtin-script.md §2.2, §4, §6.1).
 * 이 검사를 통과한 스크립트만 저장되고 실행된다. 통과하면 모든 식에 확정 타입(`ty`)이 붙는다.
 */

import type {
  BinOp, Expr, ExprTy, FuncDef, IndexSpec, NameRef, PrimName, Program, RetType, Stmt, TopItem, Ty, TypeAnn,
} from './ast';
import { BUILTINS, isBuiltin } from './builtins';
import type { BuiltinParam, BuiltinSig } from './builtins';
import { Diagnostic, Span, makeDiagnostic } from './diagnostics';
import { RESERVED, UNSUPPORTED_HINT } from './lexer';
import { MAX_INT_BITS } from './limits';
import { validateSpec } from './format';
import { Msg, tmsg } from '../messages';

export interface PortSpec {
  id: string;
  /** 'bytes' | 'int' | 'bool' | 'string'만 가능하다. 그 밖의 값은 진단한다. */
  dataType: string;
}

export interface PortList {
  inputs: PortSpec[];
  outputs: PortSpec[];
}

export interface FuncSig {
  name: string;
  params: { name: string; type: Ty }[];
  /** 없으면 반환값이 없는 함수 */
  ret?: Ty | { tuple: Ty[] };
  def: FuncDef;
}

export interface TypedProgram {
  /** 모든 식에 `ty`가 채워진 AST. 내장 함수 호출은 인자가 위치 순서로 정렬되고 기본값이 채워져 있다. */
  program: Program;
  funcs: Map<string, FuncSig>;
  consts: Map<string, Ty>;
  inputs: Map<string, Ty>;
  outputs: Map<string, Ty>;
}

export interface CheckResult {
  /** 진단이 없을 때만 있다 */
  typed?: TypedProgram;
  diagnostics: Diagnostic[];
}

export function check(program: Program, ports: PortList): CheckResult {
  return new Checker().run(program, ports);
}

// ---- 타입 도우미 ----

const PRIMS: PrimName[] = ['int', 'bool', 'bytes', 'string'];
const isValueTy = (t: ExprTy): t is Ty => typeof t === 'string' && t !== 'void' && t !== 'range';
const listOf = (p: PrimName): Ty => `list[${p}]`;
const elemOf = (t: Ty): PrimName | null => (t.startsWith('list[') ? (t.slice(5, -1) as PrimName) : null);
const annToTy = (a: TypeAnn): Ty => (a.kind === 'prim' ? a.name : listOf(a.elem));
const show = (t: ExprTy | null): Msg | string =>
  t === null ? tmsg('script:word.unknown') : typeof t === 'string' ? t : `tuple[${t.tuple.join(', ')}]`;
const IDENT = /^[A-Za-z_][A-Za-z0-9_]*$/;
const CONST_NAME = /^_*[A-Z][A-Z0-9_]*$/;
const NOWHERE: Span = { line: 1, column: 1, endLine: 1, endColumn: 1 };

/** 포트 id 규칙(§2.1) 위반 사유. taken은 같은 노드의 다른 포트 id이다. 편집 UI도 이 함수로 입력을 거른다. */
export function portIdProblem(id: string, taken: Iterable<string> = []): { message: Msg; code: string } | undefined {
  if (!IDENT.test(id)) return { message: tmsg('script:port.invalidId'), code: 'SCRIPT_PORT_INVALID_ID' };
  if (id.startsWith('__')) return { message: tmsg('script:port.reservedPrefix'), code: 'SCRIPT_PORT_INVALID_ID' };
  if (RESERVED.has(id) || id in UNSUPPORTED_HINT) return { message: tmsg('script:port.reservedWord'), code: 'SCRIPT_PORT_RESERVED_ID' };
  if (isBuiltin(id)) return { message: tmsg('script:port.builtinName'), code: 'SCRIPT_PORT_RESERVED_ID' };
  if (new Set(taken).has(id)) return { message: tmsg('script:port.duplicateId'), code: 'SCRIPT_PORT_DUPLICATE_ID' };
  return undefined;
}

/**
 * 다른 노드의 포트 이름으로 포트 id를 만든다(node-catalog.md ND-8.3 "자동 생성 핸들의 포트 id").
 * 쓸 수 있는 식별자가 남지 않으면 undefined이고, 호출자가 in{N}/out{N}으로 대신한다.
 */
export function portIdFromName(name: string, taken: Iterable<string> = []): string | undefined {
  let base = name.replace(/[^A-Za-z0-9_]+/g, '_');
  if (!/[A-Za-z0-9]/.test(base)) return undefined;
  if (/^[0-9]/.test(base)) base = '_' + base;
  if (base.startsWith('__')) base = base.replace(/^_+/, '_');
  const used = new Set(taken);
  if (portIdProblem(base, [])?.code === 'SCRIPT_PORT_RESERVED_ID') base += '_';
  let id = base;
  for (let n = 2; portIdProblem(id, used); n++) id = `${base}_${n}`;
  return id;
}

class CheckError {
  /** null이면 이미 보고된 오류에서 비롯된 연쇄 오류라 조용히 건너뛴다 */
  constructor(public diag: Diagnostic | null) {}
}

interface Var {
  /** null이면 정의 중 오류가 난 변수(이후 사용은 조용히 건너뜀) */
  type: Ty | null;
  kind: 'input' | 'output' | 'local' | 'param' | 'loop';
}

interface Scope {
  vars: Map<string, Var>;
}

interface FnCtx {
  ret?: Ty | { tuple: Ty[] };
}

class Checker {
  private diags: Diagnostic[] = [];
  private funcs = new Map<string, FuncSig>();
  private consts = new Map<string, Ty>();
  private allFuncNames = new Set<string>();
  private topAssigned = new Set<string>();
  private portIds = new Set<string>();
  private top: Scope = { vars: new Map() };
  private scope: Scope = this.top;
  private fn: FnCtx | null = null;
  private loopDepth = 0;
  /** if/for 안쪽 깊이. 최상위 문장은 0 */
  private nest = 0;
  /** 현재 지점에서 확실히 대입된 변수 이름 */
  private st = new Set<string>();

  // ---- 진입 ----

  run(program: Program, ports: PortList): CheckResult {
    const inputs = new Map<string, Ty>();
    const outputs = new Map<string, Ty>();
    this.checkPorts(ports, inputs, outputs);

    for (const [id, t] of inputs) this.top.vars.set(id, { type: t, kind: 'input' });
    for (const [id, t] of outputs) this.top.vars.set(id, { type: t, kind: 'output' });
    for (const id of [...inputs.keys(), ...outputs.keys()]) this.portIds.add(id);

    for (const item of program.body) {
      if (item.kind === 'FuncDef') this.allFuncNames.add(item.name);
      else this.collectAssigned(item, this.topAssigned);
    }

    const st = new Set<string>(inputs.keys());
    const term = this.block(program.body, st);
    if (!term) {
      const last = program.body[program.body.length - 1];
      const end = last ? { ...last.span, line: last.span.endLine, column: last.span.endColumn } : NOWHERE;
      for (const id of outputs.keys()) {
        if (!st.has(id)) {
          this.diags.push({
            ...makeDiagnostic(end,
              tmsg('script:output.unassigned', { id }),
              'SCRIPT_OUTPUT_UNASSIGNED'),
            port: { direction: 'output', id },
          });
        }
      }
    }

    const diagnostics = this.diags.sort((a, b) => a.line - b.line || a.column - b.column);
    if (diagnostics.length) return { diagnostics };
    return { typed: { program, funcs: this.funcs, consts: this.consts, inputs, outputs }, diagnostics };
  }

  private report(span: Span, message: Msg, code: string) {
    this.diags.push(makeDiagnostic(span, message, code));
  }

  private fail(span: Span, message: Msg, code: string): never {
    throw new CheckError(makeDiagnostic(span, message, code));
  }

  /** 오류를 기록하고 계속한다. 실패하면 undefined. */
  private attempt<T>(fn: () => T): T | undefined {
    try {
      return fn();
    } catch (e) {
      if (!(e instanceof CheckError)) throw e;
      if (e.diag) this.diags.push(e.diag);
      return undefined;
    }
  }

  // ---- 포트 (§2.2) ----

  private checkPorts(ports: PortList, inputs: Map<string, Ty>, outputs: Map<string, Ty>) {
    const seen = new Set<string>();
    const one = (p: PortSpec, dir: 'input' | 'output', into: Map<string, Ty>) => {
      const dirWord = tmsg(dir === 'input' ? 'script:word.input' : 'script:word.output');
      const bad = (msg: Msg, code: string) => this.diags.push({
        ...makeDiagnostic(NOWHERE, tmsg('script:port.problem', { dirWord, id: p.id, msg }), code),
        port: { direction: dir, id: p.id },
      });
      const problem = portIdProblem(p.id, seen);
      if (problem) return bad(problem.message, problem.code);
      seen.add(p.id);
      if (!PRIMS.includes(p.dataType as PrimName)) {
        return bad(tmsg('script:port.invalidType', { dataType: p.dataType }), 'SCRIPT_PORT_INVALID_TYPE');
      }
      into.set(p.id, p.dataType as Ty);
    };
    ports.inputs.forEach((p) => one(p, 'input', inputs));
    ports.outputs.forEach((p) => one(p, 'output', outputs));
  }

  /** 최상위 문장이 대입하는 모든 이름(함수 안에서 쓰려 할 때 안내 문구용) */
  private collectAssigned(s: Stmt, into: Set<string>) {
    switch (s.kind) {
      case 'Assign': case 'AnnAssign': case 'AugAssign': case 'SubAssign': into.add(s.target.name); break;
      case 'Unpack': s.targets.forEach((t) => into.add(t.name)); break;
      case 'If': s.branches.forEach((b) => b.body.forEach((x) => this.collectAssigned(x, into))); s.orelse?.forEach((x) => this.collectAssigned(x, into)); break;
      case 'For': into.add(s.target.name); s.body.forEach((x) => this.collectAssigned(x, into)); break;
      default: break;
    }
  }

  // ---- 문장 목록과 정의된 대입 분석 (§4.5) ----

  /** 문장 목록을 검사한다. 이 경로가 return/fail/break/continue로 끝나면 true. */
  private block(items: TopItem[], st: Set<string>): boolean {
    let term = false;
    for (const item of items) {
      this.st = st;
      try {
        if (item.kind === 'FuncDef') this.funcDef(item);
        else if (this.stmt(item, st)) term = true;
      } catch (e) {
        if (!(e instanceof CheckError)) throw e;
        if (e.diag) this.diags.push(e.diag);
        if (item.kind !== 'FuncDef') {
          this.poison(item, st);
          // 실패한 return/fail은 경로를 끝내는 것으로 본다(연쇄 오류 방지)
          if (item.kind === 'Return' || (item.kind === 'ExprStmt' && item.call.name === 'fail')) term = true;
        }
      }
    }
    return term;
  }

  /** 문장이 실패했을 때 정의하려던 이름을 연쇄 오류 없이 남겨 둔다. */
  private poison(s: Stmt, st: Set<string>) {
    const define = (n: NameRef, type: Ty | null) => {
      if (!this.scope.vars.has(n.name) && !this.consts.has(n.name)) this.scope.vars.set(n.name, { type, kind: 'local' });
    };
    // 대입이 실패해도 대상은 대입된 것으로 남겨 '대입되지 않음' 연쇄 오류를 막는다.
    if (s.kind === 'Assign') { define(s.target, null); st.add(s.target.name); }
    else if (s.kind === 'AnnAssign') { define(s.target, annToTy(s.type)); st.add(s.target.name); }
    else if (s.kind === 'Unpack') s.targets.forEach((t) => { define(t, null); st.add(t.name); });
  }

  /** 반환값은 이 문장 뒤로 경로가 이어지지 않으면 true */
  private stmt(s: Stmt, st: Set<string>): boolean {
    switch (s.kind) {
      case 'Assign': {
        const ty = this.valueTy(s.value);
        this.bind(s.target, ty, s.value, st);
        return false;
      }
      case 'AnnAssign': {
        const ann = annToTy(s.type);
        let ty: Ty;
        if (s.value.kind === 'ListLit' && s.value.elements.length === 0) {
          if (!elemOf(ann)) this.fail(s.value.span, tmsg('script:check.emptyListToVar', { ann }), 'SCRIPT_TYPE_MISMATCH');
          s.value.ty = ann;
          ty = ann;
        } else {
          ty = this.valueTy(s.value);
          if (ty !== ann) this.fail(s.value.span, tmsg('script:check.annotationMismatch', { ann, ty }), 'SCRIPT_TYPE_MISMATCH');
        }
        this.bind(s.target, ty, s.value, st);
        return false;
      }
      case 'AugAssign': return this.augAssign(s, st);
      case 'SubAssign': return this.subAssign(s, st);
      case 'Unpack': return this.unpack(s, st);
      case 'If': return this.ifStmt(s, st);
      case 'For': return this.forStmt(s, st);
      case 'Return': return this.returnStmt(s);
      case 'Break': case 'Continue':
        if (this.loopDepth === 0) {
          this.fail(s.span, tmsg('script:check.loopOnly', { kw: s.kind === 'Break' ? 'break' : 'continue' }), 'SCRIPT_LOOP_CONTROL_OUTSIDE');
        }
        return true;
      case 'Pass': return false;
      case 'ExprStmt': {
        this.checkExpr(s.call);
        return s.call.name === 'fail';
      }
    }
  }

  // ---- 이름과 대입 ----

  private checkNewName(name: string, span: Span) {
    if (isBuiltin(name)) this.fail(span, tmsg('script:check.nameIsBuiltin', { name }), 'SCRIPT_NAME_RESERVED');
    if (this.allFuncNames.has(name)) this.fail(span, tmsg('script:check.nameIsFunction', { name }), 'SCRIPT_NAME_CONFLICT');
    if (this.consts.has(name)) this.fail(span, tmsg('script:check.nameIsConst', { name }), 'SCRIPT_NAME_CONFLICT');
  }

  /** `name`에 `ty` 값을 대입한다(처음이면 변수를 정의하고 타입을 고정한다). */
  private bind(target: NameRef, ty: Ty, value: Expr | null, st: Set<string>) {
    const { name, span } = target;
    const v = this.scope.vars.get(name);
    if (v) {
      this.writable(v, name, span);
      if (v.type === null) v.type = ty;
      else if (v.type !== ty) this.mismatchAssign(name, v, ty, span, value);
      st.add(name);
      return;
    }
    if (!this.fn && CONST_NAME.test(name)) {
      if (this.nest > 0) this.fail(span, tmsg('script:check.constTopLevel', { name }), 'SCRIPT_CONST_NOT_TOP');
      if (this.consts.has(name)) this.fail(span, tmsg('script:check.constReassign', { name }), 'SCRIPT_CONST_REASSIGN');
      this.checkNewName(name, span);
      if (!value) this.fail(span, tmsg('script:check.constSingleAssign', { name }), 'SCRIPT_CONST_INVALID');
      if (!this.isConstExpr(value)) {
        this.fail(value.span, tmsg('script:check.constInit', { name }), 'SCRIPT_CONST_INVALID');
      }
      this.consts.set(name, ty);
      return;
    }
    this.checkNewName(name, span);
    this.scope.vars.set(name, { type: ty, kind: 'local' });
    st.add(name);
  }

  private writable(v: Var, name: string, span: Span) {
    if (v.kind === 'input') this.fail(span, tmsg('script:check.inputReadOnly', { name }), 'SCRIPT_INPUT_READONLY');
  }

  private mismatchAssign(name: string, v: Var, ty: Ty, span: Span, value: Expr | null) {
    const at = value ? value.span : span;
    if (v.kind === 'output') {
      this.fail(at, tmsg('script:check.outputTypeMismatch', { name, type: v.type, ty }), 'SCRIPT_OUTPUT_TYPE_MISMATCH');
    }
    this.fail(at, tmsg('script:check.varTypeFixed', { name, type: v.type, ty }), 'SCRIPT_TYPE_MISMATCH');
  }

  /** 이미 대입된 변수를 읽는다(복합 대입, 첨자 대입의 대상). */
  private readVar(ref: NameRef): Var {
    const v = this.scope.vars.get(ref.name);
    if (!v) {
      if (this.consts.has(ref.name)) this.fail(ref.span, tmsg('script:check.constImmutable', { name: ref.name }), 'SCRIPT_CONST_REASSIGN');
      this.undefinedName(ref.name, ref.span);
    }
    const var_ = v as Var;
    if (var_.type === null) throw new CheckError(null);
    if (!this.st.has(ref.name)) this.unassigned(ref.name, ref.span);
    return var_;
  }

  private unassigned(name: string, span: Span): never {
    return this.fail(span,
      tmsg('script:check.maybeUnassigned', { name }),
      'SCRIPT_UNASSIGNED');
  }

  private undefinedName(name: string, span: Span): never {
    if (this.fn && (this.portIds.has(name) || this.topAssigned.has(name))) {
      return this.fail(span, tmsg('script:check.fnOuterName', { name }), 'SCRIPT_FUNC_SCOPE');
    }
    if (this.allFuncNames.has(name) || isBuiltin(name)) {
      return this.fail(span, tmsg('script:check.nameIsFunctionValue', { name }), 'SCRIPT_NAME_UNDEFINED');
    }
    return this.fail(span, tmsg('script:check.undefinedName', { name }), 'SCRIPT_NAME_UNDEFINED');
  }

  private isConstExpr(e: Expr): boolean {
    switch (e.kind) {
      case 'IntLit': case 'BoolLit': case 'StrLit': case 'BytesLit': return true;
      case 'FString': return e.parts.every((p) => typeof p === 'string' || this.isConstExpr(p.expr));
      case 'ListLit': return e.elements.every((x) => this.isConstExpr(x));
      case 'Name': return e.ref === 'const';
      case 'Unary': return this.isConstExpr(e.operand);
      case 'Binary': return this.isConstExpr(e.left) && this.isConstExpr(e.right);
      case 'Cond': return this.isConstExpr(e.test) && this.isConstExpr(e.then) && this.isConstExpr(e.otherwise);
      case 'Index': return this.isConstExpr(e.target) && this.indexExprs(e.index).every((x) => this.isConstExpr(x));
      case 'Call': return e.callee === 'builtin' && e.name !== 'fail' && e.args.every((a) => this.isConstExpr(a.value));
      case 'Tuple': return false;
    }
  }

  private indexExprs(i: IndexSpec): Expr[] {
    if (i.kind === 'item') return [i.index];
    if (i.kind === 'slice') return [i.start, i.stop].filter((x): x is Expr => !!x);
    return i.length ? [i.offset, i.length] : [i.offset];
  }

  // ---- 문장별 검사 ----

  private augAssign(s: Extract<Stmt, { kind: 'AugAssign' }>, st: Set<string>): boolean {
    const v = this.readVar(s.target);
    this.writable(v, s.target.name, s.target.span);
    const lt = v.type as Ty;
    const rt = this.valueTy(s.value);
    const res = this.binaryResult(s.op, lt, rt);
    if (!res) this.binaryError(s.op, lt, rt, s.span);
    if (res !== lt) {
      this.fail(s.span, tmsg('script:check.augTypeMismatch', { op: s.op, res, lt, name: s.target.name }), 'SCRIPT_TYPE_MISMATCH');
    }
    st.add(s.target.name);
    return false;
  }

  private subAssign(s: Extract<Stmt, { kind: 'SubAssign' }>, st: Set<string>): boolean {
    const v = this.readVar(s.target);
    this.writable(v, s.target.name, s.target.span);
    const t = v.type as Ty;
    const idx = s.index;
    if (idx.kind === 'item') {
      this.expectInt(idx.index, tmsg('script:word.subscript'));
      const vt = this.valueTy(s.value);
      const want: Ty | null = t === 'bytes' ? 'int' : elemOf(t) as Ty | null;
      if (!want) this.fail(s.target.span, tmsg('script:check.subscriptAssignType', { t }), 'SCRIPT_TYPE_MISMATCH');
      if (vt !== want) {
        this.fail(s.value.span, tmsg('script:check.elementAssignMismatch', { t, want, vt }), 'SCRIPT_TYPE_MISMATCH');
      }
    } else {
      if (t !== 'bytes') this.fail(s.target.span, tmsg('script:check.sliceAssignType', { name: s.target.name, t }), 'SCRIPT_TYPE_MISMATCH');
      this.indexExprs(idx).forEach((x) => this.expectInt(x, tmsg('script:word.slice')));
      const vt = this.valueTy(s.value);
      if (vt !== 'bytes') this.fail(s.value.span, tmsg('script:check.sliceAssignValue', { vt }), 'SCRIPT_TYPE_MISMATCH');
    }
    st.add(s.target.name);
    return false;
  }

  private unpack(s: Extract<Stmt, { kind: 'Unpack' }>, st: Set<string>): boolean {
    const v = s.value;
    let types: Ty[];
    if (v.kind === 'Tuple') {
      types = v.elements.map((e) => this.valueTy(e));
      v.ty = { tuple: types };
    } else {
      const t = this.checkExpr(v);
      if (typeof t !== 'object') {
        this.fail(v.span, tmsg('script:check.unpackRhsTuple'), 'SCRIPT_TUPLE_MISMATCH');
      }
      types = (t as { tuple: Ty[] }).tuple;
    }
    if (types.length !== s.targets.length) {
      this.fail(v.span, tmsg('script:check.unpackArity', { length: s.targets.length, length2: types.length }), 'SCRIPT_TUPLE_MISMATCH');
    }
    const names = new Set<string>();
    for (const t of s.targets) {
      if (names.has(t.name)) this.fail(t.span, tmsg('script:check.unpackDuplicate', { name: t.name }), 'SCRIPT_TUPLE_MISMATCH');
      names.add(t.name);
    }
    s.targets.forEach((t, i) => this.bind(t, types[i], null, st));
    return false;
  }

  private ifStmt(s: Extract<Stmt, { kind: 'If' }>, st: Set<string>): boolean {
    const outs: Set<string>[] = [];
    for (const b of s.branches) {
      this.st = st;
      this.attempt(() => this.expectBool(b.test, tmsg('script:word.condition')));
      const bst = new Set(st);
      this.nest++;
      const term = this.block(b.body, bst);
      this.nest--;
      if (!term) outs.push(bst);
    }
    if (s.orelse) {
      const bst = new Set(st);
      this.nest++;
      const term = this.block(s.orelse, bst);
      this.nest--;
      if (!term) outs.push(bst);
    } else {
      outs.push(new Set(st));
    }
    if (outs.length === 0) return true; // 모든 분기가 return/fail/break/continue로 끝남
    const merged = [...outs[0]].filter((n) => outs.every((o) => o.has(n)));
    st.clear();
    merged.forEach((n) => st.add(n));
    return false;
  }

  private forStmt(s: Extract<Stmt, { kind: 'For' }>, st: Set<string>): boolean {
    const name = s.target.name;
    const elem = this.attempt((): Ty => {
      if (s.iter.kind === 'Call' && s.iter.name === 'range') return this.checkRange(s.iter);
      const t = this.valueTy(s.iter);
      if (t === 'bytes') return 'int';
      const e = elemOf(t);
      if (e) return e;
      return this.fail(s.iter.span, tmsg('script:check.forIterable', { t }), 'SCRIPT_TYPE_MISMATCH');
    });
    let defined = false;
    this.attempt(() => {
      if (this.scope.vars.has(name)) {
        this.fail(s.target.span, tmsg('script:check.loopVarDefined', { name }), 'SCRIPT_NAME_CONFLICT');
      }
      this.checkNewName(name, s.target.span);
      this.scope.vars.set(name, { type: elem ?? null, kind: 'loop' });
      defined = true;
    });
    const bst = new Set(st);
    bst.add(name);
    this.loopDepth++;
    this.nest++;
    this.block(s.body, bst);
    this.nest--;
    this.loopDepth--;
    if (defined) this.scope.vars.delete(name); // 반복 변수는 반복문 밖에서 볼 수 없다
    return false; // for 본문의 대입은 반복문 뒤에서 대입된 것으로 보지 않는다
  }

  private returnStmt(s: Extract<Stmt, { kind: 'Return' }>): boolean {
    if (!this.fn) this.fail(s.span, tmsg('script:check.returnOutsideFn'), 'SCRIPT_RETURN_OUTSIDE');
    const ret = this.fn!.ret;
    if (!ret) {
      if (s.value) this.fail(s.value.span, tmsg('script:check.returnWithoutType'), 'SCRIPT_RETURN_TYPE');
      return true;
    }
    if (!s.value) this.fail(s.span, tmsg('script:check.returnValueRequired', { type: show(ret) }), 'SCRIPT_RETURN_TYPE');
    const v = s.value!;
    if (typeof ret === 'string') {
      const t = this.valueTy(v);
      if (t !== ret) this.fail(v.span, tmsg('script:check.returnTypeMismatch', { ret, t }), 'SCRIPT_RETURN_TYPE');
      return true;
    }
    if (v.kind !== 'Tuple') this.fail(v.span, tmsg('script:check.returnTupleRequired', { type: show(ret) }), 'SCRIPT_RETURN_TYPE');
    const tup = v as Extract<Expr, { kind: 'Tuple' }>;
    if (tup.elements.length !== ret.tuple.length) {
      this.fail(v.span, tmsg('script:check.returnTupleArity', { length: ret.tuple.length, length2: tup.elements.length }), 'SCRIPT_TUPLE_MISMATCH');
    }
    const types = tup.elements.map((e) => this.valueTy(e));
    types.forEach((t, i) => {
      if (t !== ret.tuple[i]) {
        this.fail(tup.elements[i].span, tmsg('script:check.returnTupleItem', { index: i + 1, want: ret.tuple[i], t }), 'SCRIPT_RETURN_TYPE');
      }
    });
    tup.ty = { tuple: types };
    return true;
  }

  // ---- 함수 (§4.4) ----

  private funcDef(def: FuncDef) {
    const { name, nameSpan } = def;
    this.attempt(() => {
      if (isBuiltin(name)) this.fail(nameSpan, tmsg('script:check.fnNameBuiltin', { name }), 'SCRIPT_NAME_RESERVED');
      if (this.funcs.has(name)) this.fail(nameSpan, tmsg('script:check.fnDuplicate', { name }), 'SCRIPT_NAME_CONFLICT');
      if (this.portIds.has(name)) this.fail(nameSpan, tmsg('script:check.fnNamePort', { name }), 'SCRIPT_NAME_CONFLICT');
      if (this.consts.has(name) || this.topAssigned.has(name)) {
        this.fail(nameSpan, tmsg('script:check.fnNameVar', { name }), 'SCRIPT_NAME_CONFLICT');
      }
    });

    const params: FuncSig['params'] = [];
    const seen = new Set<string>();
    for (const p of def.params) {
      this.attempt(() => {
        if (seen.has(p.name)) this.fail(p.span, tmsg('script:check.paramDuplicate', { name: p.name }), 'SCRIPT_NAME_CONFLICT');
        seen.add(p.name);
        this.checkNewName(p.name, p.span);
      });
      params.push({ name: p.name, type: annToTy(p.type) });
    }
    let ret: FuncSig['ret'];
    if (def.ret) ret = this.retTy(def.ret);

    const outerScope = this.scope;
    const outerFn = this.fn;
    const outerSt = this.st;
    const outerNest = this.nest;
    this.scope = { vars: new Map(params.map((p) => [p.name, { type: p.type, kind: 'param' as const }])) };
    this.fn = { ret };
    this.nest = 0;
    this.loopDepth = 0;
    const fst = new Set(params.map((p) => p.name));
    const term = this.block(def.body, fst);
    if (ret && !term) {
      this.report(nameSpan, tmsg('script:check.fnMissingReturn', { name, type: show(ret) }), 'SCRIPT_RETURN_MISSING');
    }
    this.scope = outerScope;
    this.fn = outerFn;
    this.st = outerSt;
    this.nest = outerNest;

    this.funcs.set(name, { name, params, ret, def });
  }

  private retTy(r: RetType): Ty | { tuple: Ty[] } {
    return r.kind === 'single' ? annToTy(r.type) : { tuple: r.types.map(annToTy) };
  }

  // ---- 식 ----

  private valueTy(e: Expr): Ty {
    const t = this.checkExpr(e);
    if (isValueTy(t)) return t;
    if (t === 'void') this.fail(e.span, tmsg('script:check.voidAsValue'), 'SCRIPT_TYPE_MISMATCH');
    if (t === 'range') this.fail(e.span, tmsg('script:check.rangeContext'), 'SCRIPT_RANGE_CONTEXT');
    return this.fail(e.span, tmsg('script:syntax.tupleContext'), 'SCRIPT_TUPLE_CONTEXT');
  }

  private expectBool(e: Expr, what: Msg | string) {
    const t = this.valueTy(e);
    if (t !== 'bool') {
      this.fail(e.span, tmsg('script:check.mustBeBool', { what, t }), 'SCRIPT_TYPE_MISMATCH');
    }
  }

  private expectInt(e: Expr, what: Msg | string) {
    const t = this.valueTy(e);
    if (t !== 'int') this.fail(e.span, tmsg('script:check.mustBeInt', { what, t }), 'SCRIPT_TYPE_MISMATCH');
  }

  private checkExpr(e: Expr): ExprTy {
    const t = this.exprTy(e);
    e.ty = t;
    return t;
  }

  private exprTy(e: Expr): ExprTy {
    switch (e.kind) {
      case 'IntLit': {
        const bits = (e.value < 0n ? -e.value : e.value).toString(2).length;
        if (e.value !== 0n && bits > MAX_INT_BITS) {
          this.fail(e.span, tmsg('script:check.intLiteralTooLarge', { bits, MAX_INT_BITS }), 'SCRIPT_INT_LITERAL_TOO_LARGE');
        }
        return 'int';
      }
      case 'BoolLit': return 'bool';
      case 'StrLit': return 'string';
      case 'FString': return this.fstringTy(e);
      case 'BytesLit': return 'bytes';
      case 'Name': return this.nameTy(e);
      case 'ListLit': return this.listTy(e);
      case 'Unary': {
        const t = this.valueTy(e.operand);
        if (e.op === 'not') {
          if (t !== 'bool') this.fail(e.span, tmsg('script:check.notOperand', { t }), 'SCRIPT_TYPE_MISMATCH');
          return 'bool';
        }
        if (e.op === '-' && t === 'int') return 'int';
        if (e.op === '~' && (t === 'int' || t === 'bytes')) return t;
        return this.fail(e.span, tmsg('script:check.unaryOperand', { op: e.op, t }), 'SCRIPT_TYPE_MISMATCH');
      }
      case 'Binary': {
        const lt = this.valueTy(e.left);
        const rt = this.valueTy(e.right);
        const res = this.binaryResult(e.op, lt, rt);
        return res ?? this.binaryError(e.op, lt, rt, e.span);
      }
      case 'Cond': {
        this.expectBool(e.test, tmsg('script:word.conditionalCondition'));
        const a = this.valueTy(e.then);
        const b = this.valueTy(e.otherwise);
        if (a !== b) this.fail(e.span, tmsg('script:check.conditionalTypes', { a, b }), 'SCRIPT_TYPE_MISMATCH');
        return a;
      }
      case 'Index': return this.indexTy(e);
      case 'Call': return this.callTy(e);
      case 'Tuple': return this.fail(e.span, tmsg('script:syntax.tupleContext'), 'SCRIPT_TUPLE_CONTEXT');
    }
  }

  private nameTy(e: Extract<Expr, { kind: 'Name' }>): Ty {
    const v = this.scope.vars.get(e.name);
    if (v) {
      if (v.type === null) throw new CheckError(null);
      if (!this.st.has(e.name)) this.unassigned(e.name, e.span);
      e.ref = 'var';
      return v.type;
    }
    const c = this.consts.get(e.name);
    if (c) {
      e.ref = 'const';
      return c;
    }
    return this.undefinedName(e.name, e.span);
  }

  private listTy(e: Extract<Expr, { kind: 'ListLit' }>): Ty {
    if (e.elements.length === 0) {
      this.fail(e.span, tmsg('script:check.emptyListAnnotation'), 'SCRIPT_EMPTY_LIST');
    }
    const types = e.elements.map((x) => this.valueTy(x));
    types.forEach((t, i) => {
      if (elemOf(t)) this.fail(e.elements[i].span, tmsg('script:syntax.nestedList'), 'SCRIPT_NESTED_LIST');
      if (t !== types[0]) this.fail(e.elements[i].span, tmsg('script:check.listElementTypes', { type0: types[0], t }), 'SCRIPT_TYPE_MISMATCH');
    });
    return listOf(types[0] as PrimName);
  }

  /** f-string 필드의 값 타입과 서식 지정이 맞는지 검사한다(§4.9). */
  private fstringTy(e: Extract<Expr, { kind: 'FString' }>): Ty {
    for (const p of e.parts) {
      if (typeof p === 'string') continue;
      const t = this.valueTy(p.expr);
      const err = validateSpec(p.spec, t);
      if (err) this.fail(p.expr.span, err, 'SCRIPT_FORMAT_INVALID');
    }
    return 'string';
  }

  private indexTy(e: Extract<Expr, { kind: 'Index' }>): Ty {
    const t = this.valueTy(e.target);
    const idx = e.index;
    const elem = elemOf(t);
    if (t !== 'bytes' && !elem) this.fail(e.target.span, tmsg('script:check.subscriptType', { t }), 'SCRIPT_TYPE_MISMATCH');
    this.indexExprs(idx).forEach((x) => this.expectInt(x, tmsg('script:word.subscript')));
    if (idx.kind === 'item') return t === 'bytes' ? 'int' : (elem as Ty);
    return t; // 구간은 같은 타입
  }

  /** 이항 연산의 결과 타입(표에 없는 조합이면 undefined) — builtin-script.md §4.6 */
  private binaryResult(op: BinOp, l: Ty, r: Ty): Ty | undefined {
    switch (op) {
      case 'or': case 'and': return l === 'bool' && r === 'bool' ? 'bool' : undefined;
      case '==': case '!=': return l === r ? 'bool' : undefined;
      case '<': case '<=': case '>': case '>=': return l === r && (l === 'int' || l === 'bytes') ? 'bool' : undefined;
      case '|': case '^': case '&': return l === r && (l === 'int' || l === 'bytes') ? l : undefined;
      case '<<': case '>>': return r === 'int' && (l === 'int' || l === 'bytes') ? l : undefined;
      case '+': return l === r && (l === 'int' || l === 'bytes' || l === 'string' || elemOf(l)) ? l : undefined;
      case '-': case '//': case '%': return l === 'int' && r === 'int' ? 'int' : undefined;
      case '*':
        if (l === 'int' && r === 'int') return 'int';
        return (l === 'bytes' && r === 'int') || (l === 'int' && r === 'bytes') ? 'bytes' : undefined;
    }
  }

  private binaryError(op: BinOp, l: Ty, r: Ty, span: Span): never {
    let hint: Msg | string = tmsg('script:hint.noImplicitCast');
    if ((l === 'int' && r === 'bytes') || (l === 'bytes' && r === 'int')) hint = tmsg('script:hint.useConversion');
    else if (op === 'and' || op === 'or') hint = tmsg('script:hint.andOrBool');
    else if (l === 'string' || r === 'string' || l === 'bool' || r === 'bool') hint = '';
    return this.fail(span, tmsg('script:check.binaryOperand', { op, l, r, hint }), 'SCRIPT_TYPE_MISMATCH');
  }

  // ---- 호출 ----

  private callTy(e: Extract<Expr, { kind: 'Call' }>): ExprTy {
    const name = e.name;
    if (isBuiltin(name)) {
      const sig = BUILTINS[name];
      if (sig.special === 'range') {
        this.fail(e.span, tmsg('script:check.rangeNotValue'), 'SCRIPT_RANGE_CONTEXT');
      }
      e.callee = 'builtin';
      return this.builtinCall(e, sig);
    }
    const f = this.funcs.get(name);
    if (f) {
      e.callee = 'user';
      return this.userCall(e, f);
    }
    if (this.allFuncNames.has(name)) {
      this.fail(e.nameSpan,
        tmsg('script:check.fnDefinedBeforeCall', { name }), 'SCRIPT_FUNC_ORDER');
    }
    if (this.scope.vars.has(name) || this.consts.has(name)) this.fail(e.nameSpan, tmsg('script:check.notAFunction', { name }), 'SCRIPT_NAME_UNDEFINED');
    return this.fail(e.nameSpan, tmsg('script:check.undefinedFunction', { name }), 'SCRIPT_NAME_UNDEFINED');
  }

  private builtinCall(e: Extract<Expr, { kind: 'Call' }>, sig: BuiltinSig): ExprTy {
    const params = sig.params;
    const values: (Expr | undefined)[] = new Array(params.length).fill(undefined);
    let next = 0;
    for (const a of e.args) {
      if (!a.name) {
        if (next >= params.length) {
          this.fail(a.value.span, tmsg('script:check.maxArgs', { name: sig.name, length: params.length }), 'SCRIPT_CALL_ARGS');
        }
        values[next++] = a.value;
      } else {
        const i = params.findIndex((p) => p.name === a.name);
        if (i < 0) this.fail(a.value.span, tmsg('script:check.noSuchArg', { name: sig.name, name2: a.name }), 'SCRIPT_CALL_ARGS');
        if (values[i]) this.fail(a.value.span, tmsg('script:check.argTwice', { name: a.name }), 'SCRIPT_CALL_ARGS');
        values[i] = a.value;
      }
    }
    const ordered: Expr[] = [];
    params.forEach((p, i) => {
      let v = values[i];
      if (!v) {
        if (p.default === undefined) {
          this.fail(e.span, tmsg('script:check.argRequired', { name: sig.name, name2: p.name }), 'SCRIPT_CALL_ARGS');
        }
        v = this.defaultLiteral(p, e.span);
      } else {
        const t = this.valueTy(v);
        const ok = p.type === 'sized' ? t === 'bytes' || !!elemOf(t) : t === p.type;
        if (!ok) {
          const want = p.type === 'sized' ? tmsg('script:word.bytesOrList') : p.type;
          this.fail(v.span, tmsg('script:check.argType', { name: sig.name, name2: p.name, want, t }), 'SCRIPT_TYPE_MISMATCH');
        }
      }
      ordered.push(v);
    });
    e.args = ordered.map((value) => ({ value }));
    return sig.ret;
  }

  private defaultLiteral(p: BuiltinParam, span: Span): Expr {
    const d = p.default;
    if (typeof d === 'bigint') return { kind: 'IntLit', value: d, span, ty: 'int' };
    if (typeof d === 'boolean') return { kind: 'BoolLit', value: d, span, ty: 'bool' };
    return { kind: 'StrLit', value: d as string, span, ty: 'string' };
  }

  private userCall(e: Extract<Expr, { kind: 'Call' }>, f: FuncSig): ExprTy {
    for (const a of e.args) {
      if (a.name) this.fail(a.value.span, tmsg('script:check.noKeywordArgs'), 'SCRIPT_CALL_ARGS');
    }
    if (e.args.length !== f.params.length) {
      this.fail(e.span, tmsg('script:check.argCount', { name: f.name, length: f.params.length, length2: e.args.length }), 'SCRIPT_CALL_ARGS');
    }
    e.args.forEach((a, i) => {
      const t = this.valueTy(a.value);
      if (t !== f.params[i].type) {
        this.fail(a.value.span, tmsg('script:check.userArgType', { name: f.name, param: f.params[i].name, want: f.params[i].type, t }), 'SCRIPT_TYPE_MISMATCH');
      }
    });
    return f.ret ?? 'void';
  }

  /** for의 `range(...)` 반복 대상 검사. 반복 변수 타입(int)을 돌려준다. */
  private checkRange(c: Extract<Expr, { kind: 'Call' }>): Ty {
    if (c.args.length < 1 || c.args.length > 3 || c.args.some((a) => a.name)) {
      this.fail(c.span, tmsg('script:check.rangeArgs'), 'SCRIPT_CALL_ARGS');
    }
    c.args.forEach((a) => this.expectInt(a.value, tmsg('script:word.rangeArgument')));
    c.callee = 'builtin';
    c.ty = 'range';
    return 'int';
  }
}

