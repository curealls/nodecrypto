/**
 * 내장 스크립트 파서 (builtin-script.md §3.4).
 * 재귀 하강. 문장 하나에서 오류가 나면 그 줄(과 딸린 블록)을 건너뛰고 다음 문장부터 이어서 파싱한다.
 */

import type {
  AugOp, BinOp, CallArg, Expr, FuncDef, IndexSpec, NameRef, Param, PrimName, Program,
  RetType, Stmt, TopItem, TypeAnn, BytesForm, FPart,
} from './ast';
import { Diagnostic, Span, joinSpan, makeDiagnostic } from './diagnostics';
import { lex } from './lexer';
import type { RawFPart, Token } from './lexer';
import { parseFormatSpec } from './format';
import { Msg, tmsg } from '../messages';

class ParseError {
  /** null이면 렉서가 이미 보고한 오류라 조용히 건너뛴다 */
  constructor(public diag: Diagnostic | null) {}
}

const PRIMS: PrimName[] = ['int', 'bool', 'bytes', 'string'];
const AUG_OPS: Record<string, AugOp> = {
  '+=': '+', '-=': '-', '*=': '*', '//=': '//', '%=': '%', '&=': '&', '|=': '|', '^=': '^', '<<=': '<<', '>>=': '>>',
};
const CMP_OPS = ['==', '!=', '<', '<=', '>', '>='];
const BYTES_KIND: Record<string, BytesForm> = { HEX: 'hex', BIN: 'bin', TEXT: 'text' };
const BYTES_PREFIX: Record<string, string> = { HEX: 'h', BIN: 'b', TEXT: 's' };

type CallExpr = Extract<Expr, { kind: 'Call' }>;

export function parseTokens(tokens: Token[]): { program: Program; diagnostics: Diagnostic[] } {
  return new Parser(tokens).parseProgram();
}

class Parser {
  private pos = 0;
  private diags: Diagnostic[] = [];
  /** 괄호·대괄호 안 깊이. 0보다 클 때만 같은 종류 리터럴을 이어 붙인다. */
  private depth = 0;
  /** 직전 문장이 오류였는지(짝 없는 elif/else 연쇄 오류를 막는다) */
  private lastErrored = false;

  constructor(private tokens: Token[]) {}

  // ---- 토큰 접근 ----

  private get tok(): Token {
    return this.tokens[this.pos];
  }

  private peekAt(n: number): Token {
    return this.tokens[Math.min(this.pos + n, this.tokens.length - 1)];
  }

  private next(): Token {
    const t = this.tokens[this.pos];
    if (t.kind !== 'EOF') this.pos++;
    return t;
  }

  private isOp(text: string, t: Token = this.tok): boolean {
    return t.kind === 'OP' && t.text === text;
  }

  private isKw(text: string, t: Token = this.tok): boolean {
    return t.kind === 'KW' && t.text === text;
  }

  private acceptOp(text: string): Token | null {
    return this.isOp(text) ? this.next() : null;
  }

  // ---- 오류 ----

  private fail(span: Span, message: Msg, code: string): never {
    throw new ParseError(makeDiagnostic(span, message, code));
  }

  private describe(t: Token): Msg | string {
    switch (t.kind) {
      case 'NEWLINE': return tmsg('script:token.newline');
      case 'INDENT': return tmsg('script:token.indent');
      case 'DEDENT': return tmsg('script:token.dedent');
      case 'EOF': return tmsg('script:token.eof');
      case 'STRING': case 'FSTR': return tmsg('script:token.string');
      case 'INT': return tmsg('script:token.number', { text: t.text });
      case 'HEX': case 'BIN': case 'TEXT': return tmsg('script:token.bytesLiteral');
      default: return `'${t.text}'`;
    }
  }

  /** 예기치 않은 토큰에 대한 오류. 문법 밖의 자주 쓰는 구문은 안내 문구를 붙인다. */
  private unexpected(t: Token, expected?: Msg | string): never {
    if (t.kind === 'UNSUPPORTED') throw new ParseError(null);
    const prev = this.tokens[this.pos - 1];
    if (t.kind === 'STRING' && prev && prev.kind === 'NAME' && ['h', 'b', 's', 'f'].includes(prev.text)
        && prev.span.endLine === t.span.line && prev.span.endColumn < t.span.column) {
      this.fail(joinSpan(prev.span, t.span),
        tmsg('script:syntax.literalPrefixSpace', { text: prev.text }), 'SCRIPT_SYNTAX_LITERAL_PREFIX_SPACE');
    }
    if (t.kind === 'OP') {
      if (t.text === '.') {
        this.fail(t.span, tmsg('script:syntax.attribute'), 'SCRIPT_SYNTAX_ATTRIBUTE');
      }
      if (t.text === '**' || t.text === '**=') {
        this.fail(t.span, tmsg('script:syntax.noPowerOperator', { text: t.text }), 'SCRIPT_SYNTAX_UNSUPPORTED_OPERATOR');
      }
      if (t.text === '/' || t.text === '/=') {
        this.fail(t.span, tmsg('script:syntax.noDivOperator', { text: t.text }), 'SCRIPT_SYNTAX_UNSUPPORTED_OPERATOR');
      }
    }
    const want = expected ? tmsg('script:syntax.expectedPrefix', { expected }) : '';
    this.fail(t.span, tmsg('script:syntax.unexpected', { want, found: this.describe(t) }), 'SCRIPT_SYNTAX_UNEXPECTED_TOKEN');
  }

  private expectOp(text: string, what?: Msg | string): Token {
    if (!this.isOp(text)) this.unexpected(this.tok, what ?? `'${text}'`);
    return this.next();
  }

  private expectName(what: Msg | string): Token {
    if (this.tok.kind !== 'NAME') this.unexpected(this.tok, what);
    return this.next();
  }

  private expectEnd() {
    if (this.tok.kind === 'NEWLINE') { this.next(); return; }
    if (this.tok.kind === 'EOF') return;
    this.unexpected(this.tok, tmsg('script:token.newline'));
  }

  // ---- 오류 복구 ----

  /** start: 실패한 문장이 시작된 토큰 위치. 진행이 없었으면 그 줄을 건너뛴다. */
  private recover(start: number) {
    this.depth = 0;
    if (this.tok.kind === 'INDENT') {
      this.skipBlock();
    } else {
      const prev = this.tokens[this.pos - 1];
      const atLineStart = !prev || prev.kind === 'NEWLINE' || prev.kind === 'INDENT' || prev.kind === 'DEDENT';
      if (!atLineStart || this.pos === start) {
        while (this.tok.kind !== 'NEWLINE' && this.tok.kind !== 'EOF') this.pos++;
        if (this.tok.kind === 'NEWLINE') this.pos++;
      }
      if (this.peekAt(0).kind === 'INDENT') this.skipBlock();
    }
    if (this.pos === start && this.tok.kind !== 'EOF') this.pos++; // 진행 보장
  }

  private skipBlock() {
    let level = 0;
    do {
      if (this.tok.kind === 'INDENT') level++;
      else if (this.tok.kind === 'DEDENT') level--;
      this.pos++;
    } while (level > 0 && this.tok.kind !== 'EOF');
  }

  // ---- 프로그램, 블록 ----

  parseProgram(): { program: Program; diagnostics: Diagnostic[] } {
    const body: TopItem[] = [];
    while (this.tok.kind !== 'EOF') {
      if (this.tok.kind === 'DEDENT') { this.next(); continue; }
      const item = this.guarded(() => this.parseStatement(true));
      if (item) body.push(item);
    }
    return { program: { body }, diagnostics: this.diags };
  }

  private guarded<T>(fn: () => T): T | null {
    const start = this.pos;
    try {
      const r = fn();
      this.lastErrored = false;
      return r;
    } catch (e) {
      if (!(e instanceof ParseError)) throw e;
      if (e.diag) this.diags.push(e.diag);
      this.recover(start);
      this.lastErrored = true;
      return null;
    }
  }

  private parseBlock(): Stmt[] {
    this.expectOp(':');
    if (this.tok.kind !== 'NEWLINE') {
      this.fail(this.tok.span, tmsg('script:syntax.blockNextLine'), 'SCRIPT_SYNTAX_BLOCK_SAME_LINE');
    }
    this.next();
    if (this.peekAt(0).kind !== 'INDENT') {
      this.fail(this.tok.span, tmsg('script:syntax.indentedBlockExpected'), 'SCRIPT_SYNTAX_EXPECTED_INDENT');
    }
    this.next();
    const body: Stmt[] = [];
    while (this.peekAt(0).kind !== 'DEDENT' && this.peekAt(0).kind !== 'EOF') {
      const s = this.guarded(() => this.parseStatement(false) as Stmt);
      if (s) body.push(s);
    }
    if (this.peekAt(0).kind === 'DEDENT') this.next();
    return body;
  }

  // ---- 문장 ----

  private parseStatement(top: boolean): TopItem {
    const t = this.tok;
    if (t.kind === 'INDENT') this.fail(t.span, tmsg('script:syntax.unexpectedIndent'), 'SCRIPT_SYNTAX_UNEXPECTED_INDENT');
    if (t.kind === 'UNSUPPORTED') throw new ParseError(null);
    if (t.kind === 'KW') {
      switch (t.text) {
        case 'def':
          if (!top) this.fail(t.span, tmsg('script:syntax.defTopLevelOnly'), 'SCRIPT_SYNTAX_NESTED_DEF');
          return this.parseFuncDef();
        case 'if': return this.parseIf();
        case 'for': return this.parseFor();
        case 'return': return this.parseReturn();
        case 'break': case 'continue': case 'pass': {
          this.next();
          this.expectEnd();
          const kind = t.text === 'break' ? 'Break' : t.text === 'continue' ? 'Continue' : 'Pass';
          return { kind, span: t.span };
        }
        case 'elif': case 'else':
          if (this.lastErrored) throw new ParseError(null);
          this.fail(t.span, tmsg('script:syntax.orphanElse', { text: t.text }), 'SCRIPT_SYNTAX_DANGLING_ELSE');
      }
    }
    if (t.kind === 'NAME') {
      const n = this.peekAt(1);
      if (this.isOp(':', n)) return this.parseAnnAssign();
      if (this.isOp('=', n)) return this.parseAssign();
      if (n.kind === 'OP' && n.text in AUG_OPS) return this.parseAugAssign();
      if (this.isOp(',', n)) return this.parseUnpack();
      if (this.isOp('[', n)) return this.parseSubscriptStatement();
    }
    return this.parseExprStatement();
  }

  private nameRef(t: Token): NameRef {
    return { name: t.text, span: t.span };
  }

  private parseAssign(): Stmt {
    const name = this.next();
    this.next(); // '='
    const value = this.parseExpr();
    this.expectEnd();
    return { kind: 'Assign', target: this.nameRef(name), value, span: joinSpan(name.span, value.span) };
  }

  private parseAnnAssign(): Stmt {
    const name = this.next();
    this.next(); // ':'
    const type = this.parseType();
    if (!this.isOp('=')) {
      this.fail(this.tok.span, tmsg('script:syntax.annotationNeedsValue'), 'SCRIPT_SYNTAX_ANNOTATION_NO_VALUE');
    }
    this.next();
    const value = this.parseExpr();
    this.expectEnd();
    return { kind: 'AnnAssign', target: this.nameRef(name), type, value, span: joinSpan(name.span, value.span) };
  }

  private parseAugAssign(): Stmt {
    const name = this.next();
    const op = AUG_OPS[this.next().text];
    const value = this.parseExpr();
    this.expectEnd();
    return { kind: 'AugAssign', target: this.nameRef(name), op, value, span: joinSpan(name.span, value.span) };
  }

  private parseUnpack(): Stmt {
    const targets: NameRef[] = [this.nameRef(this.next())];
    while (this.acceptOp(',')) targets.push(this.nameRef(this.expectName(tmsg('script:token.name'))));
    this.expectOp('=');
    const value = this.parseTupleOrExpr();
    if (value.kind !== 'Call' && value.kind !== 'Tuple') {
      this.fail(value.span, tmsg('script:syntax.unpackRhs'), 'SCRIPT_SYNTAX_UNPACK_RHS');
    }
    this.expectEnd();
    return { kind: 'Unpack', targets, value, span: joinSpan(targets[0].span, value.span) };
  }

  /** `NAME [` 로 시작하는 문장: 첨자 대입이어야 한다. */
  private parseSubscriptStatement(): Stmt {
    const name = this.next();
    this.next(); // '['
    this.depth++;
    const index = this.parseIndex();
    this.depth--;
    if (!this.isOp('=')) {
      this.fail(this.tok.span, tmsg('script:syntax.exprStatementCallIndex'), 'SCRIPT_SYNTAX_EXPR_STATEMENT');
    }
    this.next();
    const value = this.parseExpr();
    this.expectEnd();
    return { kind: 'SubAssign', target: this.nameRef(name), index, value, span: joinSpan(name.span, value.span) };
  }

  private parseExprStatement(): Stmt {
    const e = this.parseExpr();
    if (e.kind !== 'Call') {
      if (this.tok.kind === 'OP' && ['.', '**', '**=', '/', '/='].includes(this.tok.text)) this.unexpected(this.tok);
      this.fail(e.span, tmsg('script:syntax.exprStatementCall'), 'SCRIPT_SYNTAX_EXPR_STATEMENT');
    }
    this.expectEnd();
    return { kind: 'ExprStmt', call: e, span: e.span };
  }

  private parseReturn(): Stmt {
    const kw = this.next();
    if (this.tok.kind === 'NEWLINE' || this.tok.kind === 'EOF') {
      this.expectEnd();
      return { kind: 'Return', span: kw.span };
    }
    const value = this.parseTupleOrExpr();
    this.expectEnd();
    return { kind: 'Return', value, span: joinSpan(kw.span, value.span) };
  }

  private parseIf(): Stmt {
    const kw = this.next();
    const branches: { test: Expr; body: Stmt[]; span: Span }[] = [];
    let test = this.parseExpr();
    let body = this.parseBlock();
    branches.push({ test, body, span: joinSpan(kw.span, test.span) });
    while (this.isKw('elif')) {
      const k = this.next();
      test = this.parseExpr();
      body = this.parseBlock();
      branches.push({ test, body, span: joinSpan(k.span, test.span) });
    }
    let orelse: Stmt[] | undefined;
    if (this.isKw('else')) {
      this.next();
      orelse = this.parseBlock();
    }
    return { kind: 'If', branches, orelse, span: joinSpan(kw.span, branches[0].test.span) };
  }

  private parseFor(): Stmt {
    const kw = this.next();
    const v = this.expectName(tmsg('script:token.loopVar'));
    if (!this.isKw('in')) this.unexpected(this.tok, "'in'");
    this.next();
    const iter = this.parseExpr();
    const body = this.parseBlock();
    return { kind: 'For', target: this.nameRef(v), iter, body, span: joinSpan(kw.span, iter.span) };
  }

  // ---- 함수, 타입 ----

  private parseFuncDef(): FuncDef {
    const kw = this.next();
    const name = this.expectName(tmsg('script:token.funcName'));
    this.expectOp('(');
    this.depth++;
    const params: Param[] = [];
    if (!this.isOp(')')) {
      do {
        const p = this.expectName(tmsg('script:token.paramName'));
        if (!this.isOp(':')) {
          this.fail(this.tok.span, tmsg('script:syntax.paramNeedsType', { text: p.text }), 'SCRIPT_SYNTAX_PARAM_TYPE');
        }
        this.next();
        const type = this.parseType();
        if (this.isOp('=')) {
          this.fail(this.tok.span, tmsg('script:syntax.paramDefault'), 'SCRIPT_SYNTAX_PARAM_DEFAULT');
        }
        params.push({ name: p.text, type, span: joinSpan(p.span, type.span) });
      } while (this.acceptOp(','));
    }
    this.expectOp(')');
    this.depth--;
    let ret: RetType | undefined;
    if (this.acceptOp('->')) ret = this.parseRetType();
    const body = this.parseBlock();
    return { kind: 'FuncDef', name: name.text, nameSpan: name.span, params, ret, body, span: joinSpan(kw.span, name.span) };
  }

  private parseType(): TypeAnn {
    const t = this.expectName(tmsg('script:token.type'));
    if (t.text === 'list') {
      this.expectOp('[');
      const e = this.expectName(tmsg('script:token.listElementType'));
      if (e.text === 'list') {
        this.fail(e.span, tmsg('script:syntax.nestedList'), 'SCRIPT_SYNTAX_NESTED_LIST');
      }
      if (!PRIMS.includes(e.text as PrimName)) {
        this.fail(e.span, tmsg('script:syntax.unknownScalarType', { text: e.text }), 'SCRIPT_SYNTAX_UNKNOWN_TYPE');
      }
      const close = this.expectOp(']');
      return { kind: 'list', elem: e.text as PrimName, span: joinSpan(t.span, close.span) };
    }
    if (!PRIMS.includes(t.text as PrimName)) {
      this.fail(t.span, tmsg('script:syntax.unknownType', { text: t.text }), 'SCRIPT_SYNTAX_UNKNOWN_TYPE');
    }
    return { kind: 'prim', name: t.text as PrimName, span: t.span };
  }

  private parseRetType(): RetType {
    if (this.tok.kind === 'NAME' && this.tok.text === 'tuple') {
      const kw = this.next();
      this.expectOp('[');
      const types = [this.parseType()];
      while (this.acceptOp(',')) types.push(this.parseType());
      const close = this.expectOp(']');
      if (types.length < 2) {
        this.fail(joinSpan(kw.span, close.span), tmsg('script:syntax.tupleArity'), 'SCRIPT_SYNTAX_TUPLE_ARITY');
      }
      return { kind: 'tuple', types, span: joinSpan(kw.span, close.span) };
    }
    const type = this.parseType();
    return { kind: 'single', type, span: type.span };
  }

  // ---- 식 ----

  /** return과 풀어쓰기 대입의 우변: `expr`, `expr, expr`, `(expr, expr)` */
  private parseTupleOrExpr(): Expr {
    if (this.isOp('(') && this.isParenTuple()) {
      const open = this.next();
      this.depth++;
      const elements = [this.parseExpr()];
      while (this.acceptOp(',')) elements.push(this.parseExpr());
      const close = this.expectOp(')');
      this.depth--;
      return { kind: 'Tuple', elements, span: joinSpan(open.span, close.span) };
    }
    const first = this.parseExpr();
    if (!this.isOp(',')) return first;
    const elements = [first];
    while (this.acceptOp(',')) elements.push(this.parseExpr());
    return { kind: 'Tuple', elements, span: joinSpan(first.span, elements[elements.length - 1].span) };
  }

  /** 현재 '(' 가 줄 전체를 차지하는, 최상위에 쉼표가 있는 괄호인지 본다. */
  private isParenTuple(): boolean {
    let level = 0;
    let comma = false;
    for (let i = this.pos; i < this.tokens.length; i++) {
      const t = this.tokens[i];
      if (t.kind === 'OP') {
        if (t.text === '(' || t.text === '[') level++;
        else if (t.text === ')' || t.text === ']') {
          level--;
          if (level === 0) {
            const after = this.tokens[i + 1];
            return comma && !!after && (after.kind === 'NEWLINE' || after.kind === 'EOF');
          }
        } else if (t.text === ',' && level === 1) comma = true;
      }
      if (t.kind === 'NEWLINE' || t.kind === 'EOF') return false;
    }
    return false;
  }

  private parseExpr(): Expr {
    return this.parseCond();
  }

  private parseCond(): Expr {
    const body = this.parseOr();
    if (!this.isKw('if')) return body;
    this.next();
    const test = this.parseOr();
    if (!this.isKw('else')) this.unexpected(this.tok, "'else'");
    this.next();
    const otherwise = this.parseCond();
    return { kind: 'Cond', test, then: body, otherwise, span: joinSpan(body.span, otherwise.span) };
  }

  private parseOr(): Expr {
    let left = this.parseAnd();
    while (this.isKw('or')) {
      this.next();
      const right = this.parseAnd();
      left = { kind: 'Binary', op: 'or', left, right, span: joinSpan(left.span, right.span) };
    }
    return left;
  }

  private parseAnd(): Expr {
    let left = this.parseNot();
    while (this.isKw('and')) {
      this.next();
      const right = this.parseNot();
      left = { kind: 'Binary', op: 'and', left, right, span: joinSpan(left.span, right.span) };
    }
    return left;
  }

  private parseNot(): Expr {
    if (this.isKw('not')) {
      const kw = this.next();
      const operand = this.parseNot();
      return { kind: 'Unary', op: 'not', operand, span: joinSpan(kw.span, operand.span) };
    }
    return this.parseComparison();
  }

  private parseComparison(): Expr {
    const left = this.parseBinaryLevel(0);
    if (this.tok.kind === 'OP' && CMP_OPS.includes(this.tok.text)) {
      const op = this.next().text as BinOp;
      const right = this.parseBinaryLevel(0);
      if (this.tok.kind === 'OP' && CMP_OPS.includes(this.tok.text)) {
        this.fail(this.tok.span, tmsg('script:syntax.chainedComparison'), 'SCRIPT_SYNTAX_CHAINED_COMPARISON');
      }
      return { kind: 'Binary', op, left, right, span: joinSpan(left.span, right.span) };
    }
    return left;
  }

  /** 낮은 우선순위부터: | ^ & shift arith term */
  private static LEVELS: string[][] = [['|'], ['^'], ['&'], ['<<', '>>'], ['+', '-'], ['*', '//', '%']];

  private parseBinaryLevel(level: number): Expr {
    if (level >= Parser.LEVELS.length) return this.parseUnary();
    let left = this.parseBinaryLevel(level + 1);
    while (this.tok.kind === 'OP' && Parser.LEVELS[level].includes(this.tok.text)) {
      const op = this.next().text as BinOp;
      const right = this.parseBinaryLevel(level + 1);
      left = { kind: 'Binary', op, left, right, span: joinSpan(left.span, right.span) };
    }
    return left;
  }

  private parseUnary(): Expr {
    if (this.isOp('-') || this.isOp('~')) {
      const op = this.next();
      const operand = this.parseUnary();
      return { kind: 'Unary', op: op.text as '-' | '~', operand, span: joinSpan(op.span, operand.span) };
    }
    return this.parsePostfix();
  }

  private parsePostfix(): Expr {
    let e = this.parseAtom();
    for (;;) {
      if (this.isOp('[')) {
        this.next();
        this.depth++;
        const index = this.parseIndex();
        this.depth--;
        e = { kind: 'Index', target: e, index, span: joinSpan(e.span, index.span) };
      } else if (this.isOp('(')) {
        if (e.kind !== 'Name') {
          this.fail(this.tok.span, tmsg('script:syntax.callByNameOnly'), 'SCRIPT_SYNTAX_CALL_TARGET');
        }
        e = this.parseCallArgs(e);
      } else break;
    }
    return e;
  }

  private parseCallArgs(callee: Extract<Expr, { kind: 'Name' }>): CallExpr {
    this.next(); // '('
    this.depth++;
    const args: CallArg[] = [];
    let sawKeyword = false;
    if (!this.isOp(')')) {
      do {
        if (this.isOp(')')) break; // 마지막 쉼표 허용
        if (this.tok.kind === 'NAME' && this.isOp('=', this.peekAt(1))) {
          const name = this.next();
          this.next();
          args.push({ name: name.text, value: this.parseExpr() });
          sawKeyword = true;
        } else {
          const v = this.parseExpr();
          if (sawKeyword) {
            this.fail(v.span, tmsg('script:syntax.positionalAfterKeyword'), 'SCRIPT_SYNTAX_POSITIONAL_AFTER_KEYWORD');
          }
          args.push({ value: v });
        }
      } while (this.acceptOp(','));
    }
    const close = this.expectOp(')');
    this.depth--;
    return { kind: 'Call', name: callee.name, nameSpan: callee.span, args, span: joinSpan(callee.span, close.span) };
  }

  /** '[' 다음부터 ']' 까지(']' 포함)를 읽는다. */
  private parseIndex(): IndexSpec {
    const open = this.tokens[this.pos - 1];
    let spec: IndexSpec;
    if (this.isOp(':')) {
      this.next();
      const stop = this.isOp(']') ? undefined : this.parseExpr();
      spec = { kind: 'slice', stop, span: open.span };
    } else {
      const first = this.parseExpr();
      if (this.isOp(':')) {
        this.next();
        const stop = this.isOp(']') ? undefined : this.parseExpr();
        spec = { kind: 'slice', start: first, stop, span: open.span };
      } else if (this.isOp(',')) {
        this.next();
        const length = this.isOp(']') ? undefined : this.parseExpr();
        spec = { kind: 'offsetLength', offset: first, length, span: open.span };
      } else {
        spec = { kind: 'item', index: first, span: open.span };
      }
    }
    const close = this.expectOp(']');
    spec.span = joinSpan(open.span, close.span);
    return spec;
  }

  private parseAtom(): Expr {
    const t = this.tok;
    switch (t.kind) {
      case 'INT':
        this.next();
        return { kind: 'IntLit', value: t.value as bigint, span: t.span };
      case 'STRING':
        this.next();
        return { kind: 'StrLit', value: t.value as string, span: t.span };
      case 'FSTR':
        this.next();
        return { kind: 'FString', parts: (t.value as RawFPart[]).map((p) => this.fstringPart(p)), span: t.span };
      case 'NAME':
        this.next();
        return { kind: 'Name', name: t.text, span: t.span };
      case 'HEX': case 'BIN': case 'TEXT':
        return this.parseBytesLiteral();
      case 'KW':
        if (t.text === 'True' || t.text === 'False') {
          this.next();
          return { kind: 'BoolLit', value: t.text === 'True', span: t.span };
        }
        break;
      case 'OP':
        if (t.text === '(') return this.parseParen();
        if (t.text === '[') return this.parseListLiteral();
        break;
    }
    return this.unexpected(t, tmsg('script:token.value'));
  }

  /** f-string 필드의 식 소스를 따로 렉싱·파싱한다. 오류 위치는 원래 줄·열로 옮긴다. */
  private fstringPart(p: RawFPart): FPart {
    if (typeof p === 'string') return p;
    const lead = p.src.length - p.src.trimStart().length;
    const col = p.col + lead;
    const move = (d: Diagnostic): Diagnostic => ({
      ...d, line: p.line, endLine: p.line, column: d.column + col - 1, endColumn: d.endColumn + col - 1,
    });
    const sub = lex(p.src.trim());
    const toks = sub.tokens.map((t) => ({
      ...t, span: { line: p.line, endLine: p.line, column: t.span.column + col - 1, endColumn: t.span.endColumn + col - 1 },
    }));
    if (sub.diagnostics.length) {
      this.diags.push(...sub.diagnostics.map(move));
      throw new ParseError(null);
    }
    const inner = new Parser(toks);
    let expr: Expr;
    try {
      expr = inner.parseExpr();
      if (inner.tok.kind !== 'NEWLINE' && inner.tok.kind !== 'EOF') inner.unexpected(inner.tok, tmsg('script:token.closeOrColon'));
    } catch (e) {
      if (e instanceof ParseError && e.diag) this.diags.push(e.diag);
      throw new ParseError(null);
    }
    const spec = parseFormatSpec(p.spec);
    if ('key' in spec) {
      const sc = { line: p.line, endLine: p.line, column: p.specCol, endColumn: p.specCol + p.spec.length };
      this.fail(sc, spec, 'SCRIPT_FORMAT_INVALID');
    }
    return { expr, spec };
  }

  private parseParen(): Expr {
    this.next();
    this.depth++;
    const e = this.parseExpr();
    if (this.isOp(',')) {
      this.fail(this.tok.span, tmsg('script:syntax.tupleContext'), 'SCRIPT_SYNTAX_TUPLE_CONTEXT');
    }
    this.expectOp(')');
    this.depth--;
    return e;
  }

  private parseListLiteral(): Expr {
    const open = this.next();
    this.depth++;
    const elements: Expr[] = [];
    if (!this.isOp(']')) {
      do {
        if (this.isOp(']')) break;
        elements.push(this.parseExpr());
        if (this.isKw('for')) {
          this.fail(this.tok.span, tmsg('script:syntax.comprehension'), 'SCRIPT_SYNTAX_COMPREHENSION');
        }
      } while (this.acceptOp(','));
    }
    const close = this.expectOp(']');
    this.depth--;
    return { kind: 'ListLit', elements, span: joinSpan(open.span, close.span) };
  }

  /** 같은 종류의 바이트열 리터럴이 괄호 안에서 연달아 오면 하나로 합친다(§3.3.1). */
  private parseBytesLiteral(): Expr {
    const first = this.next();
    let value = first.value as Uint8Array;
    let span = first.span;
    while (this.tok.kind === first.kind && this.depth > 0) {
      const t = this.next();
      const merged = new Uint8Array(value.length + (t.value as Uint8Array).length);
      merged.set(value);
      merged.set(t.value as Uint8Array, value.length);
      value = merged;
      span = joinSpan(span, t.span);
    }
    const t = this.tok;
    if (t.kind === 'HEX' || t.kind === 'BIN' || t.kind === 'TEXT') {
      if (t.kind !== first.kind) {
        this.fail(joinSpan(span, t.span),
          tmsg('script:syntax.literalMixedKind', { first: BYTES_PREFIX[first.kind], second: BYTES_PREFIX[t.kind] }), 'SCRIPT_SYNTAX_LITERAL_MIXED_KIND');
      }
      this.fail(joinSpan(span, t.span),
        tmsg('script:syntax.literalConcatOutsideParen'), 'SCRIPT_SYNTAX_LITERAL_CONCAT_OUTSIDE_PAREN');
    }
    return { kind: 'BytesLit', value, form: BYTES_KIND[first.kind], span };
  }
}
