/**
 * 내장 스크립트 AST (builtin-script.md §3.4).
 * 모든 노드가 소스 위치(span)를 가진다. 의미 검사는 하지 않는다.
 */

import type { Span } from './diagnostics';

export type PrimName = 'int' | 'bool' | 'bytes' | 'string';

/** 값의 타입. 목록은 list[T](T는 prim)이다. */
export type Ty = PrimName | `list[${PrimName}]`;

/** 식의 정적 타입. tuple은 풀어쓰기 대입의 우변, void는 값이 없는 호출, range는 for 전용이다. */
export type ExprTy = Ty | { tuple: Ty[] } | 'void' | 'range';

export type TypeAnn =
  | { kind: 'prim'; name: PrimName; span: Span }
  | { kind: 'list'; elem: PrimName; span: Span };

export type RetType =
  | { kind: 'single'; type: TypeAnn; span: Span }
  | { kind: 'tuple'; types: TypeAnn[]; span: Span };

export type BinOp =
  | 'or' | 'and'
  | '==' | '!=' | '<' | '<=' | '>' | '>='
  | '|' | '^' | '&' | '<<' | '>>'
  | '+' | '-' | '*' | '//' | '%';

export type UnaryOp = '-' | '~' | 'not';

/** 복합 대입의 연산자(`+=`이면 '+') */
export type AugOp = '+' | '-' | '*' | '//' | '%' | '&' | '|' | '^' | '<<' | '>>';

export type BytesForm = 'hex' | 'bin' | 'text';

export interface CallArg {
  /** 키워드 인자 이름(내장 함수만 허용, 검사는 T05) */
  name?: string;
  value: Expr;
}

/** 첨자 안쪽의 세 형태 (§4.7) */
export type IndexSpec =
  | { kind: 'item'; index: Expr; span: Span }
  /** `[a:c]`, `[:c]`, `[a:]`, `[:]` — 끝 위치 방식 */
  | { kind: 'slice'; start?: Expr; stop?: Expr; span: Span }
  /** `[o, n]`, `[o,]` — 오프셋과 길이 방식. `length`가 없으면 끝까지 */
  | { kind: 'offsetLength'; offset: Expr; length?: Expr; span: Span };

/** f-string 서식 지정 `[[채움]정렬][부호][#][0][너비][형식]` (§4.9) */
export interface FormatSpec {
  fill?: string;
  align?: '<' | '>' | '^';
  sign?: '+' | '-' | ' ';
  alt: boolean;
  zero: boolean;
  width?: number;
  type?: string;
}

/** f-string의 조각: 글자 그대로의 텍스트이거나 `{식:서식}` 필드 */
export type FPart = string | { expr: Expr; spec: FormatSpec };

/** 검사기(T05)가 `ty`(확정 타입)를 채운다. */
export type Expr = ExprNode & { ty?: ExprTy };

type ExprNode =
  | { kind: 'Name'; name: string; ref?: 'var' | 'const'; span: Span }
  | { kind: 'IntLit'; value: bigint; span: Span }
  | { kind: 'BoolLit'; value: boolean; span: Span }
  | { kind: 'StrLit'; value: string; span: Span }
  | { kind: 'FString'; parts: FPart[]; span: Span }
  | { kind: 'BytesLit'; value: Uint8Array; form: BytesForm; span: Span }
  | { kind: 'ListLit'; elements: Expr[]; span: Span }
  | { kind: 'Unary'; op: UnaryOp; operand: Expr; span: Span }
  | { kind: 'Binary'; op: BinOp; left: Expr; right: Expr; span: Span }
  | { kind: 'Cond'; test: Expr; then: Expr; otherwise: Expr; span: Span }
  | { kind: 'Call'; name: string; nameSpan: Span; args: CallArg[]; callee?: 'builtin' | 'user'; span: Span }
  | { kind: 'Index'; target: Expr; index: IndexSpec; span: Span }
  /** return과 풀어쓰기 대입의 우변에서만 나온다 */
  | { kind: 'Tuple'; elements: Expr[]; span: Span };

export interface NameRef {
  name: string;
  span: Span;
}

export type Stmt =
  | { kind: 'Assign'; target: NameRef; value: Expr; span: Span }
  | { kind: 'AnnAssign'; target: NameRef; type: TypeAnn; value: Expr; span: Span }
  | { kind: 'AugAssign'; target: NameRef; op: AugOp; value: Expr; span: Span }
  | { kind: 'SubAssign'; target: NameRef; index: IndexSpec; value: Expr; span: Span }
  | { kind: 'Unpack'; targets: NameRef[]; value: Expr; span: Span }
  | { kind: 'If'; branches: { test: Expr; body: Stmt[]; span: Span }[]; orelse?: Stmt[]; span: Span }
  | { kind: 'For'; target: NameRef; iter: Expr; body: Stmt[]; span: Span }
  | { kind: 'Return'; value?: Expr; span: Span }
  | { kind: 'Break'; span: Span }
  | { kind: 'Continue'; span: Span }
  | { kind: 'Pass'; span: Span }
  | { kind: 'ExprStmt'; call: Extract<Expr, { kind: 'Call' }>; span: Span };

export interface Param {
  name: string;
  type: TypeAnn;
  span: Span;
}

export interface FuncDef {
  kind: 'FuncDef';
  name: string;
  nameSpan: Span;
  params: Param[];
  ret?: RetType;
  body: Stmt[];
  span: Span;
}

export type TopItem = Stmt | FuncDef;

export interface Program {
  body: TopItem[];
}
