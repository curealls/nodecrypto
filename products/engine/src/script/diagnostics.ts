/**
 * 내장 스크립트 진단 형식 (builtin-script.md §6.1).
 * 줄·열은 1부터 시작하고, endLine/endColumn은 끝 위치의 다음(배타)이다.
 */

import { Msg, formatMsg } from '../messages';

export interface Span {
  line: number;
  column: number;
  endLine: number;
  endColumn: number;
}

export interface Diagnostic extends Span {
  /** English default text (formatMsg of `msg`); the UI translates `msg` (i18n.md §6.3) */
  message: string;
  msg: Msg;
  /** 식별 코드(예: SCRIPT_SYNTAX_HEX_ODD_DIGITS) */
  code?: string;
  /** 포트 표의 행에도 표시할 진단이면 그 포트 (ui-canvas-spec.md §14.4) */
  port?: { direction: 'input' | 'output'; id: string };
}

export function makeDiagnostic(span: Span, msg: Msg, code?: string): Diagnostic {
  return { line: span.line, column: span.column, endLine: span.endLine, endColumn: span.endColumn, message: formatMsg(msg), msg, code };
}

export function joinSpan(a: Span, b: Span): Span {
  return { line: a.line, column: a.column, endLine: b.endLine, endColumn: b.endColumn };
}
