/**
 * 내장 스크립트 파서 진입점 (builtin-script.md §3).
 * UI(React)나 DOM에 의존하지 않는다.
 */

import type { Program } from './ast';
import { Diagnostic, makeDiagnostic } from './diagnostics';
import { lex } from './lexer';
import { MAX_SOURCE } from './limits';
import { check } from './checker';
import type { CheckResult, PortList } from './checker';
import { parseTokens } from './parser';
import { tmsg } from '../messages';

export type { Diagnostic, Span } from './diagnostics';
export type * from './ast';

export { MAX_SOURCE };

export interface ParseResult {
  /** 진단이 없을 때만 있다 */
  program?: Program;
  diagnostics: Diagnostic[];
}

export function parse(source: string): ParseResult {
  const size = new TextEncoder().encode(source).length;
  if (size > MAX_SOURCE) {
    return {
      diagnostics: [makeDiagnostic(
        { line: 1, column: 1, endLine: 1, endColumn: 1 },
        tmsg('script:syntax.sourceTooLarge', { size, MAX_SOURCE }),
        'SCRIPT_SYNTAX_SOURCE_TOO_LARGE',
      )],
    };
  }
  const lexed = lex(source);
  const parsed = parseTokens(lexed.tokens);
  const diagnostics = [...lexed.diagnostics, ...parsed.diagnostics].sort(
    (a, b) => a.line - b.line || a.column - b.column,
  );
  return diagnostics.length ? { diagnostics } : { program: parsed.program, diagnostics };
}

export { check, portIdFromName, portIdProblem } from './checker';
export type { CheckResult, FuncSig, PortList, PortSpec, TypedProgram } from './checker';
export { runScript } from './evaluator';
export type { RunOptions, ScriptValue } from './evaluator';

/** 소스를 파싱하고 타입 검사한다. 진단이 없을 때만 typed가 있고, 그때만 runScript로 실행할 수 있다. */
export function compile(source: string, ports: PortList): CheckResult {
  const parsed = parse(source);
  if (!parsed.program) return { diagnostics: parsed.diagnostics };
  return check(parsed.program, ports);
}
