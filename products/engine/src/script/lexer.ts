/**
 * 내장 스크립트 렉서 (builtin-script.md §3.1 ~ §3.3).
 * 오류를 만나도 멈추지 않고 진단을 모으며 가능한 한 토큰을 이어서 만든다.
 */

import { Diagnostic, Span, makeDiagnostic } from './diagnostics';
import { Msg, tmsg } from '../messages';

export type TokenKind =
  | 'NAME' | 'KW' | 'INT' | 'STRING' | 'FSTR' | 'HEX' | 'BIN' | 'TEXT'
  | 'OP' | 'NEWLINE' | 'INDENT' | 'DEDENT' | 'EOF'
  /** 문법에 없는 키워드. 렉서가 이미 진단을 냈으므로 파서는 조용히 그 줄을 건너뛴다. */
  | 'UNSUPPORTED';

/** f-string 조각: 텍스트, 또는 필드(식 소스와 그 위치, 서식 지정 문자열) */
export type RawFPart = string | { src: string; line: number; col: number; spec: string; specCol: number };

export interface Token {
  kind: TokenKind;
  text: string;
  span: Span;
  /** INT: bigint, STRING: string, FSTR: RawFPart[], HEX/BIN/TEXT: Uint8Array */
  value?: bigint | string | Uint8Array | RawFPart[];
}

export const RESERVED = new Set([
  'def', 'return', 'if', 'elif', 'else', 'for', 'in', 'break', 'continue', 'pass',
  'and', 'or', 'not', 'True', 'False',
]);

/** 문법에 없는 Python 키워드. 만나면 "지원하지 않는 구문" 오류를 낸다. */
export const UNSUPPORTED_HINT: Record<string, Msg> = {
  import: tmsg('script:syntax.hint.import'),
  from: tmsg('script:syntax.hint.from'),
  class: tmsg('script:syntax.hint.class'),
  while: tmsg('script:syntax.hint.while'),
  lambda: tmsg('script:syntax.hint.lambda'),
  try: tmsg('script:syntax.hint.try'),
  except: tmsg('script:syntax.hint.except'),
  finally: tmsg('script:syntax.hint.finally'),
  raise: tmsg('script:syntax.hint.raise'),
  with: tmsg('script:syntax.hint.with'),
  as: tmsg('script:syntax.hint.as'),
  global: tmsg('script:syntax.hint.global'),
  nonlocal: tmsg('script:syntax.hint.nonlocal'),
  del: tmsg('script:syntax.hint.del'),
  assert: tmsg('script:syntax.hint.assert'),
  yield: tmsg('script:syntax.hint.yield'),
  async: tmsg('script:syntax.hint.async'),
  await: tmsg('script:syntax.hint.await'),
  print: tmsg('script:syntax.hint.print'),
  is: tmsg('script:syntax.hint.is'),
};

// 길이가 긴 연산자부터 맞춘다.
const OPERATORS = [
  '//=', '<<=', '>>=', '**=',
  '->', '//', '<<', '>>', '<=', '>=', '==', '!=', '+=', '-=', '*=', '%=', '&=', '|=', '^=', '**', '/=',
  '+', '-', '*', '/', '%', '&', '|', '^', '~', '<', '>', '=', '(', ')', '[', ']', ':', ',', '.',
];

const OPEN: Record<string, string> = { '(': ')', '[': ']' };

const isIdentStart = (c: string) => /[A-Za-z_]/.test(c);
const isIdentChar = (c: string) => /[A-Za-z0-9_]/.test(c);
const isDigit = (c: string) => c >= '0' && c <= '9';
const isHexDigit = (c: string) => /[0-9a-fA-F]/.test(c);

export function lex(source: string): { tokens: Token[]; diagnostics: Diagnostic[] } {
  return new Lexer(source).run();
}

class Lexer {
  private tokens: Token[] = [];
  private diags: Diagnostic[] = [];
  private indents: number[] = [0];
  private brackets: { ch: string; span: Span }[] = [];
  private pendingNewline = false;
  private line = 0;

  constructor(private source: string) {}

  run() {
    const lines = this.source.split(/\r\n|\r|\n/);
    for (let n = 0; n < lines.length; n++) {
      this.line = n + 1;
      this.lexLine(lines[n]);
    }
    const last = lines[lines.length - 1];
    const endSpan = { line: lines.length, column: last.length + 1, endLine: lines.length, endColumn: last.length + 1 };
    for (const b of this.brackets) {
      this.error(b.span, tmsg('script:syntax.unclosedBracket', { ch: b.ch }), 'SCRIPT_SYNTAX_UNCLOSED_BRACKET');
    }
    if (this.pendingNewline) this.push('NEWLINE', '', endSpan);
    while (this.indents.length > 1) {
      this.indents.pop();
      this.push('DEDENT', '', endSpan);
    }
    this.push('EOF', '', endSpan);
    return { tokens: this.tokens, diagnostics: this.diags };
  }

  private span(startCol: number, endCol: number): Span {
    return { line: this.line, column: startCol, endLine: this.line, endColumn: endCol };
  }

  private error(span: Span, message: Msg, code: string) {
    this.diags.push(makeDiagnostic(span, message, code));
  }

  private push(kind: TokenKind, text: string, span: Span, value?: Token['value']) {
    this.tokens.push({ kind, text, span, value });
    if (kind !== 'NEWLINE' && kind !== 'INDENT' && kind !== 'DEDENT' && kind !== 'EOF') this.pendingNewline = true;
  }

  private lexLine(text: string) {
    let i = 0;
    if (this.brackets.length === 0) {
      let spaces = 0;
      let tabCol = 0;
      while (i < text.length && (text[i] === ' ' || text[i] === '\t')) {
        if (text[i] === '\t') {
          if (!tabCol) tabCol = i + 1;
          spaces += 4; // 오류는 낸 뒤, 들여쓰기 수준은 탭을 4칸으로 쳐서 연쇄 오류를 막는다.
        } else spaces++;
        i++;
      }
      if (i >= text.length || text[i] === '#') return; // 빈 줄, 주석만 있는 줄
      if (tabCol) {
        this.error(this.span(tabCol, tabCol + 1), tmsg('script:syntax.tabIndent'), 'SCRIPT_SYNTAX_TAB_INDENT');
      } else if (spaces % 4 !== 0) {
        this.error(this.span(1, spaces + 1), tmsg('script:syntax.indentUnit', { spaces }), 'SCRIPT_SYNTAX_INDENT_UNIT');
      }
      this.applyIndent(Math.floor(spaces / 4), spaces + 1, i + 1);
    }

    while (i < text.length) {
      const c = text[i];
      const col = i + 1;
      if (c === ' ' || c === '\t') { i++; continue; }
      if (c === '#') break;
      if (isDigit(c)) { i = this.lexNumber(text, i); continue; }
      if (isIdentStart(c)) { i = this.lexWord(text, i); continue; }
      if (c === '"') {
        const r = this.readString(text, i);
        this.push('STRING', text.slice(i, r.end), this.span(col, r.end + 1), r.value);
        i = r.end;
        continue;
      }
      if (c === "'") {
        this.error(this.span(col, col + 1), tmsg('script:syntax.singleQuote'), 'SCRIPT_SYNTAX_SINGLE_QUOTE');
        i = text.indexOf("'", i + 1) < 0 ? text.length : text.indexOf("'", i + 1) + 1;
        this.push('STRING', '', this.span(col, i + 1), '');
        continue;
      }
      const op = OPERATORS.find((o) => text.startsWith(o, i));
      if (op) {
        this.lexOperator(op, col);
        i += op.length;
        continue;
      }
      i++;
      this.lexUnknownChar(c, col);
    }

    if (this.brackets.length === 0 && this.pendingNewline) {
      this.push('NEWLINE', '', this.span(text.length + 1, text.length + 1));
      this.pendingNewline = false;
    }
  }

  private applyIndent(level: number, startCol: number, endCol: number) {
    const span = this.span(startCol, endCol);
    const cur = this.indents[this.indents.length - 1];
    if (level > cur) {
      if (level > cur + 1) {
        this.error(span, tmsg('script:syntax.indentTooDeep'), 'SCRIPT_SYNTAX_INDENT_TOO_DEEP');
      }
      this.indents.push(cur + 1);
      this.push('INDENT', '', span);
      this.pendingNewline = false;
    } else {
      while (this.indents[this.indents.length - 1] > level) {
        this.indents.pop();
        this.push('DEDENT', '', span);
      }
      this.pendingNewline = false;
    }
  }

  private lexOperator(op: string, col: number) {
    const span = this.span(col, col + op.length);
    if (op in OPEN) this.brackets.push({ ch: op, span });
    else if (op === ')' || op === ']') {
      const top = this.brackets[this.brackets.length - 1];
      if (!top || OPEN[top.ch] !== op) {
        this.error(span, tmsg('script:syntax.unmatchedBracket', { op }), 'SCRIPT_SYNTAX_UNMATCHED_BRACKET');
      } else this.brackets.pop();
    }
    this.push('OP', op, span);
  }

  private lexUnknownChar(c: string, col: number) {
    const span = this.span(col, col + 1);
    if (c === '{' || c === '}') {
      this.error(span, tmsg('script:syntax.brace'), 'SCRIPT_SYNTAX_BRACE');
    } else if (c === ';') {
      this.error(span, tmsg('script:syntax.semicolon'), 'SCRIPT_SYNTAX_SEMICOLON');
    } else if (c === '\\') {
      this.error(span, tmsg('script:syntax.lineContinuation'), 'SCRIPT_SYNTAX_LINE_CONTINUATION');
    } else {
      this.error(span, tmsg('script:syntax.unknownChar', { c }), 'SCRIPT_SYNTAX_UNKNOWN_CHAR');
    }
  }

  private lexNumber(text: string, start: number): number {
    const rest = text.slice(start);
    const m =
      /^0[xX][0-9a-fA-F]+(?:_[0-9a-fA-F]+)*/.exec(rest) ??
      /^0[bB][01]+(?:_[01]+)*/.exec(rest) ??
      /^[0-9]+(?:_[0-9]+)*/.exec(rest);
    const len = m ? m[0].length : 1;
    let end = start + len;
    const col = start + 1;
    // 숫자 바로 뒤에 소수점이나 영문자가 붙은 경우
    const next = text[end];
    if (next === '.' && end + 1 < text.length && isDigit(text[end + 1])) {
      end++;
      while (end < text.length && (isIdentChar(text[end]) || text[end] === '.')) end++;
      this.error(this.span(col, end + 1), tmsg('script:syntax.float'), 'SCRIPT_SYNTAX_FLOAT');
      this.push('INT', text.slice(start, end), this.span(col, end + 1), 0n);
      return end;
    }
    if (next !== undefined && isIdentChar(next)) {
      while (end < text.length && isIdentChar(text[end])) end++;
      this.error(this.span(col, end + 1), tmsg('script:syntax.invalidNumber', { p0: text.slice(start, end) }), 'SCRIPT_SYNTAX_INVALID_NUMBER');
      this.push('INT', text.slice(start, end), this.span(col, end + 1), 0n);
      return end;
    }
    const digits = text.slice(start, end).replace(/_/g, '');
    this.push('INT', text.slice(start, end), this.span(col, end + 1), BigInt(digits));
    return end;
  }

  private lexWord(text: string, start: number): number {
    let end = start + 1;
    while (end < text.length && isIdentChar(text[end])) end++;
    const word = text.slice(start, end);
    const col = start + 1;
    const span = this.span(col, end + 1);
    // 접두사는 따옴표와 붙어 있을 때만 리터럴이다.
    if ((word === 'h' || word === 'b' || word === 's') && text[end] === '"') {
      return this.lexBytesLiteral(text, start, word);
    }
    if (word === 'f' && text[end] === '"') return this.lexFString(text, start);
    if (word in UNSUPPORTED_HINT) {
      this.error(span, tmsg('script:syntax.unsupported', { hint: UNSUPPORTED_HINT[word] }), 'SCRIPT_SYNTAX_UNSUPPORTED');
      this.push('UNSUPPORTED', word, span);
      return end;
    }
    if (word.startsWith('__')) {
      this.error(span, tmsg('script:syntax.reservedName', { word }), 'SCRIPT_SYNTAX_RESERVED_NAME');
    }
    this.push(RESERVED.has(word) ? 'KW' : 'NAME', word, span);
    return end;
  }

  /** text[i]의 `\` 이스케이프 하나를 읽어 문자와 다음 인덱스를 돌려준다. 잘못된 이스케이프는 오류를 내고 건너뛴다. */
  private readEscape(text: string, i: number): { ch: string; next: number } {
    const col = i + 1;
    const e = text[i + 1];
    const simple: Record<string, string> = { '\\': '\\', '"': '"', n: '\n', r: '\r', t: '\t' };
    if (e !== undefined && e in simple) return { ch: simple[e], next: i + 2 };
    if (e === 'u') {
      const hex = text.slice(i + 2, i + 6);
      if (/^[0-9a-fA-F]{4}$/.test(hex)) return { ch: String.fromCharCode(parseInt(hex, 16)), next: i + 6 };
      this.error(this.span(col, Math.min(i + 6, text.length) + 1), tmsg('script:syntax.badUnicodeEscape'), 'SCRIPT_SYNTAX_BAD_ESCAPE');
      return { ch: '', next: i + 2 };
    }
    this.error(this.span(col, col + 2), tmsg('script:syntax.badEscape', { p0: e ?? '' }), 'SCRIPT_SYNTAX_BAD_ESCAPE');
    return { ch: '', next: i + 2 };
  }

  /** f"..." (§4.9). 필드 {식:서식}의 식은 소스 그대로 담아 파서가 읽는다. */
  private lexFString(text: string, start: number): number {
    const parts: RawFPart[] = [];
    let lit = '';
    let i = start + 2;
    const bad = (col: number, endCol: number, msg: Msg, code: string): number => {
      this.error(this.span(col, endCol), msg, code);
      const q = text.indexOf('"', i);
      const end = q < 0 ? text.length : q + 1;
      this.push('FSTR', text.slice(start, end), this.span(start + 1, end + 1), []);
      return end;
    };
    while (i < text.length && text[i] !== '"') {
      const c = text[i];
      if (c === '\\') { const r = this.readEscape(text, i); lit += r.ch; i = r.next; continue; }
      if ((c === '{' || c === '}') && text[i + 1] === c) { lit += c; i += 2; continue; }
      if (c === '}') return bad(i + 1, i + 2, tmsg('script:syntax.fstringBrace'), 'SCRIPT_SYNTAX_FSTRING_BRACE');
      if (c !== '{') { lit += c; i++; continue; }
      let j = i + 1;
      let depth = 0;
      while (j < text.length) {
        const d = text[j];
        if (d === '"' || d === '\\' || d === '{') break;
        if (d === '(' || d === '[') depth++;
        else if (d === ')' || d === ']') depth--;
        else if (depth <= 0 && (d === ':' || d === '}')) break;
        j++;
      }
      if (text[j] !== ':' && text[j] !== '}') {
        return bad(i + 1, Math.min(j, text.length) + 1,
          tmsg('script:syntax.fstringField'), 'SCRIPT_SYNTAX_FSTRING_FIELD');
      }
      const src = text.slice(i + 1, j);
      if (src.trim() === '') return bad(i + 1, j + 2, tmsg('script:syntax.fstringEmpty'), 'SCRIPT_SYNTAX_FSTRING_EMPTY');
      let spec = '';
      let close = j;
      if (text[j] === ':') {
        close = j + 1;
        while (close < text.length && !'"{}\\'.includes(text[close])) close++;
        if (text[close] !== '}') return bad(j + 1, close + 1, tmsg('script:syntax.fstringSpec'), 'SCRIPT_SYNTAX_FSTRING_FIELD');
        spec = text.slice(j + 1, close);
      }
      if (lit) { parts.push(lit); lit = ''; }
      parts.push({ src, line: this.line, col: i + 2, spec, specCol: j + 2 });
      i = close + 1;
    }
    if (i >= text.length) {
      this.error(this.span(start + 1, text.length + 1), tmsg('script:syntax.unterminatedString'), 'SCRIPT_SYNTAX_UNTERMINATED_STRING');
      this.push('FSTR', text.slice(start), this.span(start + 1, text.length + 1), []);
      return text.length;
    }
    if (lit) parts.push(lit);
    this.push('FSTR', text.slice(start, i + 1), this.span(start + 1, i + 2), parts);
    return i + 1;
  }

  /** 여는 따옴표 위치 qi부터 읽어 닫는 따옴표 다음 인덱스를 end로 돌려준다. */
  private readString(text: string, qi: number): { value: string; end: number } {
    let i = qi + 1;
    let out = '';
    while (i < text.length && text[i] !== '"') {
      if (text[i] !== '\\') { out += text[i++]; continue; }
      const r = this.readEscape(text, i);
      out += r.ch;
      i = r.next;
    }
    if (i >= text.length) {
      this.error(this.span(qi + 1, text.length + 1), tmsg('script:syntax.unterminatedString'), 'SCRIPT_SYNTAX_UNTERMINATED_STRING');
      return { value: out, end: text.length };
    }
    return { value: out, end: i + 1 };
  }

  private lexBytesLiteral(text: string, start: number, prefix: string): number {
    const col = start + 1;
    const qi = start + 1;
    if (prefix === 's') {
      const r = this.readString(text, qi);
      this.push('TEXT', text.slice(start, r.end), this.span(col, r.end + 1), new TextEncoder().encode(r.value));
      return r.end;
    }
    const close = text.indexOf('"', qi + 1);
    if (close < 0) {
      this.error(this.span(col, text.length + 1), tmsg('script:syntax.unterminatedLiteral'), 'SCRIPT_SYNTAX_UNTERMINATED_STRING');
      this.push(prefix === 'h' ? 'HEX' : 'BIN', text.slice(start), this.span(col, text.length + 1), new Uint8Array(0));
      return text.length;
    }
    const body = text.slice(qi + 1, close);
    const bodyCol = qi + 2; // 첫 내용 문자의 열
    const bytes = prefix === 'h' ? this.parseHexBody(body, bodyCol) : this.parseBinBody(body, bodyCol);
    this.push(prefix === 'h' ? 'HEX' : 'BIN', text.slice(start, close + 1), this.span(col, close + 2), bytes);
    return close + 1;
  }

  private parseHexBody(body: string, bodyCol: number): Uint8Array {
    const digits: number[] = []; // 각 16진 문자의 본문 내 인덱스
    for (let k = 0; k < body.length; k++) {
      const c = body[k];
      if (c === ' ' || c === '\t') continue;
      if (isHexDigit(c)) { digits.push(k); continue; }
      const prev = digits.length ? body[digits[digits.length - 1]] : '';
      const hint = (c === 'x' || c === 'X') && prev === '0' ? tmsg('script:syntax.hexPrefixHint') : '';
      this.error(this.span(bodyCol + k, bodyCol + k + 1),
        tmsg('script:syntax.hexInvalidChar', { c, hint }),
        'SCRIPT_SYNTAX_HEX_INVALID_CHAR');
      return new Uint8Array(0);
    }
    const pairs = Math.floor(digits.length / 2);
    if (digits.length % 2 !== 0) {
      const k = digits[digits.length - 1];
      this.error(this.span(bodyCol + k, bodyCol + k + 1),
        tmsg('script:syntax.hexOddDigits', { length: digits.length }),
        'SCRIPT_SYNTAX_HEX_ODD_DIGITS');
    }
    const out = new Uint8Array(pairs);
    for (let p = 0; p < pairs; p++) out[p] = parseInt(body[digits[2 * p]] + body[digits[2 * p + 1]], 16);
    return out;
  }

  private parseBinBody(body: string, bodyCol: number): Uint8Array {
    const bits: number[] = [];
    for (let k = 0; k < body.length; k++) {
      const c = body[k];
      if (c === ' ' || c === '\t') continue;
      if (c === '0' || c === '1') { bits.push(k); continue; }
      this.error(this.span(bodyCol + k, bodyCol + k + 1),
        tmsg('script:syntax.binInvalidChar', { c }),
        'SCRIPT_SYNTAX_BIN_INVALID_CHAR');
      return new Uint8Array(0);
    }
    const whole = Math.floor(bits.length / 8);
    if (bits.length % 8 !== 0) {
      const k = bits[whole * 8];
      this.error(this.span(bodyCol + k, bodyCol + k + 1),
        tmsg('script:syntax.binBitCount', { length: bits.length }),
        'SCRIPT_SYNTAX_BIN_BIT_COUNT');
    }
    const out = new Uint8Array(whole);
    for (let p = 0; p < whole; p++) {
      let v = 0;
      for (let q = 0; q < 8; q++) v = (v << 1) | (body[bits[p * 8 + q]] === '1' ? 1 : 0);
      out[p] = v;
    }
    return out;
  }
}
