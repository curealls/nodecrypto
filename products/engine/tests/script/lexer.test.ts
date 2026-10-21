import { describe, it, expect } from 'vitest';
import { lex } from 'nodecrypto-engine/script/lexer';

const hex = (v: unknown) => Array.from(v as Uint8Array).map((b) => b.toString(16).padStart(2, '0')).join('');
const kinds = (src: string) => lex(src).tokens.map((t) => t.kind);
const codes = (src: string) => lex(src).diagnostics.map((d) => d.code);

describe('lexer: 줄과 들여쓰기 (§3.1)', () => {
  it('INDENT/DEDENT를 만들고 빈 줄과 주석 줄은 무시한다', () => {
    const src = 'if x:\n    # 주석\n\n    y = 1\nz = 2\n';
    expect(kinds(src)).toEqual([
      'KW', 'NAME', 'OP', 'NEWLINE', 'INDENT', 'NAME', 'OP', 'INT', 'NEWLINE', 'DEDENT', 'NAME', 'OP', 'INT', 'NEWLINE', 'EOF',
    ]);
  });

  it('괄호 안에서는 줄 바꿈과 들여쓰기가 무시된다', () => {
    const toks = kinds('x = (1 +\n  2)\n');
    expect(toks).not.toContain('INDENT');
    expect(toks.filter((k) => k === 'NEWLINE')).toHaveLength(1);
  });

  it('탭 들여쓰기는 오류이며 줄:열이 정확하다', () => {
    const d = lex('if True:\n\tpass\n').diagnostics;
    expect(d).toHaveLength(1);
    expect(d[0]).toMatchObject({ line: 2, column: 1, code: 'SCRIPT_SYNTAX_TAB_INDENT' });
  });

  it('들여쓰기가 4칸 단위가 아니면 오류', () => {
    const d = lex('if True:\n  pass\n').diagnostics;
    expect(d[0]).toMatchObject({ line: 2, column: 1, endColumn: 3, code: 'SCRIPT_SYNTAX_INDENT_UNIT' });
  });

  it('한 번에 두 단계 이상 들여쓰면 오류', () => {
    expect(codes('if True:\n        pass\n')).toContain('SCRIPT_SYNTAX_INDENT_TOO_DEEP');
  });

  it('줄 이음(\\)은 오류', () => {
    expect(codes('x = 1 + \\\n 2\n')).toContain('SCRIPT_SYNTAX_LINE_CONTINUATION');
  });

  it('닫히지 않은 괄호와 짝이 맞지 않는 괄호', () => {
    expect(lex('x = (1\n').diagnostics[0]).toMatchObject({ line: 1, column: 5, code: 'SCRIPT_SYNTAX_UNCLOSED_BRACKET' });
    expect(lex('x = 1)\n').diagnostics[0]).toMatchObject({ line: 1, column: 6, code: 'SCRIPT_SYNTAX_UNMATCHED_BRACKET' });
  });
});

describe('lexer: 식별자와 예약어 (§3.2)', () => {
  it('예약어는 KW, 나머지는 NAME', () => {
    expect(kinds('def x\n').slice(0, 2)).toEqual(['KW', 'NAME']);
    expect(kinds('True False and or not\n').slice(0, 5)).toEqual(['KW', 'KW', 'KW', 'KW', 'KW']);
  });

  it('__로 시작하는 이름은 오류', () => {
    expect(lex('__x = 1\n').diagnostics[0]).toMatchObject({ line: 1, column: 1, code: 'SCRIPT_SYNTAX_RESERVED_NAME' });
  });

  it.each(['import', 'class', 'while', 'lambda', 'try', 'with', 'global', 'print'])('문법에 없는 키워드 %s는 지원하지 않는 구문 오류', (kw) => {
    const d = lex(`${kw} x\n`).diagnostics;
    expect(d).toHaveLength(1);
    expect(d[0]).toMatchObject({ line: 1, column: 1, endColumn: kw.length + 1, code: 'SCRIPT_SYNTAX_UNSUPPORTED' });
    expect(d[0].msg.key).toBe('script:syntax.unsupported');
    expect(d[0].msg.params?.hint).toMatchObject({ key: `script:syntax.hint.${kw}` });
  });
});

describe('lexer: 리터럴 (§3.3)', () => {
  it('int: 10진, 16진, 2진, 밑줄', () => {
    const v = lex('255 0xFF 0b1010 1_000 0xdead_beef\n').tokens.filter((t) => t.kind === 'INT').map((t) => t.value);
    expect(v).toEqual([255n, 255n, 10n, 1000n, 0xdeadbeefn]);
  });

  it('큰 정수는 bigint로 보존된다', () => {
    const t = lex('4722366482869645213695\n').tokens[0];
    expect(t.value).toBe(4722366482869645213695n);
  });

  it('부동소수점과 잘못된 숫자는 오류', () => {
    expect(lex('x = 1.5\n').diagnostics[0]).toMatchObject({ line: 1, column: 5, code: 'SCRIPT_SYNTAX_FLOAT' });
    expect(codes('x = 12abc\n')).toEqual(['SCRIPT_SYNTAX_INVALID_NUMBER']);
    expect(codes('x = 1e5\n')).toEqual(['SCRIPT_SYNTAX_INVALID_NUMBER']);
  });

  it('string 이스케이프', () => {
    const t = lex('"a\\n\\t\\"\\\\\\u0041"\n').tokens[0];
    expect(t.value).toBe('a\n\t"\\A');
  });

  it('잘못된 이스케이프, 닫히지 않은 문자열, 작은따옴표는 오류', () => {
    expect(lex('"a\\q"\n').diagnostics[0]).toMatchObject({ line: 1, column: 3, code: 'SCRIPT_SYNTAX_BAD_ESCAPE' });
    expect(codes('"abc\n')).toEqual(['SCRIPT_SYNTAX_UNTERMINATED_STRING']);
    expect(codes("'abc'\n")).toEqual(['SCRIPT_SYNTAX_SINGLE_QUOTE']);
  });
});

describe('lexer: bytes 리터럴 h/b/s (§3.3.1)', () => {
  it('h"..."는 공백(탭 포함)을 무시하고 대소문자를 모두 받는다', () => {
    const t = lex('h"87 23\taF"\n').tokens[0];
    expect(t.kind).toBe('HEX');
    expect(hex(t.value)).toBe('8723af');
  });

  it('빈 리터럴', () => {
    expect(hex(lex('h""\n').tokens[0].value)).toBe('');
    expect(hex(lex('b""\n').tokens[0].value)).toBe('');
    expect(hex(lex('s""\n').tokens[0].value)).toBe('');
  });

  it('b"..."는 2진, 공백 무시', () => {
    expect(hex(lex('b"1000 0000 0000 0001"\n').tokens[0].value)).toBe('8001');
  });

  it('s"..."는 UTF-8이며 이스케이프는 string과 같다', () => {
    expect(hex(lex('s"0123"\n').tokens[0].value)).toBe('30313233');
    expect(hex(lex('s"가"\n').tokens[0].value)).toBe('eab080');
    expect(hex(lex('s"a\\nb"\n').tokens[0].value)).toBe('610a62');
  });

  it('h 홀수 자릿수: 짝이 없는 마지막 문자 위치', () => {
    const d = lex('h"8"\n').diagnostics;
    expect(d).toHaveLength(1);
    expect(d[0]).toMatchObject({ line: 1, column: 3, endColumn: 4, code: 'SCRIPT_SYNTAX_HEX_ODD_DIGITS' });
    expect(lex('h"00 11 2"\n').diagnostics[0]).toMatchObject({ column: 9, code: 'SCRIPT_SYNTAX_HEX_ODD_DIGITS' });
  });

  it('h 잘못된 문자: 그 문자 위치', () => {
    expect(lex('h"8g"\n').diagnostics[0]).toMatchObject({ line: 1, column: 4, endColumn: 5, code: 'SCRIPT_SYNTAX_HEX_INVALID_CHAR' });
    const d = lex('h"0x00"\n').diagnostics[0];
    expect(d).toMatchObject({ column: 4, code: 'SCRIPT_SYNTAX_HEX_INVALID_CHAR' });
    expect(d.message).toContain('0x');
  });

  it('b 비트 수가 8의 배수가 아니면 불완전한 마지막 바이트의 시작 위치', () => {
    expect(lex('b"101"\n').diagnostics[0]).toMatchObject({ line: 1, column: 3, code: 'SCRIPT_SYNTAX_BIN_BIT_COUNT' });
    expect(lex('b"1010 0001 101"\n').diagnostics[0]).toMatchObject({ column: 13, code: 'SCRIPT_SYNTAX_BIN_BIT_COUNT' });
    expect(lex('b"1010 0001 101"\n').diagnostics[0].msg).toEqual({ key: 'script:syntax.binBitCount', params: { length: 11 } });
  });

  it('Python식 b"abc", b"\\x87"는 오류이며 h/s를 안내한다', () => {
    for (const [src, col] of [['b"abc"', 3], ['b"\\x87"', 3], ['b"1012"', 6]] as const) {
      const d = lex(src + '\n').diagnostics;
      expect(d).toHaveLength(1);
      expect(d[0]).toMatchObject({ line: 1, column: col, code: 'SCRIPT_SYNTAX_BIN_INVALID_CHAR' });
      expect(d[0].message).toContain('h"');
      expect(d[0].message).toContain('s"');
    }
  });

  it('접두사는 따옴표와 붙어 있을 때만 리터럴이고, 변수 이름 h/b/s는 허용된다', () => {
    expect(kinds('h = 1\n').slice(0, 3)).toEqual(['NAME', 'OP', 'INT']);
    expect(kinds('x = h + b + s\n').filter((k) => k === 'NAME')).toHaveLength(4);
    expect(kinds('h "87"\n').slice(0, 2)).toEqual(['NAME', 'STRING']);
  });

  it('닫히지 않은 리터럴', () => {
    expect(codes('h"00\n')).toEqual(['SCRIPT_SYNTAX_UNTERMINATED_STRING']);
  });
});

describe('lexer: 기타 오류', () => {
  it.each([['{', 'SCRIPT_SYNTAX_BRACE'], [';', 'SCRIPT_SYNTAX_SEMICOLON'], ['$', 'SCRIPT_SYNTAX_UNKNOWN_CHAR']])('문자 %s', (ch, code) => {
    expect(lex(`x = 1 ${ch}\n`).diagnostics[0]).toMatchObject({ line: 1, column: 7, code });
  });
});
