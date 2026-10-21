import { describe, it, expect } from 'vitest';
import { parse, MAX_SOURCE } from 'nodecrypto-engine/script';
import type { Expr, Stmt, FuncDef } from 'nodecrypto-engine/script';

const hex = (v: Uint8Array) => Array.from(v).map((b) => b.toString(16).padStart(2, '0')).join('');

function ok(src: string) {
  const r = parse(src);
  expect(r.diagnostics).toEqual([]);
  return r.program!.body;
}
const diags = (src: string) => parse(src).diagnostics;
/** 한 문장짜리 소스에서 우변 식을 꺼낸다 */
function rhs(src: string): Expr {
  const s = ok(src)[0] as Stmt;
  if (s.kind !== 'Assign') throw new Error('Assign이 아님');
  return s.value;
}

// ---- builtin-script.md §12 예제 ----
const EXAMPLES: Record<string, string> = {
  'CMAC 서브키 (§12.1)': `def dbl(x: bytes) -> bytes:
    rb = h"00" * (len(x) - 1) + (h"87" if len(x) == 16 else h"1b")
    r = x << 1
    if x[0] & 0x80 != 0:
        r ^= rb
    return r

k1 = dbl(l)
k2 = dbl(k1)
`,
  '카운터 블록 (§12.2)': `parts: list[bytes] = []
for i in range(n):
    parts += [seed + to_bytes(i, 4)]
out = concat(parts)
`,
  '오류 검사와 튜플 반환 (§12.3)': `def split2(b: bytes, n: int) -> tuple[bytes, bytes]:
    if len(b) < n:
        fail("DATA_TOO_SHORT", "data is shorter than the header")
    return b[:n], b[n:]

head, body = split2(data, 4)
`,
  'DES 키 홀수 패리티 (§12.4)': `out: list[int] = []
for v in key:
    ones = 0
    for s in range(1, 8):
        ones += (v >> s) & 1
    out += [(v & 0xFE) | (1 - ones % 2)]
fixed = from_ints(out)
`,
};

describe('parser: §12 예제', () => {
  it.each(Object.entries(EXAMPLES))('%s', (_n, src) => {
    expect(ok(src).length).toBeGreaterThan(0);
  });
});

describe('parser: 문법 구문', () => {
  it('대입, 타입 주석 대입, 복합 대입', () => {
    const [a, b, c] = ok('x = 1\ny: list[bytes] = []\nz += 2\n') as Stmt[];
    expect(a.kind).toBe('Assign');
    expect(b).toMatchObject({ kind: 'AnnAssign', type: { kind: 'list', elem: 'bytes' } });
    expect(c).toMatchObject({ kind: 'AugAssign', op: '+' });
  });

  it.each(['+=', '-=', '*=', '//=', '%=', '&=', '|=', '^=', '<<=', '>>='])('복합 대입 %s', (op) => {
    expect(ok(`x ${op} 1\n`)[0]).toMatchObject({ kind: 'AugAssign', op: op.slice(0, -1) });
  });

  it('첨자 대입 세 형태', () => {
    const [a, b, c] = ok('b[0] = 1\nb[1:3] = p\nb[0, 2] = p\n') as Extract<Stmt, { kind: 'SubAssign' }>[];
    expect(a.index.kind).toBe('item');
    expect(b.index.kind).toBe('slice');
    expect(c.index.kind).toBe('offsetLength');
  });

  it('풀어쓰기 대입(호출, 튜플, 맞바꿈)', () => {
    const [a, b] = ok('a, b = f(x)\na, b = b, a\n') as Extract<Stmt, { kind: 'Unpack' }>[];
    expect(a.targets.map((t) => t.name)).toEqual(['a', 'b']);
    expect(a.value.kind).toBe('Call');
    expect(b.value.kind).toBe('Tuple');
  });

  it('if / elif / else, for, break, continue, pass', () => {
    const [s] = ok(`if a:
    pass
elif b:
    break
else:
    continue
for i in range(3):
    pass
`) as Stmt[];
    expect(s).toMatchObject({ kind: 'If' });
    const i = s as Extract<Stmt, { kind: 'If' }>;
    expect(i.branches).toHaveLength(2);
    expect(i.orelse?.[0].kind).toBe('Continue');
  });

  it('for는 목록, bytes, range를 반복한다', () => {
    const body = ok('for x in xs:\n    pass\nfor v in b:\n    pass\nfor i in range(1, 8):\n    pass\n') as Extract<Stmt, { kind: 'For' }>[];
    expect(body.map((f) => f.iter.kind)).toEqual(['Name', 'Name', 'Call']);
  });

  it('함수 정의: 반환 타입 없음, 단일, 튜플', () => {
    const f = ok(`def a(x: int):
    pass
def b(x: list[int], y: bytes) -> list[int]:
    return x
def c(x: int) -> tuple[int, bool]:
    return x, True
`) as FuncDef[];
    expect(f[0].ret).toBeUndefined();
    expect(f[1].ret).toMatchObject({ kind: 'single' });
    expect(f[1].params).toHaveLength(2);
    expect(f[2].ret).toMatchObject({ kind: 'tuple' });
  });

  it('return: 값 없음, 튜플(괄호 유무)', () => {
    const body = (ok('def f():\n    return\ndef g():\n    return (1, 2)\ndef h():\n    return 1, 2\n') as FuncDef[]).map((f) => (f.body[0] as Extract<Stmt, { kind: 'Return' }>).value);
    expect(body[0]).toBeUndefined();
    expect(body[1]?.kind).toBe('Tuple');
    expect(body[2]?.kind).toBe('Tuple');
  });

  it('식 문장은 호출만, 키워드 인자', () => {
    const [s] = ok('fail("A", "b")\n') as Stmt[];
    expect(s.kind).toBe('ExprStmt');
    const c = rhs('x = to_int(b, signed=True)\n') as Extract<Expr, { kind: 'Call' }>;
    expect(c.args.map((a) => a.name)).toEqual([undefined, 'signed']);
  });

  it('조건식, 목록 리터럴, 호출 결과 첨자', () => {
    expect(rhs('x = 1 if c else 2\n').kind).toBe('Cond');
    expect(rhs('x = [1, 2, 3,]\n')).toMatchObject({ kind: 'ListLit' });
    expect(rhs('x = f(1)[0]\n').kind).toBe('Index');
  });

  it('리터럴 값', () => {
    expect(rhs('x = 0xFF\n')).toMatchObject({ kind: 'IntLit', value: 255n });
    expect(rhs('x = True\n')).toMatchObject({ kind: 'BoolLit', value: true });
    expect(rhs('x = "a"\n')).toMatchObject({ kind: 'StrLit', value: 'a' });
    const h = rhs('x = h"87 23"\n') as Extract<Expr, { kind: 'BytesLit' }>;
    expect([h.form, hex(h.value)]).toEqual(['hex', '8723']);
    const b = rhs('x = b"1000 0111"\n') as Extract<Expr, { kind: 'BytesLit' }>;
    expect([b.form, hex(b.value)]).toEqual(['bin', '87']);
    const s = rhs('x = s"0123"\n') as Extract<Expr, { kind: 'BytesLit' }>;
    expect([s.form, hex(s.value)]).toEqual(['text', '30313233']);
  });

  it('모든 노드가 소스 위치를 가진다', () => {
    const e = rhs('x = ab + 12\n') as Extract<Expr, { kind: 'Binary' }>;
    expect(e.span).toMatchObject({ line: 1, column: 5, endLine: 1, endColumn: 12 });
    expect(e.left.span).toMatchObject({ column: 5, endColumn: 7 });
    expect(e.right.span).toMatchObject({ column: 10, endColumn: 12 });
  });
});

describe('parser: 우선순위와 첨자', () => {
  it('x & 0x80 != 0 은 (x & 0x80) != 0', () => {
    const e = rhs('r = x & 0x80 != 0\n') as Extract<Expr, { kind: 'Binary' }>;
    expect(e.op).toBe('!=');
    expect(e.left).toMatchObject({ kind: 'Binary', op: '&' });
  });

  it('산술/시프트/비트 우선순위: | < ^ < & < << < + < *', () => {
    const e = rhs('r = a | b ^ c & d << e + f * g\n') as Extract<Expr, { kind: 'Binary' }>;
    expect(e.op).toBe('|');
    const x = e.right as Extract<Expr, { kind: 'Binary' }>;
    expect(x.op).toBe('^');
    const a = x.right as Extract<Expr, { kind: 'Binary' }>;
    expect(a.op).toBe('&');
    const sh = a.right as Extract<Expr, { kind: 'Binary' }>;
    expect(sh.op).toBe('<<');
    const add = sh.right as Extract<Expr, { kind: 'Binary' }>;
    expect(add.op).toBe('+');
    expect((add.right as Extract<Expr, { kind: 'Binary' }>).op).toBe('*');
  });

  it('왼쪽 결합, and/or/not, 단항', () => {
    expect(rhs('r = a - b - c\n')).toMatchObject({ op: '-', left: { op: '-' } });
    expect(rhs('r = a or b and not c\n')).toMatchObject({ op: 'or', right: { op: 'and', right: { kind: 'Unary', op: 'not' } } });
    expect(rhs('r = -~x\n')).toMatchObject({ kind: 'Unary', op: '-', operand: { kind: 'Unary', op: '~' } });
  });

  it('b[6, -1]과 b[6:-1]을 구분한다', () => {
    const ol = rhs('r = b[6, -1]\n') as Extract<Expr, { kind: 'Index' }>;
    expect(ol.index).toMatchObject({ kind: 'offsetLength', offset: { value: 6n }, length: { kind: 'Unary', op: '-' } });
    const sl = rhs('r = b[6:-1]\n') as Extract<Expr, { kind: 'Index' }>;
    expect(sl.index).toMatchObject({ kind: 'slice', start: { value: 6n }, stop: { kind: 'Unary', op: '-' } });
  });

  it('구간 생략 형태', () => {
    const idx = (s: string) => (rhs(`r = ${s}\n`) as Extract<Expr, { kind: 'Index' }>).index;
    expect(idx('b[:3]')).toMatchObject({ kind: 'slice', stop: { value: 3n } });
    expect(idx('b[2:]')).toMatchObject({ kind: 'slice', start: { value: 2n } });
    const all = idx('b[:]') as Extract<ReturnType<typeof idx>, { kind: 'slice' }>;
    expect([all.kind, all.start, all.stop]).toEqual(['slice', undefined, undefined]);
    expect(idx('b[1]')).toMatchObject({ kind: 'item' });
  });
});

describe('parser: 바이트열 리터럴 이어 붙이기', () => {
  it('괄호 안 줄 바꿈으로 나란한 h"..."는 하나로 합쳐진다(주석 포함)', () => {
    const e = rhs('KEY = (h"00 11"   # 앞\n       h"22 33")\n') as Extract<Expr, { kind: 'BytesLit' }>;
    expect(hex(e.value)).toBe('00112233');
    expect(e.span).toMatchObject({ line: 1, column: 8, endLine: 2, endColumn: 16 });
  });

  it('b끼리, s끼리도 합친다', () => {
    expect(hex((rhs('x = (b"0000 0001"\n b"0000 0010")\n') as Extract<Expr, { kind: 'BytesLit' }>).value)).toBe('0102');
    expect(hex((rhs('x = (s"ab"\n s"cd")\n') as Extract<Expr, { kind: 'BytesLit' }>).value)).toBe('61626364');
  });

  it('호출 인자와 목록 안에서도 합친다', () => {
    expect(ok('x = f(h"00"\n h"11")\n')).toHaveLength(1);
    expect(ok('x = [h"00"\n h"11"]\n')).toHaveLength(1);
  });

  it('괄호 밖에서는 오류', () => {
    const d = diags('x = h"00" h"11"\n');
    expect(d).toHaveLength(1);
    expect(d[0]).toMatchObject({ line: 1, code: 'SCRIPT_SYNTAX_LITERAL_CONCAT_OUTSIDE_PAREN' });
  });

  it('종류가 다르면 합치지 않고 오류', () => {
    const d = diags('x = (h"00" s"a")\n');
    expect(d).toHaveLength(1);
    expect(d[0].code).toBe('SCRIPT_SYNTAX_LITERAL_MIXED_KIND');
  });
});

describe('parser: 문법 밖 구문의 진단과 줄:열', () => {
  it('h "87" (접두사와 따옴표 사이 공백)', () => {
    const d = diags('x = h "87"\n');
    expect(d).toHaveLength(1);
    expect(d[0]).toMatchObject({ line: 1, column: 5, endColumn: 11, code: 'SCRIPT_SYNTAX_LITERAL_PREFIX_SPACE' });
  });

  it('while 블록은 진단 하나만 내고 본문을 건너뛴다', () => {
    const d = diags('while True:\n    x = 1\ny = 2\n');
    expect(d).toHaveLength(1);
    expect(d[0]).toMatchObject({ line: 1, column: 1, endColumn: 6, code: 'SCRIPT_SYNTAX_UNSUPPORTED' });
  });

  it('import', () => {
    const d = diags('import os\n');
    expect(d).toHaveLength(1);
    expect(d[0]).toMatchObject({ line: 1, column: 1, code: 'SCRIPT_SYNTAX_UNSUPPORTED' });
  });

  it('. 속성 접근/메서드 호출', () => {
    const d = diags('x = b.hex()\n');
    expect(d).toHaveLength(1);
    expect(d[0]).toMatchObject({ line: 1, column: 6, endColumn: 7, code: 'SCRIPT_SYNTAX_ATTRIBUTE' });
    expect(d[0].msg.key).toBe('script:syntax.attribute');
  });

  it('연쇄 비교는 두 번째 연산자를 가리킨다', () => {
    const d = diags('x = a < b < c\n');
    expect(d).toHaveLength(1);
    expect(d[0]).toMatchObject({ line: 1, column: 11, code: 'SCRIPT_SYNTAX_CHAINED_COMPARISON' });
  });

  it('** 와 / 연산자', () => {
    expect(diags('x = a ** 2\n')[0]).toMatchObject({ line: 1, column: 7, endColumn: 9, code: 'SCRIPT_SYNTAX_UNSUPPORTED_OPERATOR' });
    expect(diags('x = a / 2\n')[0]).toMatchObject({ line: 1, column: 7, endColumn: 8, code: 'SCRIPT_SYNTAX_UNSUPPORTED_OPERATOR' });
    expect(diags('x /= 2\n')[0]).toMatchObject({ code: 'SCRIPT_SYNTAX_UNSUPPORTED_OPERATOR' });
    expect(diags('b.hex()\n')[0]).toMatchObject({ line: 1, column: 2, code: 'SCRIPT_SYNTAX_ATTRIBUTE' });
  });

  it('탭 들여쓰기, 4칸 아님은 줄:열을 가리킨다', () => {
    expect(diags('if a:\n\tx = 1\n')[0]).toMatchObject({ line: 2, column: 1, code: 'SCRIPT_SYNTAX_TAB_INDENT' });
    expect(diags('if a:\n   x = 1\n')[0]).toMatchObject({ line: 2, column: 1, code: 'SCRIPT_SYNTAX_INDENT_UNIT' });
  });

  it('식 문장은 호출만 허용', () => {
    expect(diags('x + 1\n')[0]).toMatchObject({ line: 1, column: 1, endColumn: 6, code: 'SCRIPT_SYNTAX_EXPR_STATEMENT' });
    expect(diags('x\n')[0].code).toBe('SCRIPT_SYNTAX_EXPR_STATEMENT');
    expect(diags('x[0]\n')[0].code).toBe('SCRIPT_SYNTAX_EXPR_STATEMENT');
  });

  it('튜플은 return과 풀어쓰기 우변에서만', () => {
    expect(diags('x = (1, 2)\n')[0]).toMatchObject({ line: 1, column: 7, code: 'SCRIPT_SYNTAX_TUPLE_CONTEXT' });
    expect(diags('a, b = 1\n')[0].code).toBe('SCRIPT_SYNTAX_UNPACK_RHS');
  });

  it('함수 호출 대상은 이름뿐', () => {
    expect(diags('x = (a)[0](1)\n')[0].code).toBe('SCRIPT_SYNTAX_CALL_TARGET');
    expect(diags('x = f(1)(2)\n')[0].code).toBe('SCRIPT_SYNTAX_CALL_TARGET');
  });

  it('중첩 def, 짝 없는 else, 한 줄 블록, 컴프리헨션, 중첩 목록 타입', () => {
    expect(diags('if a:\n    def f():\n        pass\n')[0].code).toBe('SCRIPT_SYNTAX_NESTED_DEF');
    expect(diags('else:\n    pass\n')[0].code).toBe('SCRIPT_SYNTAX_DANGLING_ELSE');
    expect(diags('if a: x = 1\n')[0].code).toBe('SCRIPT_SYNTAX_BLOCK_SAME_LINE');
    expect(diags('x = [i for i in y]\n')[0].code).toBe('SCRIPT_SYNTAX_COMPREHENSION');
    expect(diags('x: list[list[int]] = []\n')[0].code).toBe('SCRIPT_SYNTAX_NESTED_LIST');
  });

  it('타입 주석 누락과 기본값 인자', () => {
    expect(diags('def f(x):\n    pass\n')[0].code).toBe('SCRIPT_SYNTAX_PARAM_TYPE');
    expect(diags('def f(x: int = 1):\n    pass\n')[0].code).toBe('SCRIPT_SYNTAX_PARAM_DEFAULT');
    expect(diags('x: int\n')[0].code).toBe('SCRIPT_SYNTAX_ANNOTATION_NO_VALUE');
  });

  it('블록이 비어 있으면 오류', () => {
    expect(diags('if a:\nx = 1\n')[0]).toMatchObject({ line: 2, code: 'SCRIPT_SYNTAX_EXPECTED_INDENT' });
  });

  it('값 위치의 잘못된 토큰', () => {
    expect(diags('x = \n')[0]).toMatchObject({ line: 1, code: 'SCRIPT_SYNTAX_UNEXPECTED_TOKEN' });
    expect(diags('x = 1 +\n')[0].code).toBe('SCRIPT_SYNTAX_UNEXPECTED_TOKEN');
  });

  it('모든 진단은 줄:열 범위를 가진다', () => {
    const d = diags('while x:\n    pass\nx = b.y\ny = (1\nz = h"8"\n');
    expect(d.length).toBeGreaterThanOrEqual(4);
    for (const x of d) {
      expect(x.line).toBeGreaterThanOrEqual(1);
      expect(x.column).toBeGreaterThanOrEqual(1);
      expect(x.endLine).toBeGreaterThanOrEqual(x.line);
      expect(typeof x.message).toBe('string');
    }
  });
});

describe('parser: 오류 복구', () => {
  it('한 오류에서 멈추지 않고 여러 진단을 모은다', () => {
    const d = diags('x = a ** 2\ny = h"8"\nz = b.q\nw = 1\n');
    expect(d.map((x) => x.line)).toEqual([1, 2, 3]);
  });

  it('블록 안의 오류가 바깥 문장 파싱을 막지 않는다', () => {
    const d = diags('if a:\n    x = a ** 2\n    y = 1\nz = b.q\n');
    expect(d.map((x) => x.line)).toEqual([2, 4]);
  });

  it('진단이 있으면 program이 없다', () => {
    expect(parse('x = a ** 2\n').program).toBeUndefined();
    expect(parse('x = 1\n').program).toBeDefined();
  });

  it('소스가 MAX_SOURCE를 넘으면 파싱하지 않고 진단을 반환한다', () => {
    const r = parse('x = 1  # ' + 'a'.repeat(MAX_SOURCE) + '\n');
    expect(r.program).toBeUndefined();
    expect(r.diagnostics).toHaveLength(1);
    expect(r.diagnostics[0].code).toBe('SCRIPT_SYNTAX_SOURCE_TOO_LARGE');
  });

  it('빈 소스와 주석뿐인 소스는 빈 프로그램', () => {
    expect(ok('')).toEqual([]);
    expect(ok('# 주석\n\n')).toEqual([]);
  });

  it('줄 끝 개행이 없어도 파싱되고 CRLF도 같다', () => {
    expect(ok('x = 1')).toHaveLength(1);
    expect(ok('if a:\r\n    x = 1\r\ny = 2\r\n')).toHaveLength(2);
  });
});
