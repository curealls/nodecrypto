import { describe, it, expect } from 'vitest';
import { parse } from 'nodecrypto-engine/script';
import { lex } from 'nodecrypto-engine/script/lexer';
import { parseTokens } from 'nodecrypto-engine/script/parser';
import { check } from 'nodecrypto-engine/script/checker';
import type { PortList } from 'nodecrypto-engine/script/checker';
import { BUILTINS, isBuiltin } from 'nodecrypto-engine/script/builtins';
import type { Expr, Stmt } from 'nodecrypto-engine/script';

/** "l:bytes, n:int" 형태를 포트 목록으로 */
function ports(ins: string, outs: string): PortList {
  const p = (s: string) => s.split(',').map((x) => x.trim()).filter(Boolean).map((x) => {
    const [id, dataType] = x.split(':');
    return { id, dataType };
  });
  return { inputs: p(ins), outputs: p(outs) };
}

function run(src: string, ins = '', outs = 'o:int') {
  const parsed = parse(src);
  expect(parsed.diagnostics).toEqual([]);
  return check(parsed.program!, ports(ins, outs));
}
const okOf = (src: string, ins = '', outs = 'o:int') => {
  const r = run(src, ins, outs);
  expect(r.diagnostics).toEqual([]);
  return r.typed!;
};
const diag = (src: string, ins = '', outs = 'o:int') => run(src, ins, outs).diagnostics;
const codesOf = (src: string, ins = '', outs = 'o:int') => diag(src, ins, outs).map((d) => d.code);

const EXAMPLES: [string, string, string, string][] = [
  ['CMAC 서브키 (§12.1)', 'l:bytes', 'k1:bytes, k2:bytes', `def dbl(x: bytes) -> bytes:
    rb = h"00" * (len(x) - 1) + (h"87" if len(x) == 16 else h"1b")
    r = x << 1
    if x[0] & 0x80 != 0:
        r ^= rb
    return r

k1 = dbl(l)
k2 = dbl(k1)
`],
  ['카운터 블록 (§12.2)', 'seed:bytes, n:int', 'out:bytes', `parts: list[bytes] = []
for i in range(n):
    parts += [seed + to_bytes(i, 4)]
out = concat(parts)
`],
  ['오류 검사와 튜플 반환 (§12.3)', 'data:bytes', 'head:bytes, body:bytes', `def split2(b: bytes, n: int) -> tuple[bytes, bytes]:
    if len(b) < n:
        fail("DATA_TOO_SHORT", "data is shorter than the header")
    return b[:n], b[n:]

head, body = split2(data, 4)
`],
  ['DES 키 홀수 패리티 (§12.4)', 'key:bytes', 'fixed:bytes', `out: list[int] = []
for v in key:
    ones = 0
    for s in range(1, 8):
        ones += (v >> s) & 1
    out += [(v & 0xFE) | (1 - ones % 2)]
fixed = from_ints(out)
`],
];

describe('checker: §12 예제는 통과한다', () => {
  it.each(EXAMPLES)('%s', (_n, ins, outs, src) => {
    const t = okOf(src, ins, outs);
    expect(t.outputs.size).toBeGreaterThan(0);
  });

  it('통과하면 식에 확정 타입이 붙는다', () => {
    const t = okOf('x = 1 + 2\ny = h"00" * x\no = len(y)\n');
    const [a, b, c] = t.program.body as Extract<Stmt, { kind: 'Assign' }>[];
    expect([a.value.ty, b.value.ty, c.value.ty]).toEqual(['int', 'bytes', 'int']);
  });

  it('함수와 상수 심볼 표를 내보낸다', () => {
    const t = okOf('K = 5\ndef f(a: int) -> tuple[int, bool]:\n    return a + K, True\no = 1\n');
    expect(t.consts.get('K')).toBe('int');
    expect(t.funcs.get('f')).toMatchObject({ params: [{ name: 'a', type: 'int' }], ret: { tuple: ['int', 'bool'] } });
  });
});

describe('checker: 타입 결정 (§4.1~4.2)', () => {
  it('변수 타입은 첫 대입에서 고정된다', () => {
    const d = diag('x = 1\nx = h"00"\no = 1\n');
    expect(d).toHaveLength(1);
    expect(d[0]).toMatchObject({ line: 2, column: 5, endColumn: 10, code: 'SCRIPT_TYPE_MISMATCH' });
  });

  it('암묵적 형변환은 없다(int와 bytes 혼합은 변환 안내)', () => {
    const d = diag('o = 1 + h"00"\n');
    expect(d[0]).toMatchObject({ line: 1, code: 'SCRIPT_TYPE_MISMATCH' });
    expect(d[0].message).toContain('to_int');
    expect(codesOf('o = 1 + True\n')).toEqual(['SCRIPT_TYPE_MISMATCH']);
  });

  it('조건은 bool만(truthiness 없음)', () => {
    const d = diag('if 1:\n    pass\no = 1\n');
    expect(d[0]).toMatchObject({ line: 1, column: 4, code: 'SCRIPT_TYPE_MISMATCH' });
    expect(codesOf('o = 1 if 5 else 2\n')).toEqual(['SCRIPT_TYPE_MISMATCH']);
    expect(codesOf('x = 1 and True\no = 1\n')).toEqual(['SCRIPT_TYPE_MISMATCH']);
    expect(codesOf('x = not 3\no = 1\n')).toEqual(['SCRIPT_TYPE_MISMATCH']);
  });

  it('빈 목록은 타입 주석이 있어야 한다', () => {
    expect(diag('xs = []\no = 1\n')[0]).toMatchObject({ line: 1, column: 6, code: 'SCRIPT_EMPTY_LIST' });
    okOf('xs: list[bytes] = []\no = len(xs)\n');
    expect(codesOf('xs: int = []\no = 1\n')).toEqual(['SCRIPT_TYPE_MISMATCH']);
  });

  it('중첩 목록과 원소 타입 불일치', () => {
    expect(codesOf('xs = [[1]]\no = 1\n')).toEqual(['SCRIPT_NESTED_LIST']);
    expect(codesOf('xs = [1, True]\no = 1\n')).toEqual(['SCRIPT_TYPE_MISMATCH']);
  });

  it('타입 주석과 값의 불일치', () => {
    expect(codesOf('x: int = h"00"\no = 1\n')).toEqual(['SCRIPT_TYPE_MISMATCH']);
    okOf('x: int = 1\nx: int = 2\no = x\n');
  });

  it('연쇄 오류를 막는다(실패한 대입의 대상은 조용히 건너뜀)', () => {
    const d = diag('x = y + 1\nz = x + 1\no = z\n');
    expect(d).toHaveLength(1);
    expect(d[0].code).toBe('SCRIPT_NAME_UNDEFINED');
  });

  it('정의되지 않은 이름의 위치', () => {
    expect(diag('o = zzz\n')[0]).toMatchObject({ line: 1, column: 5, endColumn: 8, code: 'SCRIPT_NAME_UNDEFINED' });
  });
});

describe('checker: 연산자와 첨자 (§4.6~4.7)', () => {
  it('표에 있는 조합은 통과한다', () => {
    okOf(`a = h"01" + h"02"
b = h"00" * 3
c = 3 * h"00"
d = a ^ b
e = a << 1
f = ~a
g = "x" + "y"
h = [1] + [2]
i = a == b
j = a < b
k = [1] == [2]
m = g == "xy"
o = (1 << 3) | (7 // 2) % 3 - -1
`);
  });

  it.each([
    ['o = 1 << h"00"\n'], ['x = h"00" - h"00"\n'], ['x = "a" < "b"\n'], ['x = True + True\n'], ['x = [1] + [True]\n'],
    ['x = 1 == h"00"\n'], ['x = "a" * 2\n'], ['x = h"00" // 2\n'], ['x = -h"00"\n'], ['x = ~True\n'],
  ])('표에 없는 조합은 오류: %s', (src) => {
    expect(codesOf(src + 'o = 1\n')).toContain('SCRIPT_TYPE_MISMATCH');
  });

  it('첨자: bytes와 list', () => {
    const t = okOf('b = h"0102"\nxs = [h"01"]\na = b[0]\nc = b[0:1]\nd = b[0, 1]\ne = xs[0]\nf = xs[0:1]\ng = xs[0, 1]\no = a\n');
    const body = t.program.body as Extract<Stmt, { kind: 'Assign' }>[];
    expect(body.slice(2, 8).map((s) => s.value.ty)).toEqual(['int', 'bytes', 'bytes', 'bytes', 'list[bytes]', 'list[bytes]']);
  });

  it('첨자 오류: string, 비정수 인덱스', () => {
    expect(codesOf('s = "ab"\nx = s[0]\no = 1\n')).toEqual(['SCRIPT_TYPE_MISMATCH']);
    expect(codesOf('b = h"00"\nx = b[True]\no = 1\n')).toEqual(['SCRIPT_TYPE_MISMATCH']);
    expect(diag('b = h"00"\nx = b[1, h"00"]\no = 1\n')[0]).toMatchObject({ line: 2, column: 10 });
  });

  it('첨자 대입', () => {
    okOf('b = h"0000"\nb[0] = 1\nb[0:1] = h"ff"\nb[0, 1] = h"ff"\nxs: list[int] = [1]\nxs[0] = 2\no = xs[0]\n');
    expect(codesOf('b = h"00"\nb[0] = h"01"\no = 1\n')).toEqual(['SCRIPT_TYPE_MISMATCH']);
    expect(codesOf('b = h"00"\nb[0:1] = 1\no = 1\n')).toEqual(['SCRIPT_TYPE_MISMATCH']);
    expect(codesOf('xs: list[int] = [1]\nxs[0:1] = [2]\no = 1\n')).toEqual(['SCRIPT_TYPE_MISMATCH']);
    expect(codesOf('xs: list[int] = [1]\nxs[0] = True\no = 1\n')).toEqual(['SCRIPT_TYPE_MISMATCH']);
    expect(codesOf('s = "a"\ns[0] = 1\no = 1\n')).toEqual(['SCRIPT_TYPE_MISMATCH']);
  });

  it('복합 대입은 x = x op e와 같고 결과 타입이 변수 타입이어야 한다', () => {
    okOf('x = 1\nx += 2\nb = h"00"\nb ^= h"01"\nb <<= 1\no = x\n');
    expect(codesOf('x = 1\nx += h"00"\no = x\n')).toEqual(['SCRIPT_TYPE_MISMATCH']);
    expect(codesOf('b = h"00"\nb *= 2\no = 1\n')).toEqual([]);
  });
});

describe('checker: 내장 함수 (§7)', () => {
  it('내장 함수 표는 단일 원천으로 모든 §7 함수를 가진다', () => {
    const names = ['len', 'zeros', 'fill', 'concat', 'reverse', 'blocks', 'to_ints', 'from_ints', 'rol', 'ror', 'ct_equals', 'compare',
      'to_int', 'to_bytes', 'from_hex', 'to_hex', 'from_utf8', 'to_utf8', 'str', 'abs', 'min', 'max', 'pow', 'bit_length', 'range', 'fail'];
    for (const n of names) expect(isBuiltin(n)).toBe(true);
    expect(Object.keys(BUILTINS).sort()).toEqual([...names].sort());
  });

  it('키워드 인자와 기본값: 위치 순서로 정렬되고 기본값이 채워진다', () => {
    const t = okOf('b = h"01"\nx = to_int(b)\ny = to_int(b, signed=True)\nz = to_int(b, "little", True)\no = x + y + z\n');
    const calls = (t.program.body.slice(1, 4) as Extract<Stmt, { kind: 'Assign' }>[]).map((s) => s.value as Extract<Expr, { kind: 'Call' }>);
    for (const c of calls) { expect(c.args).toHaveLength(3); expect(c.callee).toBe('builtin'); }
    expect(calls[0].args[1].value).toMatchObject({ kind: 'StrLit', value: 'big' });
    expect(calls[0].args[2].value).toMatchObject({ kind: 'BoolLit', value: false });
    expect(calls[1].args[2].value).toMatchObject({ kind: 'BoolLit', value: true });
    expect(calls[2].args[1].value).toMatchObject({ kind: 'StrLit', value: 'little' });
  });

  it('endian은 string 변수여도 된다', () => {
    okOf('e = "big"\nx = to_int(h"01", e)\no = x\n');
  });

  it('len은 bytes와 모든 목록을 받는다', () => {
    okOf('a = len(h"00") + len([1]) + len([h"00"])\no = a\n');
    expect(codesOf('o = len(1)\n')).toEqual(['SCRIPT_TYPE_MISMATCH']);
  });

  it('호출 오류: 인자 개수, 이름, 타입, 중복', () => {
    expect(codesOf('o = len()\n')).toEqual(['SCRIPT_CALL_ARGS']);
    expect(codesOf('o = len(h"00", h"00")\n')).toEqual(['SCRIPT_CALL_ARGS']);
    expect(codesOf('x = to_int(h"00", sign=True)\no = 1\n')).toEqual(['SCRIPT_CALL_ARGS']);
    expect(codesOf('x = to_int(h"00", "big", True, 1)\no = 1\n')).toEqual(['SCRIPT_CALL_ARGS']);
    expect(codesOf('x = to_int(h"00", "big", endian="big")\no = 1\n')).toEqual(['SCRIPT_CALL_ARGS']);
    expect(codesOf('x = zeros(h"00")\no = 1\n')).toEqual(['SCRIPT_TYPE_MISMATCH']);
    expect(codesOf('x = to_bytes(1)\no = 1\n')).toEqual(['SCRIPT_CALL_ARGS']);
    expect(codesOf('x = foo(1)\no = 1\n')).toEqual(['SCRIPT_NAME_UNDEFINED']);
  });

  it('fail의 인자는 string 두 개이고 값으로 쓸 수 없다', () => {
    okOf('fail("A", "b")\n');
    expect(codesOf('fail(1, "b")\no = 1\n')).toEqual(['SCRIPT_TYPE_MISMATCH']);
    expect(codesOf('fail("A")\n')).toEqual(['SCRIPT_CALL_ARGS']);
    expect(codesOf('x = fail("A", "b")\no = 1\n')).toEqual(['SCRIPT_TYPE_MISMATCH']);
  });

  it('값이 있는 호출을 식 문장으로 쓰는 것은 허용된다', () => {
    okOf('len(h"00")\no = 1\n');
  });

  it('int 리터럴은 MAX_INT_BITS를 넘을 수 없다', () => {
    const src = `o = 0x${'f'.repeat(262145)}\n`; // 1,048,580비트 (소스 한도는 parse()에서만 검사)
    const lexed = lex(src);
    const parsed = parseTokens(lexed.tokens);
    expect(parsed.diagnostics).toEqual([]);
    const r = check(parsed.program, ports('', 'o:int'));
    expect(r.diagnostics.map((d) => d.code)).toEqual(['SCRIPT_INT_LITERAL_TOO_LARGE']);
  });
});

describe('checker: for와 range (§4.8)', () => {
  it('list, bytes, range를 반복하고 반복 변수 타입이 정해진다', () => {
    okOf('t = 0\nfor x in [1, 2]:\n    t += x\nfor v in h"0102":\n    t += v\nfor i in range(2):\n    t += i\nfor i in range(1, 5):\n    t += i\nfor i in range(0, 10, 3):\n    t += i\no = t\n');
    okOf('t = h""\nfor x in [h"01"]:\n    t += x\no = len(t)\n');
  });

  it('반복 대상 오류', () => {
    expect(codesOf('for x in 5:\n    pass\no = 1\n')).toEqual(['SCRIPT_TYPE_MISMATCH']);
    expect(codesOf('for x in "ab":\n    pass\no = 1\n')).toEqual(['SCRIPT_TYPE_MISMATCH']);
    expect(codesOf('for i in range():\n    pass\no = 1\n')).toEqual(['SCRIPT_CALL_ARGS']);
    expect(codesOf('for i in range(1, 2, 3, 4):\n    pass\no = 1\n')).toEqual(['SCRIPT_CALL_ARGS']);
    expect(codesOf('for i in range(h"00"):\n    pass\no = 1\n')).toEqual(['SCRIPT_TYPE_MISMATCH']);
  });

  it('range는 for의 반복 대상으로만 쓸 수 있다', () => {
    expect(diag('r = range(3)\no = 1\n')[0]).toMatchObject({ line: 1, column: 5, code: 'SCRIPT_RANGE_CONTEXT' });
    expect(codesOf('o = len(range(3))\n')).toEqual(['SCRIPT_RANGE_CONTEXT']);
  });

  it('반복 변수는 반복문 밖에서 볼 수 없다', () => {
    const d = diag('for i in range(3):\n    pass\no = i\n');
    expect(d).toHaveLength(1);
    expect(d[0]).toMatchObject({ line: 3, column: 5, code: 'SCRIPT_NAME_UNDEFINED' });
  });

  it('반복 변수가 이미 있는 이름과 같으면 오류, 순차 반복에서는 같은 이름을 다시 쓸 수 있다', () => {
    expect(codesOf('i = 0\nfor i in range(3):\n    pass\no = i\n')).toEqual(['SCRIPT_NAME_CONFLICT']);
    expect(codesOf('for i in range(3):\n    for i in range(3):\n        pass\no = 1\n')).toEqual(['SCRIPT_NAME_CONFLICT']);
    okOf('for i in range(3):\n    pass\nfor i in range(3):\n    pass\no = 1\n');
  });

  it('break/continue는 for 안에서만', () => {
    expect(diag('break\no = 1\n')[0]).toMatchObject({ line: 1, code: 'SCRIPT_LOOP_CONTROL_OUTSIDE' });
    expect(codesOf('if True:\n    continue\no = 1\n')).toEqual(['SCRIPT_LOOP_CONTROL_OUTSIDE']);
    okOf('t = 0\nfor i in range(5):\n    if i == 3:\n        break\n    if i == 1:\n        continue\n    t += i\no = t\n');
  });
});

describe('checker: 정의된 대입 분석 (§4.5)', () => {
  const IO = ['a:bool, b:bool', 'o:int'] as const;

  it('if만 있고 else가 없으면 출력 미대입', () => {
    const d = diag('if a:\n    o = 1\n', ...IO);
    expect(d).toHaveLength(1);
    expect(d[0]).toMatchObject({ code: 'SCRIPT_OUTPUT_UNASSIGNED' });
    expect(d[0].message).toContain("'o'");
  });

  it('모든 분기(else 포함)에서 대입하면 통과', () => {
    okOf('if a:\n    o = 1\nelif b:\n    o = 2\nelse:\n    o = 3\n', ...IO);
  });

  it('elif 체인에 else가 없으면 오류', () => {
    expect(codesOf('if a:\n    o = 1\nelif b:\n    o = 2\n', ...IO)).toEqual(['SCRIPT_OUTPUT_UNASSIGNED']);
  });

  it('중첩 if: 안쪽에 else가 없으면 오류, 있으면 통과', () => {
    okOf('if a:\n    if b:\n        o = 1\n    else:\n        o = 2\nelse:\n    o = 3\n', ...IO);
    expect(codesOf('if a:\n    if b:\n        o = 1\nelse:\n    o = 3\n', ...IO)).toEqual(['SCRIPT_OUTPUT_UNASSIGNED']);
    expect(codesOf('if a:\n    o = 1\nelse:\n    if b:\n        o = 2\n', ...IO)).toEqual(['SCRIPT_OUTPUT_UNASSIGNED']);
  });

  it('fail로 끝나는 분기는 합류에서 제외된다', () => {
    okOf('if a:\n    fail("A", "x")\nelse:\n    o = 1\n', ...IO);
    okOf('if a:\n    o = 1\nelif b:\n    fail("A", "x")\nelse:\n    o = 2\n', ...IO);
    okOf('if a:\n    if b:\n        fail("A", "x")\n    else:\n        fail("B", "y")\nelse:\n    o = 1\n', ...IO);
    okOf('if a:\n    o = 1\n    fail("A", "x")\nelse:\n    o = 2\n', ...IO);
  });

  it('스크립트가 fail로 끝나면 출력 대입 검사를 하지 않는다', () => {
    okOf('fail("A", "x")\n', ...IO);
  });

  it('변수 하나를 한 분기에서만 대입하고 뒤에서 읽으면 오류', () => {
    const d = diag('if a:\n    x = 1\no = x\n', ...IO);
    expect(d.map((x) => x.code)).toEqual(['SCRIPT_UNASSIGNED']);
    expect(d[0]).toMatchObject({ line: 3, column: 5 });
    okOf('if a:\n    x = 1\nelse:\n    x = 2\no = x\n', ...IO);
  });

  it('두 분기에서 서로 다른 타입을 대입하면 오류', () => {
    expect(codesOf('if a:\n    x = 1\nelse:\n    x = h"00"\no = 1\n', ...IO)).toEqual(['SCRIPT_TYPE_MISMATCH']);
  });

  it('for 안에서만 대입한 변수는 반복문 뒤에서 쓸 수 없다', () => {
    const d = diag('for i in range(3):\n    x = i\no = x\n');
    expect(d.map((x) => x.code)).toEqual(['SCRIPT_UNASSIGNED']);
    expect(d[0]).toMatchObject({ line: 3, column: 5 });
    expect(codesOf('for i in range(3):\n    o = i\n')).toEqual(['SCRIPT_OUTPUT_UNASSIGNED']);
  });

  it('for 밖에서 미리 대입한 출력은 for 안에서 바꿔도 된다', () => {
    okOf('o = 0\nfor i in range(3):\n    o += i\n');
  });

  it('자기 자신을 읽는 첫 대입', () => {
    expect(codesOf('x = x + 1\no = 1\n')).toEqual(['SCRIPT_NAME_UNDEFINED']);
  });

  it('맞바꿈 a, b = b, a', () => {
    okOf('a = 1\nb = 2\na, b = b, a\no = a\n');
    expect(codesOf('a = 1\nb = h"00"\na, b = b, a\no = 1\n')).toEqual(['SCRIPT_TYPE_MISMATCH']);
  });

  it('출력 변수를 읽기 전에 대입해야 한다', () => {
    expect(codesOf('o += 1\n')).toEqual(['SCRIPT_UNASSIGNED', 'SCRIPT_OUTPUT_UNASSIGNED']);
  });

  it('함수 안: if 합류와 return 경로', () => {
    okOf('def f(x: int) -> int:\n    if x > 0:\n        return 1\n    else:\n        return 2\no = f(1)\n');
    okOf('def f(x: int) -> int:\n    if x > 0:\n        return 1\n    return 2\no = f(1)\n');
    okOf('def f(x: int) -> int:\n    if x > 0:\n        fail("A", "b")\n    return 2\no = f(1)\n');
    const d = diag('def f(x: int) -> int:\n    if x > 0:\n        return 1\no = 1\n');
    expect(d).toHaveLength(1);
    expect(d[0]).toMatchObject({ line: 1, column: 5, endColumn: 6, code: 'SCRIPT_RETURN_MISSING' });
    expect(codesOf('def f(x: int) -> int:\n    for i in range(3):\n        return i\no = 1\n')).toEqual(['SCRIPT_RETURN_MISSING']);
  });
});

describe('checker: 함수 (§4.4)', () => {
  it('재귀 호출은 거부된다', () => {
    const d = diag('def f(x: int) -> int:\n    return f(x)\no = 1\n');
    expect(d).toHaveLength(1);
    expect(d[0]).toMatchObject({ line: 2, column: 12, code: 'SCRIPT_FUNC_ORDER' });
  });

  it('위에서 정의되지 않은 함수를 부르면 거부된다(상호 재귀 포함)', () => {
    expect(codesOf('o = g(1)\ndef g(x: int) -> int:\n    return x\n')).toEqual(['SCRIPT_FUNC_ORDER']);
    expect(codesOf('def f(x: int) -> int:\n    return g(x)\ndef g(x: int) -> int:\n    return f(x)\no = 1\n')).toEqual(['SCRIPT_FUNC_ORDER']);
    okOf('def g(x: int) -> int:\n    return x\ndef f(x: int) -> int:\n    return g(x)\no = f(1)\n');
  });

  it('함수 안에서 입력 포트, 출력, 최상위 변수를 볼 수 없다', () => {
    const d = diag('def f() -> int:\n    return n\no = f()\n', 'n:int');
    expect(d).toHaveLength(1);
    expect(d[0]).toMatchObject({ line: 2, column: 12, code: 'SCRIPT_FUNC_SCOPE' });
    expect(codesOf('x = 1\ndef f() -> int:\n    return x\no = f()\n')).toEqual(['SCRIPT_FUNC_SCOPE']);
    expect(codesOf('def f() -> int:\n    return o\no = 1\n')).toEqual(['SCRIPT_FUNC_SCOPE']);
  });

  it('매개변수 이름은 포트 이름과 같아도 되고, 함수는 인자를 바꿀 수 있다', () => {
    okOf('def f(n: int) -> int:\n    n += 1\n    return n\no = f(n)\n', 'n:int');
  });

  it('인자와 반환 타입 검사', () => {
    expect(codesOf('def f(x: int) -> int:\n    return x\no = f(h"00")\n')).toEqual(['SCRIPT_TYPE_MISMATCH']);
    expect(codesOf('def f(x: int) -> int:\n    return x\no = f(1, 2)\n')).toEqual(['SCRIPT_CALL_ARGS']);
    expect(codesOf('def f(x: int) -> int:\n    return h"00"\no = 1\n')).toEqual(['SCRIPT_RETURN_TYPE']);
    expect(codesOf('def f(x: int) -> int:\n    return\no = 1\n')).toEqual(['SCRIPT_RETURN_TYPE']);
    expect(codesOf('def f(x: int):\n    return 1\no = 1\n')).toEqual(['SCRIPT_RETURN_TYPE']);
  });

  it('사용자 함수에는 키워드 인자가 없다', () => {
    expect(codesOf('def f(x: int) -> int:\n    return x\no = f(x=1)\n')).toEqual(['SCRIPT_CALL_ARGS']);
  });

  it('반환값이 없는 함수는 호출문으로만 쓴다', () => {
    okOf('def chk(x: int):\n    if x < 0:\n        fail("NEG", "negative")\nchk(1)\no = 1\n');
    expect(codesOf('def chk(x: int):\n    pass\no = chk(1)\n')).toEqual(['SCRIPT_TYPE_MISMATCH']);
  });

  it('return은 함수 안에서만', () => {
    expect(diag('return 1\no = 1\n')[0]).toMatchObject({ line: 1, code: 'SCRIPT_RETURN_OUTSIDE' });
  });

  it('이름 충돌: 내장 함수, 중복 정의, 포트, 변수', () => {
    expect(codesOf('def len(x: int) -> int:\n    return x\no = 1\n')).toEqual(['SCRIPT_NAME_RESERVED']);
    expect(codesOf('def f() -> int:\n    return 1\ndef f() -> int:\n    return 2\no = 1\n')).toEqual(['SCRIPT_NAME_CONFLICT']);
    expect(codesOf('def n() -> int:\n    return 1\no = 1\n', 'n:int')).toEqual(['SCRIPT_NAME_CONFLICT']);
    // 정의와 대입 양쪽을 가리킨다
    expect(codesOf('def f() -> int:\n    return 1\nf = 2\no = 1\n')).toEqual(['SCRIPT_NAME_CONFLICT', 'SCRIPT_NAME_CONFLICT']);
    expect(codesOf('len = 1\no = 1\n')).toEqual(['SCRIPT_NAME_RESERVED']);
    expect(codesOf('def f(len: int) -> int:\n    return len\no = 1\n')).toEqual(['SCRIPT_NAME_RESERVED']);
    expect(codesOf('def f(x: int, x: int) -> int:\n    return x\no = 1\n')).toEqual(['SCRIPT_NAME_CONFLICT']);
  });

  it('함수 이름은 값으로 쓸 수 없다', () => {
    const d = diag('def f() -> int:\n    return 1\nx = f\no = 1\n');
    expect(d).toHaveLength(1);
    expect(d[0].code).toBe('SCRIPT_NAME_UNDEFINED');
    expect(d[0].msg).toEqual({ key: 'script:check.nameIsFunctionValue', params: { name: 'f' } });
  });
});

describe('checker: 상수 (§4.4)', () => {
  it('상수는 함수 안에서 읽을 수 있다', () => {
    okOf('K = 5\nMASK = h"ff"\nTWO = K * 2\ndef f(x: int) -> int:\n    return x + TWO\no = f(1)\n');
  });

  it('상수는 리터럴, 다른 상수, 내장 함수 호출로만 만든다', () => {
    okOf('A = from_hex("00ff")\nB = A + h"01"\nC = len(B) + 1\nD: list[int] = [C, 2]\no = C\n');
    const d = diag('x = 1\nK = x\no = 1\n');
    expect(d).toHaveLength(1);
    expect(d[0]).toMatchObject({ line: 2, column: 5, code: 'SCRIPT_CONST_INVALID' });
    expect(codesOf('n2 = 1\nK = n2 + 1\no = 1\n')).toEqual(['SCRIPT_CONST_INVALID']);
    expect(codesOf('def f() -> int:\n    return 1\nK = f()\no = 1\n')).toEqual(['SCRIPT_CONST_INVALID']);
    expect(codesOf('K = n\no = 1\n', 'n:int')).toEqual(['SCRIPT_CONST_INVALID']);
  });

  it('상수는 재대입할 수 없다', () => {
    expect(codesOf('K = 1\nK = 2\no = 1\n')).toEqual(['SCRIPT_CONST_REASSIGN']);
    expect(codesOf('K = 1\nK += 2\no = 1\n')).toEqual(['SCRIPT_CONST_REASSIGN']);
    expect(codesOf('K = h"00"\nK[0] = 1\no = 1\n')).toEqual(['SCRIPT_CONST_REASSIGN']);
  });

  it('상수는 최상위에서만 정의한다', () => {
    expect(codesOf('if True:\n    K = 1\no = 1\n')).toEqual(['SCRIPT_CONST_NOT_TOP']);
    expect(codesOf('for i in range(2):\n    K = i\no = 1\n')).toEqual(['SCRIPT_CONST_NOT_TOP']);
  });

  it('함수 안의 대문자 이름은 지역 변수이지만 상수와 같은 이름은 안 된다', () => {
    okOf('def f() -> int:\n    X = 1\n    return X\no = f()\n');
    expect(codesOf('K = 1\ndef f() -> int:\n    K = 2\n    return K\no = 1\n')).toEqual(['SCRIPT_NAME_CONFLICT']);
  });

  it('위에서 정의된 상수만 함수에서 쓸 수 있다', () => {
    expect(codesOf('def f() -> int:\n    return K\nK = 1\no = f()\n')).toEqual(['SCRIPT_FUNC_SCOPE']);
  });

  it('출력 포트와 같은 이름은 상수가 아니라 출력 변수이다', () => {
    okOf('OUT = 1\n', '', 'OUT:int');
    okOf('if True:\n    OUT = 1\nelse:\n    OUT = 2\n', '', 'OUT:int');
    expect(codesOf('KEY = 1\n', 'KEY:int', 'o:int')).toEqual(['SCRIPT_INPUT_READONLY', 'SCRIPT_OUTPUT_UNASSIGNED']);
  });
});

describe('checker: 튜플 (§4.4)', () => {
  const F = 'def f(x: int) -> tuple[int, bytes]:\n    return x, h"00"\n';

  it('풀어쓰기 대입', () => {
    const t = okOf(F + 'a, b = f(1)\no = a + len(b)\n');
    expect((t.program.body[1] as Extract<Stmt, { kind: 'Unpack' }>).value.ty).toEqual({ tuple: ['int', 'bytes'] });
    okOf('a, b = 1, h"00"\no = a\n');
  });

  it('개수와 타입이 같아야 한다', () => {
    expect(diag(F + 'a, b, c = f(1)\no = 1\n')[0]).toMatchObject({ line: 3, code: 'SCRIPT_TUPLE_MISMATCH' });
    expect(codesOf(F + 'a = 0\nb = 0\na, b = f(1)\no = 1\n')).toEqual(['SCRIPT_TYPE_MISMATCH']);
    expect(codesOf('a, b = 1, 2, 3\no = 1\n')).toEqual(['SCRIPT_TUPLE_MISMATCH']);
    expect(codesOf('a, a = 1, 2\no = 1\n')).toEqual(['SCRIPT_TUPLE_MISMATCH']);
    expect(codesOf('def g() -> int:\n    return 1\na, b = g()\no = 1\n')).toEqual(['SCRIPT_TUPLE_MISMATCH']);
  });

  it('return 튜플 검사', () => {
    expect(codesOf('def f() -> tuple[int, int]:\n    return 1\no = 1\n')).toEqual(['SCRIPT_RETURN_TYPE']);
    expect(codesOf('def f() -> tuple[int, int]:\n    return 1, 2, 3\no = 1\n')).toEqual(['SCRIPT_TUPLE_MISMATCH']);
    expect(codesOf('def f() -> tuple[int, int]:\n    return 1, True\no = 1\n')).toEqual(['SCRIPT_RETURN_TYPE']);
    expect(codesOf('def f() -> int:\n    return 1, 2\no = 1\n')).toEqual(['SCRIPT_TUPLE_CONTEXT']);
  });

  it('튜플을 반환하는 호출을 값으로 쓸 수 없다', () => {
    expect(codesOf(F + 'x = f(1)\no = 1\n')).toEqual(['SCRIPT_TUPLE_CONTEXT']);
  });
});

describe('checker: 포트 바인딩 (§2.2)', () => {
  it('입력 변수는 읽기 전용', () => {
    expect(diag('n = 1\no = n\n', 'n:int')[0]).toMatchObject({ line: 1, column: 1, code: 'SCRIPT_INPUT_READONLY' });
    expect(codesOf('n += 1\no = n\n', 'n:int')).toEqual(['SCRIPT_INPUT_READONLY']);
    expect(codesOf('b[0] = 1\no = 1\n', 'b:bytes')).toEqual(['SCRIPT_INPUT_READONLY']);
    expect(codesOf('n, m = 1, 2\no = 1\n', 'n:int')).toEqual(['SCRIPT_INPUT_READONLY']);
  });

  it('출력 변수의 타입은 출력 포트와 같아야 한다', () => {
    const d = diag('o = h"00"\n');
    expect(d[0]).toMatchObject({ line: 1, column: 5, code: 'SCRIPT_OUTPUT_TYPE_MISMATCH' });
    expect(d[0].message).toContain('int');
  });

  it('출력이 한 번도 대입되지 않으면 오류(출력마다 하나)', () => {
    expect(codesOf('o = 1\n', '', 'o:int, p:int')).toEqual(['SCRIPT_OUTPUT_UNASSIGNED']);
    expect(codesOf('x = 1\n')).toEqual(['SCRIPT_OUTPUT_UNASSIGNED']);
    expect(codesOf('', '', 'o:int')).toEqual(['SCRIPT_OUTPUT_UNASSIGNED']);
  });

  it('입출력 변수를 읽을 수 있다', () => {
    okOf('o = n + 1\n', 'n:int');
    okOf('o = 1\np = o + 1\n', '', 'o:int, p:int');
  });

  it('포트 id 규칙', () => {
    const portDiags = (ins: string, outs: string) => check({ body: [] }, ports(ins, outs)).diagnostics.map((d) => d.code);
    expect(portDiags('x:any', 'o:int')).toContain('SCRIPT_PORT_INVALID_TYPE');
    expect(portDiags('x:set', 'o:int')).toContain('SCRIPT_PORT_INVALID_TYPE');
    expect(portDiags('x:int, x:int', 'o:int')).toContain('SCRIPT_PORT_DUPLICATE_ID');
    expect(portDiags('x:int', 'x:int')).toContain('SCRIPT_PORT_DUPLICATE_ID');
    expect(portDiags('for:int', 'o:int')).toContain('SCRIPT_PORT_RESERVED_ID');
    expect(portDiags('len:int', 'o:int')).toContain('SCRIPT_PORT_RESERVED_ID');
    expect(portDiags('import:int', 'o:int')).toContain('SCRIPT_PORT_RESERVED_ID');
    expect(portDiags('1x:int', 'o:int')).toContain('SCRIPT_PORT_INVALID_ID');
    expect(portDiags('a-b:int', 'o:int')).toContain('SCRIPT_PORT_INVALID_ID');
    expect(portDiags('__x:int', 'o:int')).toContain('SCRIPT_PORT_INVALID_ID');
    expect(portDiags('x:int', '')).toEqual([]);
  });

  it('포트 진단은 줄:열 범위를 가진다', () => {
    const d = check({ body: [] }, ports('x:any', 'o:int')).diagnostics[0];
    expect(d).toMatchObject({ line: 1, column: 1, endLine: 1, endColumn: 1 });
  });
});

describe('checker: 진단 형식', () => {
  it('진단은 줄:열 순으로 정렬되고 여러 오류를 모은다', () => {
    const d = diag('a = zz\nb = 1 + h"00"\nc = [[1]]\no = 1\n');
    expect(d.map((x) => x.line)).toEqual([1, 2, 3]);
    for (const x of d) {
      expect(x.column).toBeGreaterThanOrEqual(1);
      expect(x.endColumn).toBeGreaterThan(x.column);
      expect(x.code).toMatch(/^SCRIPT_/);
    }
  });

  it('오류가 있으면 typed가 없다', () => {
    expect(run('o = h"00"\n').typed).toBeUndefined();
  });

  it('while류 구문은 T04(파서)에서 거부되어 검사기에 도달하지 않는다', () => {
    const r = parse('while True:\n    pass\n');
    expect(r.program).toBeUndefined();
    expect(r.diagnostics[0].code).toBe('SCRIPT_SYNTAX_UNSUPPORTED');
  });
});
