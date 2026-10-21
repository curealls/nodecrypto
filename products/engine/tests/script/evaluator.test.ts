import { describe, it, expect } from 'vitest';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { compile, runScript } from 'nodecrypto-engine/script';
import type { RunOptions, ScriptValue } from 'nodecrypto-engine/script';
import { BUILTINS } from 'nodecrypto-engine/script/builtins';
import { missingImpls } from 'nodecrypto-engine/script/builtinImpl';
import { NodeError } from 'nodecrypto-engine/dag/errors';

type PortTypes = Record<string, string>;

function build(src: string, ins: PortTypes = {}, outs: PortTypes = { o: 'int' }) {
  const r = compile(src, {
    inputs: Object.entries(ins).map(([id, dataType]) => ({ id, dataType })),
    outputs: Object.entries(outs).map(([id, dataType]) => ({ id, dataType })),
  });
  expect(r.diagnostics).toEqual([]);
  return r.typed!;
}

function run(src: string, inputs: Record<string, ScriptValue> = {}, ins: PortTypes = {}, outs: PortTypes = { o: 'int' }, options?: RunOptions) {
  return runScript(build(src, ins, outs), inputs, options);
}

function errorOf(fn: () => unknown): NodeError {
  try {
    fn();
  } catch (e) {
    expect(e).toBeInstanceOf(NodeError);
    return e as NodeError;
  }
  throw new Error('오류가 발생해야 한다');
}

const bytes = (...b: number[]) => new Uint8Array(b);

describe('runScript: 기본', () => {
  it('입력을 받아 출력을 돌려준다', () => {
    expect(run('o = n * 2 + 1\n', { n: 20n }, { n: 'int' })).toEqual({ o: 41n });
    expect(run('o = b + h"ff"\n', { b: bytes(1) }, { b: 'bytes' }, { o: 'bytes' })).toEqual({ o: bytes(1, 255) });
  });

  it('입력 값의 타입이 포트와 다르면 SCRIPT_INTERNAL_ERROR', () => {
    const t = build('o = n\n', { n: 'int' });
    expect(errorOf(() => runScript(t, { n: 1 as unknown as bigint })).code).toBe('SCRIPT_INTERNAL_ERROR');
    expect(errorOf(() => runScript(t, {})).code).toBe('SCRIPT_INTERNAL_ERROR');
  });

  it('정적 검사를 통과하지 못한 프로그램은 실행할 수 없다(typed가 없다)', () => {
    const r = compile('o = h"00"\n', { inputs: [], outputs: [{ id: 'o', dataType: 'int' }] });
    expect(r.typed).toBeUndefined();
    expect(r.diagnostics.length).toBeGreaterThan(0);
    const p = compile('while True:\n    pass\n', { inputs: [], outputs: [{ id: 'o', dataType: 'int' }] });
    expect(p.typed).toBeUndefined();
  });

  it('입력 bytes를 바꾸지 않는다', () => {
    const b = bytes(0, 0, 0);
    const r = run('c = b\nc[0] = 255\no = c\n', { b }, { b: 'bytes' }, { o: 'bytes' });
    expect([...(r.o as Uint8Array)]).toEqual([255, 0, 0]);
    expect([...b]).toEqual([0, 0, 0]);
  });

  it('내부 예외는 SCRIPT_INTERNAL_ERROR로 감싸고 삼키지 않는다', () => {
    const t = build('o = n + 1\n', { n: 'int' });
    t.inputs.delete('n'); // 해석기 내부 불일치를 일부러 만든다
    const e = errorOf(() => runScript(t, {}));
    expect(e.code).toBe('SCRIPT_INTERNAL_ERROR');
    expect(e.msg?.key).toBe('script:eval.internal');
  });
});

describe('값 의미론 (§4.3)', () => {
  it('대입한 목록을 바꿔도 원본이 변하지 않는다(양방향)', () => {
    expect(run('xs: list[int] = [1, 2]\nys = xs\nys[0] = 9\nxs[1] = 8\no = xs[0] * 100 + xs[1] * 10 + ys[0] + ys[1]\n'))
      .toEqual({ o: 1n * 100n + 8n * 10n + 9n + 2n });
  });

  it('함수 인자로 넘긴 목록을 함수가 바꿔도 호출한 쪽은 그대로', () => {
    expect(run('def f(xs: list[int]) -> int:\n    xs += [5]\n    xs[0] = 7\n    return len(xs)\nxs: list[int] = [1]\nr = f(xs)\no = r * 10 + xs[0]\n'))
      .toEqual({ o: 21n });
  });

  it('함수가 돌려준 목록은 호출 전 변수와 공유되지 않는다', () => {
    expect(run('def f(xs: list[int]) -> list[int]:\n    ys = xs\n    ys[0] = 5\n    return ys\nxs: list[int] = [1]\nys = f(xs)\nys[0] = ys[0] + 1\no =xs[0] * 10 + ys[0]\n'))
      .toEqual({ o: 16n });
  });

  it('상수 목록은 읽어서 바꿔도 상수가 변하지 않는다', () => {
    expect(run('K: list[int] = [1, 2]\nxs = K\nxs[0] = 9\nfor x in K:\n    pass\no = K[0] * 10 + xs[0]\n')).toEqual({ o: 19n });
  });

  it('루프 변수가 가리키는 목록을 본문에서 바꿔도 진행 중인 반복에 영향이 없다', () => {
    expect(run('xs: list[int] = [1, 2, 3]\nt = 0\nfor x in xs:\n    xs[2] = 100\n    t += x\no = t\n')).toEqual({ o: 6n });
    expect(run('xs: list[int] = [1, 2]\nfor x in xs:\n    xs += [x]\no = len(xs)\n')).toEqual({ o: 4n });
  });

  it('튜플 풀어쓰기로 받은 목록은 서로 독립적이다', () => {
    expect(run('def f() -> tuple[list[int], list[int]]:\n    xs: list[int] = [1]\n    return xs, xs\na, b = f()\na[0] = 5\no = a[0] * 10 + b[0]\n')).toEqual({ o: 51n });
    expect(run('xs: list[int] = [1]\nys: list[int] = [2]\nxs, ys = ys, xs\nxs[0] = 7\no = xs[0] * 10 + ys[0]\n')).toEqual({ o: 71n });
  });

  it('조건식으로 고른 목록도 복사된다', () => {
    expect(run('xs: list[int] = [1]\nys = xs if True else xs\nys[0] = 5\no = xs[0]\n')).toEqual({ o: 1n });
  });

  it('bytes는 대입해도 서로 영향이 없다', () => {
    expect(run('a = h"00 00"\nb = a\nb[0] = 1\no = a[0] * 10 + b[0]\n')).toEqual({ o: 1n });
  });
});

describe('구간 해석 표 (§4.7)', () => {
  const A = 'a = h"00 11 22 33 44 55 66 77 88"\n';
  const hexOf = (expr: string) => {
    const r = run(`${A}o = ${expr}\n`, {}, {}, { o: 'bytes' }).o as Uint8Array;
    return [...r].map((x) => x.toString(16).padStart(2, '0')).join('');
  };
  it.each([
    ['a[1, 3]', '112233'], ['a[6, -1]', '6677'], ['a[6, -2]', '66'], ['a[6,]', '667788'], ['a[-3,]', '667788'], ['a[-3, 3]', '667788'],
    ['a[1:4]', '112233'], ['a[6:]', '667788'], ['a[6:-1]', '6677'], ['a[:2]', '0011'], ['a[:]', '001122334455667788'],
    ['a[9:]', ''], ['a[9, 0]', ''], ['a[0, -1]', '0011223344556677'], ['a[9,]', ''],
  ])('%s', (expr, expected) => {
    expect(hexOf(expr)).toBe(expected);
  });

  it.each([['a[3:2]'], ['a[0:10]'], ['a[0, 10]'], ['a[10:]'], ['a[-10:]'], ['a[5, -7]']])('범위 밖 %s는 BYTES_OUT_OF_RANGE', (expr) => {
    expect(errorOf(() => hexOf(expr)).code).toBe('BYTES_OUT_OF_RANGE');
  });

  it('목록 구간은 같은 규칙, 범위 밖은 SCRIPT_INDEX_OUT_OF_RANGE', () => {
    expect(run('xs = [1, 2, 3, 4]\nys = xs[1, -1]\no = len(ys)\n')).toEqual({ o: 2n });
    expect(run('xs = [1, 2, 3, 4]\nys = xs[1,]\no = len(ys)\n')).toEqual({ o: 3n });
    expect(run('xs = [1, 2, 3, 4]\nys = xs[:-1]\no = len(ys)\n')).toEqual({ o: 3n });
    expect(errorOf(() => run('xs = [1]\nys = xs[0:2]\no = 1\n')).code).toBe('SCRIPT_INDEX_OUT_OF_RANGE');
  });
});

describe('int (§4.6)', () => {
  it('음수의 //와 %는 내림과 제수 부호를 따른다(Python과 같음)', () => {
    const cases: [bigint, bigint][] = [[-7n, 2n], [7n, -2n], [-7n, -2n], [7n, 2n], [-6n, 3n], [0n, 5n], [-1n, 1000000000000000000000n]];
    for (const [a, b] of cases) {
      const q = a / b - (a % b !== 0n && (a < 0n) !== (b < 0n) ? 1n : 0n);
      const m = a - q * b;
      const r = run('q = a // b\nm = a % b\n', { a, b }, { a: 'int', b: 'int' }, { q: 'int', m: 'int' });
      expect(r).toEqual({ q, m });
    }
  });

  it('2^64를 넘는 곱셈과 시프트', () => {
    expect(run('o = (1 << 64) * (1 << 64) + 1\n')).toEqual({ o: (1n << 128n) + 1n });
    expect(run('o = (n << 70) >> 3\n', { n: 5n }, { n: 'int' })).toEqual({ o: (5n << 70n) >> 3n });
    expect(run('o = -n >> 1\n', { n: 5n }, { n: 'int' })).toEqual({ o: -3n });
  });

  it('>>로 아주 큰 이동량은 0 또는 -1', () => {
    expect(run('o = n >> 1000000000000000000000\n', { n: -5n }, { n: 'int' })).toEqual({ o: -1n });
    expect(run('o = n >> 1000000000000000000000\n', { n: 5n }, { n: 'int' })).toEqual({ o: 0n });
  });

  it('to_int/to_bytes 왕복과 BYTES_INT_OVERFLOW', () => {
    for (const n of [0n, 1n, 255n, 256n, 65535n, (1n << 100n) - 1n]) {
      for (const endian of ['big', 'little']) {
        const r = run(`b = to_bytes(n, 16, "${endian}")\no = to_int(b, "${endian}")\n`, { n }, { n: 'int' });
        expect(r.o).toBe(n);
      }
    }
    for (const n of [-128n, -1n, 127n]) {
      expect(run('o = to_int(to_bytes(n, 1, signed=True), signed=True)\n', { n }, { n: 'int' }).o).toBe(n);
    }
    expect(errorOf(() => run('b = to_bytes(n, 1)\no = 1\n', { n: 256n }, { n: 'int' })).code).toBe('BYTES_INT_OVERFLOW');
    expect(errorOf(() => run('b = to_bytes(n, 1, signed=True)\no = 1\n', { n: 128n }, { n: 'int' })).code).toBe('BYTES_INT_OVERFLOW');
  });

  it('bit_length', () => {
    const r = (n: bigint) => run('o = bit_length(n)\n', { n }, { n: 'int' }).o;
    expect([r(0n), r(1n), r(255n), r(256n), r(-256n), r(1n << 100n), r((1n << 100n) - 1n)]).toEqual([0n, 1n, 8n, 9n, 9n, 101n, 100n]);
  });

  it('큰 정수 입력과 시프트의 비트 수를 정확히 센다', () => {
    const big = (1n << 1_048_575n) + 1n; // 1,048,576비트
    expect(run('o = n\n', { n: big }, { n: 'int' }).o).toBe(big);
    expect(errorOf(() => run('o = n << 1\n', { n: big }, { n: 'int' })).code).toBe('SCRIPT_SIZE_LIMIT');
    expect(errorOf(() => run('o = n + n\n', { n: big }, { n: 'int' })).code).toBe('SCRIPT_SIZE_LIMIT');
  });

  it('pow는 mod 1과 음수 base를 Python과 같게 계산한다', () => {
    expect(run('o = pow(2, 10, 1000)\n').o).toBe(24n);
    expect(run('o = pow(-7, 3, 11)\n').o).toBe(((-343n % 11n) + 11n) % 11n);
    expect(run('o = pow(n, e, m)\n', { n: 123456789n, e: (1n << 64n) + 3n, m: (1n << 61n) - 1n }, { n: 'int', e: 'int', m: 'int' }).o)
      .toBe(((): bigint => { let r = 1n, b = 123456789n % ((1n << 61n) - 1n), e = (1n << 64n) + 3n; const m = (1n << 61n) - 1n; while (e) { if (e & 1n) r = r * b % m; b = b * b % m; e >>= 1n; } return r; })());
  });
});

describe('제어 흐름', () => {
  it('for 안에서 return', () => {
    expect(run('def first_big(xs: list[int]) -> int:\n    for x in xs:\n        if x > 10:\n            return x\n    return -1\no = first_big([1, 20, 30])\n').o).toBe(20n);
  });

  it('중첩 for에서 break는 안쪽에만 적용된다', () => {
    expect(run('t = 0\nfor i in range(3):\n    for j in range(10):\n        if j == 2:\n            break\n        t += 1\no = t\n').o).toBe(6n);
  });

  it('반복 변수는 반복이 끝난 뒤 이름 충돌 없이 다시 쓸 수 있다', () => {
    expect(run('t = 0\nfor i in range(3):\n    t += i\nfor i in range(3):\n    t += i\no = t\n').o).toBe(6n);
  });

  it('인자 없는 호출문과 반환값 없는 함수', () => {
    expect(run('def chk(x: int):\n    if x < 0:\n        fail("NEG", "negative")\nchk(1)\no = 1\n').o).toBe(1n);
    const e = errorOf(() => run('def chk(x: int):\n    if x < 0:\n        fail("NEG", "negative")\nchk(-1)\no = 1\n'));
    expect([e.code, e.message]).toEqual(['NEG', 'negative']);
  });
});

describe('내장 함수 표와 평가 함수', () => {
  it('표의 모든 이름(range 제외)에 평가 함수가 있다', () => {
    expect(missingImpls()).toEqual([]);
    expect(Object.keys(BUILTINS).length).toBeGreaterThan(20);
  });
});

describe('자원 한도 (§9)', () => {
  it('range 반복 횟수와 거대한 range', () => {
    expect(errorOf(() => run('for i in range(2000000):\n    pass\no = 1\n')).code).toBe('SCRIPT_SIZE_LIMIT');
    expect(errorOf(() => run('for i in range(0, 1000000000000000000000000):\n    pass\no = 1\n')).code).toBe('SCRIPT_SIZE_LIMIT');
    expect(errorOf(() => run('for i in range(0, 5, 0):\n    pass\no = 1\n')).code).toBe('SCRIPT_INVALID_ARGUMENT');
    expect(run('t = 0\nfor i in range(10, 0, -3):\n    t += i\no = t\n').o).toBe(22n);
  });

  it('거대한 시프트와 repeat 폭주', () => {
    expect(errorOf(() => run('o = 1 << 2000000\n')).code).toBe('SCRIPT_SIZE_LIMIT');
    expect(errorOf(() => run('o = 1 << 1000000000000000000000\n')).code).toBe('SCRIPT_SIZE_LIMIT');
    expect(errorOf(() => run('x = h"00" * 100000000\no = 1\n')).code).toBe('BYTES_SIZE_LIMIT');
    expect(errorOf(() => run('x = h"00" * 1000000000000000000000\no = 1\n')).code).toBe('BYTES_SIZE_LIMIT');
    expect(errorOf(() => run('x = to_bytes(0, 100000000)\no = 1\n')).code).toBe('BYTES_SIZE_LIMIT');
  });

  it('실행 단계 한도: 기본값과 옵션', () => {
    expect(errorOf(() => run('for i in range(1000000):\n    for j in range(11):\n        pass\no = 1\n')).code).toBe('SCRIPT_STEP_LIMIT');
    expect(errorOf(() => run('t = 0\nfor i in range(100):\n    t += i\no = t\n', {}, {}, { o: 'int' }, { maxSteps: 50 })).code).toBe('SCRIPT_STEP_LIMIT');
    expect(run('t = 0\nfor i in range(100):\n    t += i\no = t\n', {}, {}, { o: 'int' }, { maxSteps: 1000 }).o).toBe(4950n);
  });

  it('시간 상한: 일정 단계마다 경과 시간을 검사한다', () => {
    let t = 0;
    const now = () => (t += 100); // 호출할 때마다 100ms 흐르는 시계
    const e = errorOf(() => run('for i in range(100000):\n    pass\no = 1\n', {}, {}, { o: 'int' }, { now, timeLimitMs: 1000 }));
    expect(e.code).toBe('SCRIPT_TIMEOUT');
    t = 0;
    expect(run('o = 1\n', {}, {}, { o: 'int' }, { now, timeLimitMs: 1000 }).o).toBe(1n);
  });

  it('큰 pow도 시간 상한으로 중단된다', () => {
    let t = 0;
    const now = () => (t += 100);
    const e = errorOf(() => run('o = pow(3, (1 << 5000) - 1, (1 << 64) + 13)\n', {}, {}, { o: 'int' }, { now, timeLimitMs: 1000 }));
    expect(e.code).toBe('SCRIPT_TIMEOUT');
  });

  it('목록 길이와 bytes 길이, int 비트 수 한도와 옵션', () => {
    expect(errorOf(() => run('xs: list[int] = [0]\nfor i in range(21):\n    xs += xs\no = 1\n')).code).toBe('SCRIPT_SIZE_LIMIT');
    expect(errorOf(() => run('xs: list[int] = [0]\nxs += xs\nxs += xs\no = 1\n', {}, {}, { o: 'int' }, { maxListLen: 3 })).code).toBe('SCRIPT_SIZE_LIMIT');
    expect(errorOf(() => run('x = zeros(100)\no = 1\n', {}, {}, { o: 'int' }, { maxBytes: 50 })).code).toBe('BYTES_SIZE_LIMIT');
    expect(errorOf(() => run('x = zeros(17000000)\no = 1\n', {}, {}, { o: 'int' }, { maxBytes: 1 << 30 })).code).toBe('BYTES_SIZE_LIMIT'); // bytesOps 상한보다 올릴 수 없다
    expect(errorOf(() => run('x = 1 << 100\no = 1\n', {}, {}, { o: 'int' }, { maxIntBits: 64 })).code).toBe('SCRIPT_SIZE_LIMIT');
    expect(errorOf(() => run('x = 2\nfor i in range(30):\n    x = x * x\no = 1\n')).code).toBe('SCRIPT_SIZE_LIMIT');
    expect(errorOf(() => run('for v in x:\n    pass\no = 1\n'.replace('x', 'h"00" * 2000000'))).code).toBe('SCRIPT_SIZE_LIMIT');
  });

  it('blocks와 to_ints가 만드는 목록도 한도를 지킨다', () => {
    expect(errorOf(() => run('x = blocks(h"00" * 2000000, 1)\no = 1\n')).code).toBe('SCRIPT_SIZE_LIMIT');
    expect(errorOf(() => run('x = to_ints(h"00" * 2000000)\no = 1\n')).code).toBe('SCRIPT_SIZE_LIMIT');
  });
});

describe('성능', () => {
  it('16바이트 블록 수천 개 규모의 반복이 빠르게 끝난다', () => {
    const t0 = Date.now();
    const r = run(
      'parts: list[bytes] = []\nfor i in range(5000):\n    parts += [to_bytes(i, 16) ^ key]\nout = concat(parts)\nn = len(out)\no = n\n',
      { key: new Uint8Array(16).fill(0xaa) }, { key: 'bytes' },
    );
    expect(r.o).toBe(80000n);
    expect(Date.now() - t0).toBeLessThan(2000);
  });

  it('목록에 10만 번 추가하는 반복이 제곱 시간이 아니다', () => {
    const t0 = Date.now();
    expect(run('xs: list[int] = []\nfor i in range(100000):\n    xs += [i]\no = len(xs)\n').o).toBe(100000n);
    expect(Date.now() - t0).toBeLessThan(2000);
  });
});

describe('KAT 벡터와 일관', () => {
  it('examples/kat/builtin-script가 존재하고 §4.2 필수 사례를 가진다', () => {
    const dir = join(__dirname, '../../../../examples/kat/builtin-script');
    const names = readdirSync(dir).filter((f) => f.endsWith('.json'));
    expect(names).toEqual(expect.arrayContaining(['examples.json', 'static-errors.json', 'limits.json']));
    const all = names.flatMap((f) => JSON.parse(readFileSync(join(dir, f), 'utf8')) as { name: string }[]);
    const text = all.map((v) => v.name).join('\n');
    expect(text).toContain('CMAC 서브키 RFC 4493');
    expect((text.match(/DES 키 홀수 패리티/g) ?? []).length).toBeGreaterThanOrEqual(3);
  });
});

describe('소스 점검', () => {
  it('해석기는 eval, Function, 동적 import를 쓰지 않는다', () => {
    const dir = join(__dirname, '../../src/script');
    for (const f of readdirSync(dir).filter((x) => x.endsWith('.ts'))) {
      const src = readFileSync(join(dir, f), 'utf8').replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*$/gm, '');
      expect(src, f).not.toMatch(/\beval\s*\(/);
      expect(src, f).not.toMatch(/new\s+Function\b/);
      expect(src, f).not.toMatch(/\bimport\s*\(/);
    }
  });
});

describe('f-string (§4.9)', () => {
  it('f는 따옴표가 바로 뒤따를 때만 접두사이고 변수 이름으로도 쓸 수 있다', () => {
    expect(run('f = 3\no = f + 1\n')).toEqual({ o: 4n });
  });

  it('오류 위치: 필드 안의 이름 오류는 원래 줄·열을 가리킨다', () => {
    const r = compile('x = 1\ns = f"ab{nope}"\no = 1\n', { inputs: [], outputs: [{ id: 'o', dataType: 'int' }] });
    expect(r.diagnostics[0]).toMatchObject({ line: 2, column: 10, code: 'SCRIPT_NAME_UNDEFINED' });
  });

  it('필드 하나가 1단계를 쓴다', () => {
    expect(errorOf(() => run('n = 1\ns = f"{n}{n}{n}"\no = 1\n', {}, {}, { o: 'int' }, { maxSteps: 2 })).code).toBe('SCRIPT_STEP_LIMIT');
  });
});
