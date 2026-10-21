import { describe, it, expect } from 'vitest';
import {
  Registry,
  addVariable,
  effectiveValue,
  findPathConflict,
  isValidPath,
  listChildren,
  listGroups,
  moveSubtree,
  parsePath,
  removeSubtree,
  search,
  updateVariable,
  validateValue,
} from 'nodecrypto-engine/variables/registry';

const e = (type: any, def: any, extra: any = {}) => ({ name: '', type, default: def, description: '', ...extra });
const build = (paths: Record<string, any>): Registry => {
  let r: Registry = {};
  for (const [p, entry] of Object.entries(paths)) {
    const res = addVariable(r, p, entry);
    if (!res.ok) throw new Error(res.message);
    r = res.value;
  }
  return r;
};

describe('경로', () => {
  it('유효한 경로', () => {
    expect(parsePath('$A')).toEqual(['A']);
    expect(parsePath('$a.b.c.A')).toEqual(['a', 'b', 'c', 'A']);
    expect(isValidPath('$_x1.Y2')).toBe(true);
  });
  it.each(['$', '', 'A', 'a.b', '$a..b', '$a.', '$.a', '$1a', '$a.1b', '$a b', '$a.b c', '$a-b', '$가'])('무효: %j', (p) => {
    expect(isValidPath(p)).toBe(false);
  });
  it('대소문자를 구분한다', () => {
    const r = build({ $a: e('int', '1'), $A: e('int', '2') });
    expect(Object.keys(r)).toHaveLength(2);
  });
  it('변수와 그룹은 배타적이다', () => {
    const r = build({ '$a.b': e('int', '1') });
    expect(addVariable(r, '$a.b.x', e('int', '1'))).toMatchObject({ ok: false, code: 'PATH_CONFLICT' });
    const g = build({ '$a.b.x': e('int', '1') });
    expect(addVariable(g, '$a.b', e('int', '1'))).toMatchObject({ ok: false, code: 'PATH_CONFLICT' });
    expect(addVariable(g, '$a.b.x', e('int', '1'))).toMatchObject({ ok: false, code: 'PATH_EXISTS' });
    expect(addVariable(g, '$a.b.y', e('int', '1')).ok).toBe(true);
    expect(addVariable(g, 'bad', e('int', '1'))).toMatchObject({ ok: false, code: 'INVALID_PATH' });
  });
  it('findPathConflict', () => {
    expect(findPathConflict(['$a', '$b.c'])).toBeNull();
    expect(findPathConflict(['$a', '$a.b'])).toBe('$a.b');
  });
});

describe('값 검증', () => {
  it('bytes: 정규화와 오류', () => {
    expect(validateValue('bytes', 'AA bb\n01')).toEqual({ ok: true, value: 'aabb01' });
    expect(validateValue('bytes', '')).toEqual({ ok: true, value: '' });
    expect(validateValue('bytes', 'abc').ok).toBe(false);
    expect(validateValue('bytes', 'zz').ok).toBe(false);
    expect(validateValue('bytes', 12).ok).toBe(false);
  });
  it('int: 부호, 정규형, 큰 수', () => {
    expect(validateValue('int', '-5')).toEqual({ ok: true, value: '-5' });
    expect(validateValue('int', '007')).toEqual({ ok: true, value: '7' });
    expect(validateValue('int', '-0')).toEqual({ ok: true, value: '0' });
    expect(validateValue('int', 42)).toEqual({ ok: true, value: '42' });
    const big = (2n ** 64n).toString();
    expect(validateValue('int', big)).toEqual({ ok: true, value: big });
    expect(validateValue('int', '9007199254740993')).toEqual({ ok: true, value: '9007199254740993' }); // 2^53+1 정밀도 보존
    for (const bad of ['', '1.5', '0x10', 'abc', '+3', '1e3', true, 1.5]) expect(validateValue('int', bad).ok).toBe(false);
  });
  it('bool/string', () => {
    expect(validateValue('bool', true).ok).toBe(true);
    expect(validateValue('bool', 'true').ok).toBe(false);
    expect(validateValue('string', '').ok).toBe(true);
    expect(validateValue('string', 1).ok).toBe(false);
  });
  it('유효 값은 current ?? default', () => {
    expect(effectiveValue(e('bytes', 'aa'))).toBe('aa');
    expect(effectiveValue(e('bytes', 'aa', { current: 'bb' }))).toBe('bb');
    expect(effectiveValue(e('bool', true, { current: false }))).toBe(false);
  });
  it('저장 시 검증 실패는 거부한다', () => {
    expect(addVariable({}, '$a', e('bytes', 'abc'))).toMatchObject({ ok: false, code: 'INVALID_VALUE' });
    expect(addVariable({}, '$a', { type: 'bytes' })).toMatchObject({ ok: false });
    expect(addVariable({}, '$a', e('float', '1'))).toMatchObject({ ok: false, code: 'INVALID_TYPE' });
    expect(addVariable({}, '$a', e('int', '1', { current: 'x' }))).toMatchObject({ ok: false });
  });
});

describe('수정', () => {
  const r = build({ $a: e('bytes', 'aa', { current: 'bb' }) });
  it('current를 지우면 default 사용 중', () => {
    const u = updateVariable(r, '$a', { current: null });
    expect(u.ok && 'current' in u.value.$a).toBe(false);
    expect(r.$a.current).toBe('bb'); // 원본 불변
  });
  it('타입 변경은 값을 다시 검증한다', () => {
    expect(updateVariable(r, '$a', { type: 'int' })).toMatchObject({ ok: false });
    const u = updateVariable(r, '$a', { type: 'string', default: 'x', current: null });
    expect(u.ok && u.value.$a).toMatchObject({ type: 'string', default: 'x' });
  });
  it('없는 변수', () => {
    expect(updateVariable(r, '$z', { name: 'n' })).toMatchObject({ ok: false, code: 'NOT_FOUND' });
  });
});

describe('이동·삭제', () => {
  const r = build({
    '$a.b.x': e('int', '1'),
    '$a.b.y': e('int', '2'),
    '$a.c': e('int', '3'),
    $z: e('int', '4'),
  });
  it('그룹 이동은 하위 전체의 경로가 바뀐다', () => {
    const m = moveSubtree(r, '$a.b', '$q.w');
    expect(m.ok).toBe(true);
    if (!m.ok) return;
    expect(Object.keys(m.value.registry).sort()).toEqual(['$a.c', '$q.w.x', '$q.w.y', '$z']);
    expect(m.value.moved).toEqual({ '$a.b.x': '$q.w.x', '$a.b.y': '$q.w.y' });
    expect(Object.keys(r)).toHaveLength(4); // 원본 불변
  });
  it('변수명 변경도 이동', () => {
    const m = moveSubtree(r, '$z', '$zz');
    expect(m.ok && m.value.registry.$zz).toMatchObject({ default: '4' });
  });
  it('대상 충돌과 그룹 합치기를 거부한다', () => {
    expect(moveSubtree(r, '$z', '$a.c')).toMatchObject({ ok: false, code: 'TARGET_EXISTS' });
    expect(moveSubtree(r, '$a.b', '$a.c')).toMatchObject({ ok: false, code: 'TARGET_EXISTS' });
    const g = build({ '$a.x': e('int', '1'), '$b.y': e('int', '2') });
    expect(moveSubtree(g, '$a', '$b')).toMatchObject({ ok: false, code: 'TARGET_EXISTS' }); // 합치지 않는다
  });
  it('배타 규칙을 깨는 이동을 거부한다', () => {
    expect(moveSubtree(r, '$z', '$a.c.d')).toMatchObject({ ok: false, code: 'PATH_CONFLICT' });
  });
  it('자기 하위로 이동 거부', () => {
    expect(moveSubtree(r, '$a', '$a.b2')).toMatchObject({ ok: false, code: 'MOVE_INTO_SELF' });
  });
  it('없는 경로·잘못된 경로', () => {
    expect(moveSubtree(r, '$nope', '$x')).toMatchObject({ ok: false, code: 'NOT_FOUND' });
    expect(moveSubtree(r, '$z', 'x')).toMatchObject({ ok: false, code: 'INVALID_PATH' });
  });
  it('유일한 자식 변수를 부모 그룹 자리로 옮길 수 있다', () => {
    const g = build({ '$a.b': e('int', '1') });
    expect(moveSubtree(g, '$a.b', '$a').ok).toBe(true);
  });
  it('삭제 범위', () => {
    const g = removeSubtree(r, '$a.b');
    expect(g.ok && g.value.removed.sort()).toEqual(['$a.b.x', '$a.b.y']);
    expect(g.ok && Object.keys(g.value.registry).sort()).toEqual(['$a.c', '$z']);
    const v = removeSubtree(r, '$z');
    expect(v.ok && Object.keys(v.value.registry)).toHaveLength(3);
    const all = removeSubtree(r, '$');
    expect(all.ok && Object.keys(all.value.registry)).toHaveLength(0);
    expect(removeSubtree(r, '$a.bb')).toMatchObject({ ok: false, code: 'NOT_FOUND' }); // 접두어는 구간 단위
  });
});

describe('조회·검색', () => {
  const r = build({
    '$kcv.key': e('bytes', 'aa', { name: '테스트 키', description: 'KCV 예제' }),
    '$kcv.rounds': e('int', '10'),
    '$kcv.sub.iv': e('bytes', '00'),
    $flag: e('bool', true, { description: 'Debug switch' }),
  });
  it('그룹·자식', () => {
    expect(listGroups(r)).toEqual(['$kcv', '$kcv.sub']);
    expect(listChildren(r, '$').map((c) => `${c.kind}:${c.path}`)).toEqual(['group:$kcv', 'variable:$flag']);
    expect(listChildren(r, '$kcv').map((c) => `${c.kind}:${c.path}`)).toEqual(['group:$kcv.sub', 'variable:$kcv.key', 'variable:$kcv.rounds']);
  });
  it('경로·이름·설명 부분 일치', () => {
    expect(search(r, 'rounds').map((x) => x.path)).toEqual(['$kcv.rounds']);
    expect(search(r, '테스트').map((x) => x.path)).toEqual(['$kcv.key']);
    expect(search(r, 'DEBUG').map((x) => x.path)).toEqual(['$flag']);
    expect(search(r, '')).toHaveLength(4);
  });
  it('타입 필터', () => {
    expect(search(r, '', { type: 'bytes' }).map((x) => x.path)).toEqual(['$kcv.key', '$kcv.sub.iv']);
    expect(search(r, 'kcv', { type: 'int' }).map((x) => x.path)).toEqual(['$kcv.rounds']);
  });
});
