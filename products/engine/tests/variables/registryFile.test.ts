import { describe, it, expect } from 'vitest';
import { Registry, addVariable } from 'nodecrypto-engine/variables/registry';
import { applyImport, exportRegistry, parseRegistryFile, planImport } from 'nodecrypto-engine/variables/registryFile';

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
const file = (variables: any) => ({ format: 'nodecrypto-values', formatVersion: 1, variables });
const parse = (x: any) => {
  const r = parseRegistryFile(x);
  if (!r.ok) throw new Error(r.message);
  return r.value;
};
const plan = (r: Registry, f: any, target: string) => {
  const p = planImport(r, parse(f), target);
  if (!p.ok) throw new Error(p.message);
  return p.value;
};

const reg = build({
  '$a.b.x': e('int', '1'),
  '$a.b.c.A': e('bytes', 'aa', { current: 'bb', name: 'N', description: 'D' }),
  '$a.z': e('bool', true),
  $T: e('string', 'hi'),
});

describe('내보내기', () => {
  it('전체는 루트 기준', () => {
    expect(Object.keys(exportRegistry(reg).variables)).toEqual(['T', 'a.b.c.A', 'a.b.x', 'a.z']);
  });
  it('하위 경로는 부모 기준 상대 경로', () => {
    expect(Object.keys(exportRegistry(reg, '$a.b').variables)).toEqual(['b.c.A', 'b.x']);
    expect(Object.keys(exportRegistry(reg, '$a.b.c.A').variables)).toEqual(['A']);
    expect(Object.keys(exportRegistry(reg, '$T').variables)).toEqual(['T']);
    expect(Object.keys(exportRegistry(reg, '$a').variables)).toEqual(['a.b.c.A', 'a.b.x', 'a.z']);
  });
  it('형식 필드, current는 있을 때만', () => {
    const f = exportRegistry(reg, '$T');
    expect(f).toMatchObject({ format: 'nodecrypto-values', formatVersion: 1 });
    expect('current' in f.variables.T).toBe(false);
  });
});

describe('가져오기', () => {
  it('대상 경로 아래에 주입한다', () => {
    const f = file({ 'b.c.A': e('bytes', 'aa') });
    expect(plan({}, f, '$').items[0].path).toBe('$b.c.A');
    expect(plan({}, f, '$P').items[0].path).toBe('$P.b.c.A');
    expect(plan({}, f, '$P.Q').items[0].path).toBe('$P.Q.b.c.A');
  });
  it('신규/충돌/겹침 요약과 정책', () => {
    const base = build({ $a: e('int', '1', { current: '5' }), '$g.x': e('int', '1'), $n: e('int', '1') });
    const f = file({ a: e('int', '2'), g: e('int', '4'), 'n.sub': e('int', '3'), k: e('int', '5') });
    const p = plan(base, f, '$');
    expect(p.counts).toEqual({ new: 1, conflict: 1, overlap: 2 });
    expect(p.items.map((i) => i.status)).toEqual(['conflict', 'overlap', 'overlap', 'new']);

    const skip = applyImport(p, 'skip').registry;
    expect(Object.keys(skip).sort()).toEqual(['$a', '$g.x', '$k', '$n']);
    expect(skip.$a.default).toBe('1');

    const over = applyImport(p, 'overwrite').registry;
    expect(over.$a).toEqual(e('int', '2')); // current도 사라진다
    expect(over['$g.x']).toBeDefined(); // 겹침은 덮어쓰지 않는다
    expect('$g' in over).toBe(false);
    expect('$n.sub' in over).toBe(false);
    expect(base.$a.default).toBe('1'); // 원본 불변
  });
  it('왕복: export → import 동일', () => {
    const p = plan({}, JSON.stringify(exportRegistry(reg)), '$');
    expect(applyImport(p, 'skip').registry).toEqual(reg);
  });
  it('하위 경로 왕복은 내보낸 폴더 이름이 남는다', () => {
    const p = plan({}, exportRegistry(reg, '$a.b'), '$P');
    expect(Object.keys(applyImport(p, 'skip').registry).sort()).toEqual(['$P.b.c.A', '$P.b.x']);
  });
  it('잘못된 대상 경로', () => {
    expect(planImport({}, parse(file({})), 'P')).toMatchObject({ ok: false, code: 'INVALID_PATH' });
  });
});

describe('파일 읽기 검증', () => {
  const ok = file({ A: e('int', '1') });
  const code = (x: any) => {
    const r = parseRegistryFile(x);
    return r.ok ? 'OK' : r.code;
  };
  it('형식과 버전', () => {
    expect(code(ok)).toBe('OK');
    expect(code(JSON.stringify(ok))).toBe('OK');
    expect(code('not json')).toBe('VREG_UNSUPPORTED_FORMAT');
    expect(code({ ...ok, format: 'x' })).toBe('VREG_UNSUPPORTED_FORMAT');
    expect(code(null)).toBe('VREG_UNSUPPORTED_FORMAT');
    expect(code({ ...ok, formatVersion: 2 })).toBe('VREG_UNSUPPORTED_VERSION');
  });
  it('경로', () => {
    for (const p of ['$A', 'a..b', '1a', 'a b', '']) expect(code(file({ [p]: e('int', '1') }))).toBe('VREG_INVALID_PATH');
  });
  it('겹침', () => {
    expect(code(file({ a: e('int', '1'), 'a.b': e('int', '1') }))).toBe('VREG_PATH_CONFLICT');
  });
  it('값', () => {
    expect(code(file({ A: e('bytes', 'abc') }))).toBe('VREG_INVALID_VALUE');
    expect(code(file({ A: { type: 'int' } }))).toBe('VREG_INVALID_VALUE');
    expect(code(file({ A: e('float', '1') }))).toBe('VREG_INVALID_VALUE');
    expect(code(file({ A: e('int', '1', { current: 'x' }) }))).toBe('VREG_INVALID_VALUE');
  });
  it('오류 메시지에 경로를 포함한다', () => {
    const r = parseRegistryFile(file({ 'k.A': e('bytes', 'abc') }));
    expect(!r.ok && r.message).toContain('k.A');
  });
  it('검증 순서: 경로 오류가 값 오류보다 먼저', () => {
    expect(code(file({ '1a': e('bytes', 'zz') }))).toBe('VREG_INVALID_PATH');
  });
});
