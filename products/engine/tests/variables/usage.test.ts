import { describe, expect, it } from 'vitest';
import { defaultNodeRegistry } from 'nodecrypto-engine/registry/nodeRegistry';
import { Registry } from 'nodecrypto-engine/variables/registry';
import { collectUsage, usedNodeIds } from 'nodecrypto-engine/variables/usage';

const getDef = (t: string) => defaultNodeRegistry.get(t);
const e = (type: any, def: any, extra: any = {}) => ({ name: '', type, default: def, description: '', ...extra });
const ref = (p: string) => ({ $var: p });
const staticNode = (id: string, props: Record<string, any>, label = id) => ({ id, data: { nodeType: 'input-static-value', label, properties: props } });

const registry: Registry = {
  '$k.key': e('bytes', '00112233'),
  '$k.cur': e('bytes', '00', { current: 'aabb' }),
  '$s': e('string', 'hi'),
  '$b': e('bool', true),
};

describe('collectUsage', () => {
  it('참조가 없으면 빈 목록', () => {
    expect(collectUsage([staticNode('a', { type: 'bytes', valueBytes: '00' })], getDef, registry)).toEqual([]);
  });

  it('여러 노드가 같은 변수를 쓰면 사용처를 모은다 (경로순)', () => {
    const u = collectUsage(
      [
        staticNode('n2', { type: 'bytes', valueBytes: ref('$k.key') }, 'Two'),
        staticNode('n1', { type: 'bytes', valueBytes: ref('$k.key') }, 'One'),
        staticNode('n3', { type: 'bytes', valueBytes: ref('$k.cur') }),
      ],
      getDef,
      registry
    );
    expect(u.map((x) => x.path)).toEqual(['$k.cur', '$k.key']);
    const key = u[1];
    expect(key.sites.map((s) => s.nodeId)).toEqual(['n2', 'n1']);
    expect(key.sites[0]).toMatchObject({ nodeLabel: 'Two', slot: 'valueBytes', type: 'bytes' });
    expect(usedNodeIds(key)).toEqual(['n2', 'n1']);
  });

  it('상태: default 사용 중 / 정상(current 있음) / 미등록 / 타입 불일치', () => {
    const u = collectUsage(
      [
        staticNode('a', { type: 'bytes', valueBytes: ref('$k.key') }),
        staticNode('b', { type: 'bytes', valueBytes: ref('$k.cur') }),
        staticNode('c', { type: 'bytes', valueBytes: ref('$nope') }),
        staticNode('d', { type: 'bytes', valueBytes: ref('$s') }),
      ],
      getDef,
      registry
    );
    const st = Object.fromEntries(u.map((x) => [x.path, x.status]));
    expect(st).toEqual({ '$k.key': 'default', '$k.cur': 'ok', $nope: 'unregistered', $s: 'type_mismatch' });
    expect(u.find((x) => x.path === '$k.cur')!.value).toBe('aabb');
    expect(u.find((x) => x.path === '$nope')!.value).toBeUndefined();
  });

  it('여러 사용처의 상태는 가장 심각한 것을 대표로 한다', () => {
    const r: Registry = { '$x': e('string', 'v') };
    const u = collectUsage(
      [staticNode('a', { type: 'string', valueString: ref('$x') }), staticNode('b', { type: 'bytes', valueBytes: ref('$x') })],
      getDef,
      r
    );
    expect(u).toHaveLength(1);
    expect(u[0].status).toBe('type_mismatch');
    expect(u[0].sites.map((s) => s.status)).toEqual(['default', 'type_mismatch']);
    expect(u[0].types).toEqual(['string', 'bytes']);
  });

  it('숨겨진 필드(showWhen)의 참조도 센다 (D-17)', () => {
    const u = collectUsage([staticNode('a', { type: 'string', valueBytes: ref('$k.key') })], getDef, registry);
    expect(u.map((x) => x.path)).toEqual(['$k.key']);
  });

  it('ValueSet 행의 참조', () => {
    const node = {
      id: 'vs',
      data: {
        nodeType: 'input-value-set',
        label: 'Set',
        outputs: [{ id: 'r1', name: 'Row 1', dataType: 'bytes' }, { id: 'r2', name: 'Flag', dataType: 'bool' }],
        properties: { rows: { r1: { mode: 'fixed', value: ref('$k.key') }, r2: { mode: 'fixed', value: ref('$b') } } },
      },
    };
    const u = collectUsage([node], getDef, registry);
    expect(u.map((x) => [x.path, x.sites[0].slot, x.sites[0].slotLabel, x.status])).toEqual([
      ['$b', 'rows.r2', 'Flag', 'default'],
      ['$k.key', 'rows.r1', 'Row 1', 'default'],
    ]);
  });

  it('참조를 둘 수 없는 자리의 참조는 세지 않는다', () => {
    const node = { id: 'x', data: { nodeType: 'input-static-value', properties: { type: ref('$s') } } };
    expect(collectUsage([node], getDef, registry)).toEqual([]);
  });

  it('유효 값이 필드 규칙에 맞지 않으면 값 오류', () => {
    const r: Registry = { '$odd': e('bytes', 'abc') as any };
    const u = collectUsage([staticNode('a', { type: 'bytes', valueBytes: ref('$odd') })], getDef, r);
    expect(u[0].status).toBe('invalid_value');
  });
});
