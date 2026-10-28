import { describe, it, expect } from 'vitest';
import { validate } from '../../src/authoring/validate';
import { draftToPackage } from '../../src/authoring/draft';

// authoring.md §2.3: the `type` property sets the output type of Static Value, Random Value and User Input Dialog.
const draft = (type: string, node = 'input-static-value', extra: Record<string, any> = {}) => ({
  draft: 1,
  name: 'typed',
  nodes: [
    { id: 'v', type: node, props: { type, ...extra } },
    { id: 'out', type: 'workflow-output', inputs: [{ id: 'x', dataType: type, name: 'X' }] },
  ],
  edges: [{ from: `v.${node === 'input-random' ? 'bytes' : node === 'input-dialog' ? 'string' : 'value'}`, to: 'out.x' }],
});

describe('type-driven output ports', () => {
  it.each(['bytes', 'string', 'int', 'bool'])('Static Value of type %s validates and expands with that port type', (type) => {
    const d = draft(type);
    expect(validate(d).issues).toEqual([]);
    const r: any = draftToPackage(d);
    expect(r.ok).toBe(true);
    expect(r.package.workflow.nodes[0].data.outputs[0].dataType).toBe(type);
    expect(validate(r.package).issues).toEqual([]); // the saved package passes too
  });

  it.each(['input-random', 'input-dialog'])('%s follows its type property', (node) => {
    const d = draft('int', node);
    expect(validate(d).issues).toEqual([]);
    expect((draftToPackage(d) as any).package.workflow.nodes[0].data.outputs[0].dataType).toBe('int');
  });

  it('a package whose port type disagrees with the type property is still PORT_MISMATCH', () => {
    const r: any = draftToPackage(draft('string'));
    r.package.workflow.nodes[0].data.outputs[0].dataType = 'bytes';
    expect(validate(r.package).issues.map((i) => i.code)).toContain('PORT_MISMATCH');
  });

  it('a draft that writes the port list with the default type for another type is PORT_MISMATCH', () => {
    const d: any = draft('string');
    d.nodes[0].outputs = [{ id: 'value', dataType: 'bytes' }];
    expect(validate(d).issues.map((i) => i.code)).toContain('PORT_MISMATCH');
  });

  it('connecting a string Static Value to a bytes-only input is still rejected', () => {
    const d: any = draft('string');
    d.nodes[1] = { id: 'h', type: 'converter-bytes-to-hex' };
    d.edges = [{ from: 'v.value', to: 'h.bytes' }];
    expect(validate(d).issues.map((i) => i.code)).toContain('EDGE_TYPE_MISMATCH');
  });

  it('a wrong type value is reported as before', () => {
    expect(validate(draft('float')).issues.map((i) => i.code)).toContain('PROP_INVALID_VALUE');
  });
});
