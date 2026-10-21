import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { validate } from '../../src/authoring/validate';
import { draftToPackage } from '../../src/authoring/draft';
import { formatMsg } from '../../src/messages';

const base = () => ({
  draft: 1,
  name: 'aes-gcm',
  nodes: [
    { id: 'in', type: 'workflow-input', outputs: [
      { id: 'key', dataType: 'bytes', name: 'Key', constraint: { lengths: [32] } },
      { id: 'nonce', dataType: 'bytes', name: 'Nonce' },
      { id: 'pt', dataType: 'bytes', name: 'Plaintext' },
    ] },
    { id: 'aes', type: 'symmetric-aes-encrypt', props: { mode: 'GCM' } },
    { id: 'out', type: 'workflow-output', inputs: [{ id: 'ct', dataType: 'bytes' }, { id: 'tag', dataType: 'bytes' }] },
  ] as any[],
  edges: [
    { from: 'in.key', to: 'aes.key' },
    { from: 'in.nonce', to: 'aes.nonce' },
    { from: 'in.pt', to: 'aes.plaintext' },
    { from: 'aes.ciphertext', to: 'out.ct' },
    { from: 'aes.tag', to: 'out.tag' },
  ] as any[],
} as any);

/** Applies `edit` to a valid draft and returns the issues. */
const check = (edit: (d: any) => void) => {
  const d = base();
  edit(d);
  return validate(d).issues;
};
const codes = (edit: (d: any) => void) => check(edit).map((i) => i.code);
const find = (edit: (d: any) => void, code: string) => check(edit).find((i) => i.code === code)!;

describe('validate: valid input', () => {
  it('accepts a correct draft', () => {
    expect(validate(base())).toEqual({ ok: true, kind: 'draft', issues: [] });
  });

  it('accepts every file in examples/workflows', () => {
    const dir = new URL('../../../../examples/workflows/', import.meta.url);
    const files = readdirSync(dir).filter((f) => f.endsWith('.ncw'));
    expect(files.length).toBeGreaterThan(0);
    for (const f of files) {
      const r = validate(JSON.parse(readFileSync(new URL(f, dir), 'utf8')));
      expect({ f, kind: r.kind, issues: r.issues.map((i) => [i.code, i.path]) }).toEqual({ f, kind: 'package', issues: [] });
    }
  });

  it('accepts the package expanded from a draft', () => {
    const r = draftToPackage(base());
    expect(r.ok && validate(r.package).ok).toBe(true);
  });
});

describe('validate: input kind', () => {
  it('rejects input that is neither a draft nor a package', () => {
    expect(validate({}).issues[0].code).toBe('DRAFT_BAD_STRUCTURE');
    expect(validate(null).ok).toBe(false);
  });

  it('reports a broken package envelope with its PKG code', () => {
    const r = validate({ format: 'nodecrypto', formatVersion: 99 });
    expect(r.kind).toBe('package');
    expect(r.issues[0].code).toBe('PKG_UNSUPPORTED_VERSION');
  });

  it('reports structural draft problems before semantic ones', () => {
    expect(codes((d) => { d.nodes[1].type = 'nope'; })).toEqual(['NODE_TYPE_UNKNOWN']);
  });
});

describe('validate: properties', () => {
  it('PROP_UNKNOWN suggests the nearest property', () => {
    const i = find((d) => { d.nodes[1].props = { mdoe: 'GCM' }; }, 'PROP_UNKNOWN');
    expect(i.path).toBe('nodes[1].props.mdoe');
    expect(i.hint).toContain('mode');
  });

  it('PROP_INVALID_VALUE: select outside the options, with the nearest option', () => {
    const i = find((d) => { d.nodes[1].props = { mode: 'GMC' }; }, 'PROP_INVALID_VALUE');
    expect(i.path).toBe('nodes[1].props.mode');
    expect(i.hint).toContain('GCM');
  });

  it('PROP_INVALID_VALUE: odd-length hex, wrong boolean type', () => {
    expect(codes((d) => { d.nodes.push({ id: 's', type: 'input-static-value', props: { type: 'bytes', valueBytes: 'abc' } }); })).toContain('PROP_INVALID_VALUE');
    expect(codes((d) => { d.nodes[1].props = { mode: 'GCM', errorUnify: 'yes' }; })).toContain('PROP_INVALID_VALUE');
  });

  it('PROP_HIDDEN: a hidden property set to a non-default value', () => {
    const i = find((d) => { d.nodes[1].props = { mode: 'GCM', errorUnifyCode: 'E1' }; }, 'PROP_HIDDEN');
    expect(i.hint).toContain('errorUnify=true');
    expect(codes((d) => { d.nodes[1].props = { mode: 'GCM', errorUnify: true, errorUnifyCode: 'E1' }; })).not.toContain('PROP_HIDDEN');
  });

  it('PROP_HIDDEN: RSA saltLength is only visible with the PSS scheme', () => {
    const rsa = (props: Record<string, unknown>) => codes((d) => { d.nodes.push({ id: 'r', type: 'asymmetric-rsa-sign', props }); });
    expect(rsa({ scheme: 'PKCS1-v1_5', saltLength: 20 })).toContain('PROP_HIDDEN');
    expect(rsa({ scheme: 'PKCS1-v1_5' })).not.toContain('PROP_HIDDEN');
    expect(rsa({ scheme: 'PSS', saltLength: 20 })).not.toContain('PROP_HIDDEN');
    expect(rsa({ saltLength: 20 })).not.toContain('PROP_HIDDEN');
  });

  it('VARIABLE_NOT_ALLOWED: reference in a select without a variable type', () => {
    expect(codes((d) => { d.nodes[1].props = { mode: { $var: '$a.mode' } }; })).toContain('VARIABLE_NOT_ALLOWED');
  });

  it('VARIABLE_UNDEFINED and VARIABLE_TYPE_MISMATCH in a closed draft', () => {
    const withRef = (variables: any) => (d: any) => {
      d.nodes.push({ id: 's', type: 'input-static-value', props: { type: 'bytes', valueBytes: { $var: '$a.k' } } });
      d.variables = variables;
    };
    expect(codes(withRef({}))).toContain('VARIABLE_UNDEFINED');
    expect(codes(withRef({ '$a.k': { type: 'string' } }))).toContain('VARIABLE_TYPE_MISMATCH');
    expect(codes(withRef({ '$a.k': { type: 'bytes' } }))).toEqual([]);
  });
});

describe('validate: ports', () => {
  it('PORT_MISMATCH: written list differs from the definition', () => {
    const i = find((d) => { d.nodes[1].inputs = [{ id: 'plaintext', dataType: 'bytes' }]; }, 'PORT_MISMATCH');
    expect(i.hint).toContain('key:bytes, plaintext:bytes, nonce:bytes, aad:bytes');
  });

  it('PORT_COUNT_OUT_OF_RANGE: Bitwise Logic needs two inputs', () => {
    expect(codes((d) => { d.nodes.push({ id: 'x', type: 'utility-bitwise', inputs: [{ id: 'in_1', dataType: 'bytes' }] }); })).toContain('PORT_COUNT_OUT_OF_RANGE');
  });

  it('PORT_ID_DUPLICATE, PORT_ID_INVALID', () => {
    expect(codes((d) => { d.nodes[0].outputs.push({ id: 'key', dataType: 'bytes' }); })).toContain('PORT_ID_DUPLICATE');
    expect(codes((d) => { d.nodes[0].outputs.push({ id: 'a.b', dataType: 'bytes' }); })).toContain('PORT_ID_INVALID');
  });

  it('PORT_TYPE_INVALID: any on a Workflow Input', () => {
    expect(codes((d) => { d.nodes[0].outputs[2].dataType = 'any'; })).toContain('PORT_TYPE_INVALID');
  });

  it('PORT_KEY_AMBIGUOUS: a unique name equal to another port id', () => {
    const ambiguous = (d: any) => {
      d.nodes[0].outputs = [
        { id: 'a', dataType: 'bytes', name: 'b' },
        { id: 'b', dataType: 'bytes', name: 'c' },
        { id: 'x', dataType: 'bytes', name: 'c' },
      ];
      d.edges = [];
      d.nodes.length = 1;
    };
    expect(codes(ambiguous)).toContain('PORT_KEY_AMBIGUOUS');
  });

  it('PORT_CONSTRAINT_INVALID, PORT_DEFAULT_INVALID, PORT_FIELD_NOT_ALLOWED', () => {
    expect(codes((d) => { d.nodes[0].outputs[0].constraint = { lengths: ['x'] }; })).toContain('PORT_CONSTRAINT_INVALID');
    expect(codes((d) => { d.nodes[0].outputs[0].defaultValue = 'zz'; })).toContain('PORT_DEFAULT_INVALID');
    expect(codes((d) => { d.nodes[2].inputs[0].constraint = { min: 1 }; })).toContain('PORT_FIELD_NOT_ALLOWED');
  });

  it('PORTS_DERIVATION_MISMATCH: ValueSet without its set port, bad Script port id', () => {
    expect(codes((d) => {
      d.nodes.push({ id: 'vs', type: 'input-value-set', props: { rows: { out_1: { mode: 'fixed', value: 'aa' } } }, outputs: [{ id: 'out_1', dataType: 'bytes' }] });
    })).toContain('PORTS_DERIVATION_MISMATCH');
    expect(codes((d) => {
      d.nodes.push({ id: 'sc', type: 'utility-script', props: { code: 'pass\n' }, inputs: [{ id: 'for', dataType: 'bytes' }], outputs: [] });
    })).toContain('PORTS_DERIVATION_MISMATCH');
  });

  it('accepts a ValueSet + Switch pair written by the rules', () => {
    expect(codes((d) => {
      d.nodes.push(
        { id: 'vs', type: 'input-value-set', props: { rows: { out_1: { mode: 'fixed', value: 'aa' } } }, outputs: [{ id: 'out_1', dataType: 'bytes', name: 'Row' }, { id: 'set', dataType: 'set' }] },
        { id: 'sw', type: 'switch', props: { activeInput: 'in_1' }, inputs: [{ id: 'in_1', dataType: 'set' }], outputs: [{ id: 'out_1', dataType: 'bytes', name: 'Row' }] },
      );
      d.edges.push({ from: 'vs.set', to: 'sw.in_1' });
    })).toEqual([]);
  });

  it('Switch outputs must copy the baseline ValueSet', () => {
    expect(codes((d) => {
      d.nodes.push(
        { id: 'vs', type: 'input-value-set', props: { rows: { out_1: { mode: 'fixed', value: 'aa' } } }, outputs: [{ id: 'out_1', dataType: 'bytes', name: 'Row' }, { id: 'set', dataType: 'set' }] },
        { id: 'sw', type: 'switch', inputs: [{ id: 'in_1', dataType: 'set' }], outputs: [] },
      );
      d.edges.push({ from: 'vs.set', to: 'sw.in_1' });
    })).toContain('PORTS_DERIVATION_MISMATCH');
  });
});

describe('validate: connections and graph', () => {
  it('EDGE_PORT_UNKNOWN lists the ports of the node', () => {
    const i = find((d) => { d.edges[0].to = 'aes.kay'; }, 'EDGE_PORT_UNKNOWN');
    expect(i.path).toBe('edges[0].to');
    expect(i.hint).toContain('key, plaintext');
  });

  it('EDGE_PORT_HIDDEN says when the port is visible', () => {
    const i = find((d) => { d.nodes[1].props = { mode: 'ECB' }; }, 'EDGE_PORT_HIDDEN');
    expect(i.hint).toMatch(/mode=/);
  });

  it('EDGE_DIRECTION: from an input port', () => {
    expect(codes((d) => { d.edges[0].from = 'aes.key'; })).toContain('EDGE_DIRECTION');
  });

  it('EDGE_TYPE_MISMATCH: string into bytes, set into bytes', () => {
    expect(codes((d) => { d.nodes[0].outputs[2].dataType = 'string'; })).toContain('EDGE_TYPE_MISMATCH');
  });

  it('EDGE_INPUT_MULTIPLE', () => {
    expect(codes((d) => { d.edges.push({ from: 'in.nonce', to: 'aes.key' }); })).toContain('EDGE_INPUT_MULTIPLE');
  });

  it('GRAPH_CYCLE', () => {
    expect(codes((d) => {
      d.nodes = [
        { id: 'c1', type: 'utility-concat', inputs: [{ id: 'p', dataType: 'bytes' }] },
        { id: 'c2', type: 'utility-concat', inputs: [{ id: 'p', dataType: 'bytes' }] },
      ];
      d.edges = [{ from: 'c1.combined', to: 'c2.p' }, { from: 'c2.combined', to: 'c1.p' }];
    })).toContain('GRAPH_CYCLE');
  });

  it('INPUT_REQUIRED_MISSING', () => {
    const i = find((d) => { d.edges.splice(0, 1); }, 'INPUT_REQUIRED_MISSING');
    expect(i.msg.params).toMatchObject({ node: 'aes', port: 'key' });
  });

  it('NODE_DESIGN_RULE: Value Comparator with different types', () => {
    const i = find((d) => {
      d.nodes[0].outputs.push({ id: 'n', dataType: 'int' });
      d.nodes.push({ id: 'cmp', type: 'utility-compare' });
      d.edges.push({ from: 'in.key', to: 'cmp.a' }, { from: 'in.n', to: 'cmp.b' });
    }, 'NODE_DESIGN_RULE');
    expect(i.path).toBe('nodes[3]');
    expect(formatMsg(i.msg)).toContain('bytes');
  });

  it('reports several problems in one pass with draft paths', () => {
    const r = check((d) => {
      d.nodes[1].props = { mode: 'GMC' };
      d.edges[0].to = 'aes.kay';
      d.edges.splice(1, 1);
    });
    expect(r.map((i) => [i.code, i.path])).toEqual(expect.arrayContaining([
      ['PROP_INVALID_VALUE', 'nodes[1].props.mode'],
      ['EDGE_PORT_UNKNOWN', 'edges[0].to'],
    ]));
  });
});

describe('validate: packages', () => {
  const pkg = () => {
    const r = draftToPackage(base());
    if (!r.ok) throw new Error('draft');
    return JSON.parse(JSON.stringify(r.package));
  };

  it('uses package paths and keeps hidden-property values of saved files', () => {
    const p = pkg();
    p.workflow.nodes[1].data.properties.errorUnifyCode = 'LEFTOVER';
    p.workflow.nodes[1].data.properties.legacyKey = 1;
    expect(validate(p).issues).toEqual([]);
    p.workflow.edges[0].targetHandle = 'kay';
    const i = validate(p).issues.find((x) => x.code === 'EDGE_PORT_UNKNOWN')!;
    expect(i.path).toBe('workflow.edges[0].targetHandle');
  });

  it('compares fixed ports regardless of order, but not a different set', () => {
    const p = pkg();
    const aes = p.workflow.nodes[1].data;
    aes.inputs.reverse();
    expect(validate(p).issues).toEqual([]);
    const dropped = aes.inputs.pop();
    expect(validate(p).issues.map((i: any) => i.code)).toContain('PORT_MISMATCH');
    aes.inputs.push({ ...dropped, dataType: 'string' });
    expect(validate(p).issues.map((i: any) => i.code)).toContain('PORT_MISMATCH');
  });

  it('still catches wrong values, hidden ports and missing inputs', () => {
    const p = pkg();
    p.workflow.nodes[1].data.properties.mode = 'GMC';
    p.workflow.edges.splice(0, 1);
    const got = validate(p).issues.map((i) => i.code);
    expect(got).toContain('PROP_INVALID_VALUE');
    expect(got).toContain('INPUT_REQUIRED_MISSING');
  });
});

describe('validate: Script node code', () => {
  const withScript = (code: string) => (d: any) => {
    d.nodes.push({ id: 's', type: 'utility-script', props: { code },
      inputs: [{ id: 'x', dataType: 'bytes' }], outputs: [{ id: 'y', dataType: 'bytes' }] });
    d.edges.push({ from: 'in.pt', to: 's.x' });
  };
  const diag = (code: string) => check(withScript(code)).filter((i) => i.code === 'SCRIPT_DIAGNOSTIC');

  it('accepts a correct script', () => {
    expect(check(withScript('y = x + h"00"\n'))).toEqual([]);
  });

  it('reports a syntax error with its line and column', () => {
    const d = diag('y = x +\n');
    expect(d.length).toBeGreaterThan(0);
    expect(d[0].path).toBe('nodes[3].props.code');
    expect(formatMsg(d[0].msg)).toMatch(/line 1:\d+/);
  });

  it('reports an unknown function, a type error and an unassigned output', () => {
    expect(diag('y = nope(x)\n').length).toBeGreaterThan(0);
    expect(diag('y = 1\n').length).toBeGreaterThan(0);
    expect(diag('z = x\n').length).toBeGreaterThan(0);
  });

  it('reports at most 5 issues per node', () => {
    const n = diag('a = \n'.repeat(20)).length;
    expect(n).toBeGreaterThan(0);
    expect(n).toBeLessThanOrEqual(5);
  });
});

describe('validate: portNames', () => {
  const names = (portNames: any, props?: any) => (d: any) => {
    d.nodes[1].portNames = portNames;
    if (props) d.nodes[1].props = { ...d.nodes[1].props, ...props };
  };
  const at = (e: (d: any) => void) => check(e).map((i) => [i.code, i.path]);

  it('accepts good names, directions and same-name input/output', () => {
    expect(check(names({ key: 'Session Key', plaintext: 'Payload', ciphertext: 'Payload', 'outputs.tag': 'Auth Tag' }))).toEqual([]);
  });

  it('PORT_NAME_UNKNOWN_PORT: unknown id, hidden port, variable port', () => {
    expect(at(names({ nope: 'X' }))).toEqual([['PORT_NAME_UNKNOWN_PORT', 'nodes[1].portNames.nope']]);
    const hidden = find(names({ iv: 'IV' }, { mode: 'ECB', padding: 'None' }), 'PORT_NAME_UNKNOWN_PORT');
    expect(hidden.hint).toContain('mode');
    expect(codes((d) => { d.nodes[0].portNames = { key: 'K' }; })).toEqual(['PORT_NAME_UNKNOWN_PORT']); // Workflow Input: variable side
    expect(codes((d) => { d.nodes[1].portNames = { 'inputs.tag': 'T' }; })).toEqual(['PORT_NAME_UNKNOWN_PORT']); // tag is an output
  });

  it('PORT_NAME_AMBIGUOUS: a bare id on both sides', () => {
    const d: any = {
      draft: 1, name: 'cc', nodes: [{ id: 'c', type: 'symmetric-chacha20-stream', portNames: { data: 'Payload' } }], edges: [],
    };
    expect(validate(d).issues.map((i) => i.code)).toContain('PORT_NAME_AMBIGUOUS');
    d.nodes[0].portNames = { 'inputs.data': 'Payload' };
    expect(validate(d).issues.map((i) => i.code)).not.toContain('PORT_NAME_AMBIGUOUS');
  });

  it('PORT_NAME_INVALID: empty, blank, forbidden characters, not a string', () => {
    for (const v of ['', '   ', 'a/b', 'a,b', 'a(b', 'a)b', 5, null]) {
      expect(at(names({ key: v })), String(v)).toEqual([['PORT_NAME_INVALID', 'nodes[1].portNames.key']]);
    }
  });

  it('PORT_NAME_DUPLICATE: same direction, including a port that keeps its default name', () => {
    expect(codes(names({ key: 'Plaintext' }))).toContain('PORT_NAME_DUPLICATE'); // plaintext keeps "Plaintext"
    expect(codes(names({ key: 'A', plaintext: 'A' }))).toContain('PORT_NAME_DUPLICATE');
    expect(codes(names({ key: 'Ciphertext' }))).not.toContain('PORT_NAME_DUPLICATE'); // an output name
  });
});
