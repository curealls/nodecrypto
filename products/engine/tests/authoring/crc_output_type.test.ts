import { describe, it, expect } from 'vitest';
import { validate } from '../../src/authoring/validate';
import { draftToPackage } from '../../src/authoring/draft';
import { DAGRunner } from '../../src/dag/runner';
import { defaultNodeRegistry } from '../../src/registry/nodeRegistry';
import { bytesToHex } from '@noble/hashes/utils.js';

// node-catalog.md ND-7.8, authoring.md §2.3: `Output Type` (bytes | int) sets the CRC output port; a saved node without it is an int.
const draft = (outputType?: string, preset = 'CRC-32/ISO-HDLC') => ({
  draft: 1,
  name: 'crc',
  nodes: [
    { id: 'in', type: 'input-static-value', props: { type: 'bytes', valueBytes: '313233343536373839' } },
    { id: 'crc', type: 'utility-crc', props: { preset, ...(outputType ? { outputType } : {}) } },
    { id: 'out', type: 'workflow-output', inputs: [{ id: 'x', dataType: outputType ?? 'bytes', name: 'CRC' }] },
  ],
  edges: [{ from: 'in.value', to: 'crc.data' }, { from: 'crc.checksum', to: 'out.x' }],
});
const run = (nodes: any[]) =>
  DAGRunner.execute(nodes, [{ id: 'e', source: 'in', sourceHandle: 'value', target: 'crc', targetHandle: 'data' }], defaultNodeRegistry);
const input = { id: 'in', type: 'input-static-value', properties: { type: 'bytes', valueBytes: '313233343536373839' } };

describe('CRC Output Type', () => {
  it('defaults to bytes: a draft without the property gets a bytes output', () => {
    const d = draft();
    expect(validate(d).issues).toEqual([]);
    const r: any = draftToPackage(d);
    expect(r.package.workflow.nodes[1].data.outputs[0].dataType).toBe('bytes');
    expect(r.package.workflow.nodes[1].data.properties.outputType).toBe('bytes');
    expect(validate(r.package).issues).toEqual([]);
  });

  it('int gives an int output', () => {
    const d = draft('int');
    expect(validate(d).issues).toEqual([]);
    expect((draftToPackage(d) as any).package.workflow.nodes[1].data.outputs[0].dataType).toBe('int');
  });

  it('bytes are the big-endian value over ceil(width/8) bytes (check values of "123456789")', async () => {
    for (const [preset, hex] of [['CRC-32/ISO-HDLC', 'cbf43926'], ['CRC-16/CCITT-FALSE', '29b1'], ['CRC-16/MODBUS', '4b37'], ['CRC-8/SMBUS', 'f4']] as const) {
      const r = await run([input, { id: 'crc', type: 'utility-crc', properties: { preset, outputType: 'bytes' } }]);
      expect(r.success).toBe(true);
      expect(bytesToHex(r.nodeOutputs.crc.checksum), preset).toBe(hex);
    }
  });

  it('int gives the same value as a number', async () => {
    const r = await run([input, { id: 'crc', type: 'utility-crc', properties: { preset: 'CRC-32/ISO-HDLC', outputType: 'int' } }]);
    expect(r.nodeOutputs.crc.checksum).toBe(0xcbf43926);
  });

  it('an old saved node without the property stays an int, in the run and in validation', async () => {
    const r = await run([input, { id: 'crc', type: 'utility-crc', properties: { preset: 'CRC-32/ISO-HDLC' } }]);
    expect(r.nodeOutputs.crc.checksum).toBe(0xcbf43926);
    const pkg: any = (draftToPackage(draft('int')) as any).package;
    delete pkg.workflow.nodes[1].data.properties.outputType; // what an older file looks like
    expect(validate(pkg).issues).toEqual([]);
    pkg.workflow.nodes[1].data.outputs[0].dataType = 'bytes'; // a bytes port without the property is a mismatch
    expect(validate(pkg).issues.map((i: any) => i.code)).toContain('PORT_MISMATCH');
  });

  it('a package whose port type disagrees with Output Type is PORT_MISMATCH', () => {
    const pkg: any = (draftToPackage(draft('bytes')) as any).package;
    pkg.workflow.nodes[1].data.outputs[0].dataType = 'int';
    expect(validate(pkg).issues.map((i: any) => i.code)).toContain('PORT_MISMATCH');
  });
});
