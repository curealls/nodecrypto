import { describe, it, expect } from 'vitest';
import { DAGRunner } from 'nodecrypto-engine/dag/runner';
import { defaultNodeRegistry } from 'nodecrypto-engine/registry/nodeRegistry';
import { DAGEdgeConnection } from 'nodecrypto-engine/dag/types';
import { computeDefinitionId, deriveInterface, registerCustomNodes, CustomNodeDefinition } from 'nodecrypto-engine/dag/customNode';
import { utf8ToBytes, bytesToUtf8, bytesToHex } from 'nodecrypto-engine/crypto/utils/encoding';

describe('Custom Task Packaging & Pure Black-Box Execution', () => {
  const registry = defaultNodeRegistry.getMap();

  it('packages an AES-CBC Encrypt workflow into a single Black-Box Task and executes it in an outer DAG', async () => {
    const rawPlaintext = 'Confidential Sub-DAG Encapsulated Data';
    const keyBytes = utf8ToBytes('0123456789abcdef'); // 16-byte key

    // Internal Sub-DAG: Task Entry -> AES Encrypt -> Task Exit
    const internalNodes = [
      {
        id: 'sub-entry',
        type: 'workflow-input',
        data: {
          id: 'sub-entry',
          type: 'workflow-input',
          nodeType: 'workflow-input',
          label: 'Task Entry',
          outputs: [
            { id: 'in_data', name: 'Data', dataType: 'bytes' as const },
            { id: 'in_key', name: 'Key', dataType: 'bytes' as const },
          ],
          properties: {},
        },
      },
      {
        id: 'sub-aes',
        type: 'symmetric-aes-encrypt',
        data: {
          id: 'sub-aes',
          type: 'symmetric-aes-encrypt',
          nodeType: 'symmetric-aes-encrypt',
          label: 'AES Encrypt',
          properties: { mode: 'CBC', padding: 'PKCS7' },
        },
      },
      {
        id: 'sub-exit',
        type: 'workflow-output',
        data: {
          id: 'sub-exit',
          type: 'workflow-output',
          nodeType: 'workflow-output',
          label: 'Task Exit',
          inputs: [
            { id: 'ret_cipher', name: 'Ciphertext', dataType: 'bytes' as const },
          ],
          properties: {},
        },
      },
    ];

    const internalEdges = [
      { id: 'ie1', source: 'sub-entry', sourceHandle: 'in_data', target: 'sub-aes', targetHandle: 'plaintext' },
      { id: 'ie2', source: 'sub-entry', sourceHandle: 'in_key', target: 'sub-aes', targetHandle: 'key' },
      { id: 'ie3', source: 'sub-aes', sourceHandle: 'ciphertext', target: 'sub-exit', targetHandle: 'ret_cipher' },
    ];

    // Build the custom node definition and register it under its content-hash id
    const def: CustomNodeDefinition = {
      manifest: { label: 'AES CBC Protocol', version: '1', description: '', category: 'User Custom Protocols', ...deriveInterface(internalNodes) },
      workflow: { nodes: internalNodes, edges: internalEdges },
    };
    const customType = computeDefinitionId(def);
    registerCustomNodes({ [customType]: def });

    const registeredDef = defaultNodeRegistry.get(customType);
    expect(customType).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(registeredDef?.label).toBe('AES CBC Protocol');

    // Outer Workflow: Text Input & Key Input -> Encapsulated Custom Task -> Output Inspector
    const outerNodes = [
      { id: 'outer-text', type: 'input-static-value', properties: { type: 'string', valueString: rawPlaintext } },
      { id: 'outer-key', type: 'input-static-value', properties: { type: 'bytes', valueBytes: bytesToHex(keyBytes) } },
      { id: 'outer-task-node', type: customType, properties: {} },
      { id: 'outer-inspector', type: 'output-inspector', properties: {} },
    ];

    const outerEdges: DAGEdgeConnection[] = [
      { id: 'oe1', source: 'outer-text', sourceHandle: 'value', target: 'outer-task-node', targetHandle: 'in_data' },
      { id: 'oe2', source: 'outer-key', sourceHandle: 'value', target: 'outer-task-node', targetHandle: 'in_key' },
      { id: 'oe3', source: 'outer-task-node', sourceHandle: 'ret_cipher', target: 'outer-inspector', targetHandle: 'data' },
    ];

    const outerResult = await DAGRunner.execute(outerNodes, outerEdges, registry);

    expect(outerResult.success).toBe(true);
    expect(outerResult.nodeStates['outer-task-node'].status).toBe('success');
    expect(outerResult.nodeStates['outer-inspector'].status).toBe('success');

    // Verify ciphertext was generated inside the sub-DAG and emitted to the outer inspector
    const taskOutputs = outerResult.nodeOutputs['outer-task-node'];
    expect(taskOutputs.ret_cipher).toBeInstanceOf(Uint8Array);
    expect(taskOutputs.ret_cipher.length).toBeGreaterThan(0);

    const inspectorData = outerResult.nodeStates['outer-inspector'].inputs.data;
    expect(inspectorData.length).toBe(taskOutputs.ret_cipher.length);

    // D-08: a sub-DAG failure surfaces the inner representative error code/message on the outer task node
    const badKeyNodes = outerNodes.map((n) =>
      n.id === 'outer-key' ? { ...n, properties: { type: 'bytes', valueBytes: 'aabb' } } : n
    );
    const failed = await DAGRunner.execute(badKeyNodes, outerEdges, registry);
    expect(failed.nodeStates['outer-task-node'].status).toBe('error');
    expect(failed.taskError?.nodeId).toBe('outer-task-node');
    expect(failed.taskError?.code).toBe('INVALID_KEY_LENGTH');
    expect(failed.taskError?.message).toContain('Invalid AES key length');
  });
});
