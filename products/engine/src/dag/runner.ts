/**
 * Asynchronous DAG Workflow Runner
 * Executes nodes along topological stages, performs type coercion, and tracks snapshots.
 */

import {
  DAGEdgeConnection,
  DAGExecutionLog,
  DAGExecutionResult,
  DAGNodeState,
  NodeDefinition,
  visiblePorts,
} from './types';
import { DAGScheduler } from './scheduler';
import { getEffectiveEdges } from './links';
import { NodeError } from './errors';
import { Msg, formatMsg, tmsg } from '../messages';
import {
  utf8ToBytes,
  bytesToUtf8,
} from '../crypto/utils/encoding';
import { DataType, NodePortDefinition } from '../types';
import { VariableMap, hasRefs, resolveProperties, slotsFor } from '../variables/reference';

export interface WorkflowRunnerOptions {
  /** Called once with the ids this run will process (target node and its upstream, or all), before anything runs. */
  onStart?: (nodeIds: string[]) => void;
  onNodeStatusChange?: (nodeId: string, state: DAGNodeState) => void;
  onEdgeDataChange?: (edgeId: string, value: any) => void;
  onLog?: (log: DAGExecutionLog) => void;
  targetNodeId?: string; // If specified, only executes nodes upstream of this target
  /** Variable snapshot taken at run start (value-registry.md §5.1). Nodes with unresolvable references fail with VARIABLE_UNRESOLVED. */
  variables?: VariableMap;
}

export class DAGRunner {
  /**
   * The input ports that exist for the node's current properties. A node read from a file carries no showWhen functions
   * (authoring.md §2.3), so they are taken from the definition's port of the same id.
   */
  private static activeInputs(node: any, def: any, properties: Record<string, any>) {
    const ports: any[] = node.inputs || def.inputs;
    return visiblePorts(ports.map((p) => (p.showWhen ? p : { ...p, showWhen: def.inputs?.find((d: any) => d.id === p.id)?.showWhen })), properties);
  }

  /**
   * Coerces data value to match expected target port DataType.
   */
  public static coerceDataType(value: any, targetType: DataType): any {
    if (value === undefined || value === null) return value;

    // Already matching
    if (targetType === 'bytes' && value instanceof Uint8Array) return value;
    if (targetType === 'string' && typeof value === 'string') return value;
    if (targetType === 'int' && typeof value === 'number') return Math.trunc(value);
    // data-types.md §2.2: int keeps bigint precision; only safe-range values are narrowed to number.
    if (targetType === 'int' && typeof value === 'bigint') {
      return value >= BigInt(Number.MIN_SAFE_INTEGER) && value <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(value) : value;
    }
    if (targetType === 'bool' && typeof value === 'boolean') return value;

    try {
      // From Uint8Array
      if (value instanceof Uint8Array) {
        if (targetType === 'string') return bytesToUtf8(value);
        if (targetType === 'int' && value.length <= 6) {
          let num = 0;
          for (let i = 0; i < value.length; i++) num = (num << 8) | value[i];
          return num;
        }
      }

      // From string
      if (typeof value === 'string') {
        if (targetType === 'bytes') {
          return utf8ToBytes(value);
        }
        if (targetType === 'int') {
          const parsed = Number(value);
          if (!isNaN(parsed)) return Math.trunc(parsed);
        }
        if (targetType === 'bool') {
          return value.toLowerCase() === 'true' || value === '1';
        }
      }

      // From number / bigint
      if (typeof value === 'number' || typeof value === 'bigint') {
        const num = Number(value);
        if (targetType === 'int') return Math.trunc(num);
        if (targetType === 'string') return String(value);
        if (targetType === 'bool') return Boolean(num);
        if (targetType === 'bytes') return new Uint8Array([num & 0xff]);
      }

      // From boolean
      if (typeof value === 'boolean') {
        if (targetType === 'bool') return value;
        if (targetType === 'int') return value ? 1 : 0;
        if (targetType === 'string') return String(value);
      }
    } catch {
      // Return original on coercion failure
      return value;
    }

    return value;
  }

  /**
   * Executes DAG workflow nodes with full reactivity and error isolation.
   */
  public static async execute(
    nodes: Array<{
      id: string;
      type: string;
      label?: string;
      properties?: Record<string, any>;
      inputs?: NodePortDefinition[];
      outputs?: NodePortDefinition[];
    }>,
    storedEdges: DAGEdgeConnection[],
    registry: Map<string, NodeDefinition>,
    options: WorkflowRunnerOptions = {}
  ): Promise<DAGExecutionResult> {
    const startTime = performance.now();
    // Link nodes (TASK_031) reference an output port via properties; expose that as an implicit edge
    // so scheduling / cycle detection / partial runs / failure propagation treat it like any edge.
    const edges = getEffectiveEdges(nodes, storedEdges);
    const logs: DAGExecutionLog[] = [];

    const emitLog = (nodeId: string, nodeType: string, message: string, level: 'info' | 'warn' | 'error' = 'info') => {
      const log: DAGExecutionLog = {
        id: `log-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
        timestamp: Date.now(),
        nodeId,
        nodeType,
        level,
        message,
      };
      logs.push(log);
      options.onLog?.(log);
    };

    // 1. Determine active node IDs
    let activeNodeIds = nodes.map((n) => n.id);
    if (options.targetNodeId) {
      const ancestors = DAGScheduler.getAncestors(options.targetNodeId, edges);
      const targetSet = new Set([...ancestors, options.targetNodeId]);
      activeNodeIds = activeNodeIds.filter((id) => targetSet.has(id));
    }

    options.onStart?.(activeNodeIds);

    // 2. Schedule execution plan
    const plan = DAGScheduler.schedule(activeNodeIds, edges);

    if (plan.hasCycle) {
      const cycleMsg = `DAG Cycle detected involving nodes: ${plan.cycleNodes?.join(', ')}`;
      emitLog('system', 'scheduler', cycleMsg, 'error');
      return {
        success: false,
        order: [],
        stages: [],
        nodeOutputs: {},
        edgeValues: {},
        nodeStates: {},
        logs,
        totalDurationMs: performance.now() - startTime,
        error: cycleMsg,
      };
    }

    // 3. Initialize state tracking
    const nodeMap = new Map(nodes.map((n) => [n.id, n]));
    const nodeOutputs: Record<string, Record<string, any>> = {};
    const edgeValues: Record<string, any> = {};
    const nodeStates: Record<string, DAGNodeState> = {};

    // Variable references are resolved once, before anything runs, so one run sees one consistent snapshot
    // (value-registry.md §5.1). Node implementations only ever see resolved values.
    const unresolved = new Map<string, Msg>();
    for (const id of activeNodeIds) {
      const rawNode = nodeMap.get(id)!;
      let properties: Record<string, any> = { ...rawNode.properties };
      if (hasRefs(rawNode.properties)) {
        const def = registry.get(rawNode.type);
        const resolved = resolveProperties(rawNode.properties, slotsFor(def, rawNode.outputs || def?.outputs), options.variables);
        if (resolved.ok) properties = resolved.properties;
        else unresolved.set(id, resolved.errors.length === 1 ? resolved.errors[0].msg : tmsg('errors:variable.unresolvedMany', { first: resolved.errors[0].msg, more: resolved.errors.length - 1 }));
      }
      nodeStates[id] = {
        id,
        type: rawNode.type,
        inputs: {},
        outputs: {},
        properties,
        status: 'idle',
      };
      nodeOutputs[id] = {};
    }

    // Build incoming edges map: targetNodeId -> edges
    const incomingEdges = new Map<string, DAGEdgeConnection[]>();
    for (const edge of edges) {
      if (!incomingEdges.has(edge.target)) {
        incomingEdges.set(edge.target, []);
      }
      incomingEdges.get(edge.target)!.push(edge);
    }

    let hasGlobalError = false;

    // 4. Stage-by-stage execution
    for (const stage of plan.stages) {
      // Execute all independent nodes in this stage concurrently
      await Promise.all(
        stage.map(async (nodeId) => {
          const node = nodeMap.get(nodeId);
          if (!node) return;

          const def = registry.get(node.type);
          if (!def) {
            const err = `Node type definition not found: '${node.type}'`;
            nodeStates[nodeId].status = 'error';
            nodeStates[nodeId].errorMessage = err;
            emitLog(nodeId, node.type, err, 'error');
            options.onNodeStatusChange?.(nodeId, nodeStates[nodeId]);
            hasGlobalError = true;
            return;
          }

          // A. Collect and resolve inputs from incoming edges
          const inEdges = incomingEdges.get(nodeId) || [];
          const resolvedInputs: Record<string, any> = {};

          let parentFailed = false;
          for (const edge of inEdges) {
            const sourceState = nodeStates[edge.source];
            if (sourceState && sourceState.status === 'error') {
              parentFailed = true;
              break;
            }

            const sourceOutput = nodeOutputs[edge.source]?.[edge.sourceHandle];
            if (sourceOutput !== undefined) {
              // Lookup expected data type from node instance inputs or fallback definition
              const activeInputs = DAGRunner.activeInputs(node, def, nodeStates[nodeId].properties || {});
              const targetPortDef = activeInputs.find((p) => p.id === edge.targetHandle);
              const coercedValue = targetPortDef
                ? DAGRunner.coerceDataType(sourceOutput, targetPortDef.dataType)
                : sourceOutput;

              resolvedInputs[edge.targetHandle] = coercedValue;
              edgeValues[edge.id] = coercedValue;
              options.onEdgeDataChange?.(edge.id, coercedValue);
            }
          }

          // Apply default values for unsupplied optional/default ports. Ports hidden by
          // showWhen for the node's current properties (PRD §3.4-7) don't exist for this run.
          const activeInputs = DAGRunner.activeInputs(node, def, nodeStates[nodeId].properties || {});
          for (const port of activeInputs) {
            if (resolvedInputs[port.id] === undefined && port.defaultValue !== undefined) {
              resolvedInputs[port.id] = port.defaultValue;
            }
          }

          // Hand inputs to the node in its input port order (node-catalog.md §2.2-9), not edge order.
          const orderedInputs: Record<string, any> = {};
          for (const port of activeInputs) {
            if (resolvedInputs[port.id] !== undefined) orderedInputs[port.id] = resolvedInputs[port.id];
          }
          for (const key of Object.keys(resolvedInputs)) {
            if (!(key in orderedInputs)) orderedInputs[key] = resolvedInputs[key];
          }
          for (const key of Object.keys(resolvedInputs)) delete resolvedInputs[key];
          Object.assign(resolvedInputs, orderedInputs);

          // If upstream parent failed, isolate and skip this node
          if (parentFailed) {
            nodeStates[nodeId].status = 'error';
            nodeStates[nodeId].errorMessage = 'Skipped due to upstream node failure';
            nodeStates[nodeId].skipped = true;
            emitLog(nodeId, node.type, 'Execution skipped because parent node failed', 'warn');
            options.onNodeStatusChange?.(nodeId, nodeStates[nodeId]);
            return;
          }

          // Unresolvable variable references (execution-semantics.md §4.4): engine-made error, not tied to the node's error profile
          if (unresolved.has(nodeId)) {
            const unresolvedMsg = unresolved.get(nodeId)!;
            const err = formatMsg(unresolvedMsg);
            nodeStates[nodeId].status = 'error';
            nodeStates[nodeId].errorCode = 'VARIABLE_UNRESOLVED';
            nodeStates[nodeId].errorMessage = err;
            nodeStates[nodeId].errorMsg = unresolvedMsg;
            emitLog(nodeId, node.type, `Variable reference cannot be resolved: ${err}`, 'error');
            options.onNodeStatusChange?.(nodeId, nodeStates[nodeId]);
            hasGlobalError = true;
            return;
          }

          // Check required input ports
          const missingRequired = activeInputs
            .filter((p) => p.required && resolvedInputs[p.id] === undefined)
            .map((p) => p.name);

          if (missingRequired.length > 0) {
            const err = `Missing required inputs: ${missingRequired.join(', ')}`;
            nodeStates[nodeId].status = 'error';
            nodeStates[nodeId].errorMessage = err;
            emitLog(nodeId, node.type, err, 'error');
            options.onNodeStatusChange?.(nodeId, nodeStates[nodeId]);
            hasGlobalError = true;
            return;
          }

          // B. Execute node
          nodeStates[nodeId].inputs = resolvedInputs;
          nodeStates[nodeId].status = 'running';
          options.onNodeStatusChange?.(nodeId, nodeStates[nodeId]);

          const nodeStartTime = performance.now();
          try {
            emitLog(nodeId, node.type, `Executing node '${def.label}'...`, 'info');

            const result = await def.execute({
              nodeId,
              nodeLabel: node.label || def.label,
              inputs: resolvedInputs,
              properties: nodeStates[nodeId].properties,
              inputPorts: node.inputs || def.inputs,
              outputPorts: node.outputs || def.outputs,
              log: (msg, level = 'info') => emitLog(nodeId, node.type, msg, level),
            });

            const duration = Math.round(performance.now() - nodeStartTime);
            const finalOutputs = { ...(result || {}) };
            nodeOutputs[nodeId] = finalOutputs;
            nodeStates[nodeId].outputs = finalOutputs;
            nodeStates[nodeId].status = 'success';
            nodeStates[nodeId].durationMs = duration;

            // judgement reinterpretation (D-03): must happen before downstream nodes are scheduled,
            // which holds here since downstream nodes live in a later stage of the outer loop.
            const props = nodeStates[nodeId].properties || {};
            if (def.errorProfile?.kind === 'judgement' && (props.errorOnValue === 'true' || props.errorOnValue === 'false')) {
              const judgedValue = finalOutputs[def.errorProfile.port];
              if (String(judgedValue) === props.errorOnValue) {
                nodeStates[nodeId].status = 'error';
                nodeStates[nodeId].errorCode =
                  props.errorCode || `${node.type.toUpperCase().replace(/-/g, '_')}_JUDGEMENT_FAILED`;
                const failMsg = tmsg('errors:judgement.failed', { label: node.label || def.label });
                nodeStates[nodeId].errorMessage = props.errorMessage || formatMsg(failMsg);
                nodeStates[nodeId].errorMsg = props.errorMessage ? undefined : failMsg;
                emitLog(nodeId, node.type, `Judgement reinterpreted as error: ${nodeStates[nodeId].errorMessage}`, 'error');
                hasGlobalError = true;
              }
            }

            if (nodeStates[nodeId].status === 'success') {
              emitLog(nodeId, node.type, `Completed successfully in ${duration}ms`, 'info');
            }
            options.onNodeStatusChange?.(nodeId, nodeStates[nodeId]);
          } catch (err: any) {
            const duration = Math.round(performance.now() - nodeStartTime);
            const msg = err?.message || String(err);
            const props = nodeStates[nodeId].properties || {};
            const unify = def.errorProfile?.kind === 'fixed' && props.errorUnify;
            nodeStates[nodeId].status = 'error';
            nodeStates[nodeId].errorCode = unify
              ? props.errorUnifyCode
              : err instanceof NodeError
                ? err.code
                : 'UNKNOWN_ERROR';
            nodeStates[nodeId].errorMessage = unify ? props.errorUnifyMessage : msg;
            nodeStates[nodeId].errorMsg = !unify && err instanceof NodeError ? err.msg : undefined;
            nodeStates[nodeId].durationMs = duration;

            emitLog(nodeId, node.type, `Execution failed: ${nodeStates[nodeId].errorMessage}`, 'error');
            options.onNodeStatusChange?.(nodeId, nodeStates[nodeId]);
            hasGlobalError = true;
          }
        })
      );
    }

    const totalDurationMs = Math.round(performance.now() - startTime);

    // Task-level representative error (D-04): earliest in scheduling order, chained skips excluded.
    let taskError: DAGExecutionResult['taskError'];
    for (const nodeId of plan.order) {
      const state = nodeStates[nodeId];
      if (state?.status === 'error' && !state.skipped) {
        taskError = { nodeId, code: state.errorCode || 'UNKNOWN_ERROR', message: state.errorMessage || 'Unknown error' };
        break;
      }
    }

    return {
      success: !hasGlobalError,
      order: plan.order,
      stages: plan.stages,
      nodeOutputs,
      edgeValues,
      nodeStates,
      logs,
      totalDurationMs,
      error: hasGlobalError ? 'One or more nodes failed during execution' : undefined,
      taskError,
    };
  }
}
