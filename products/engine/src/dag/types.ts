/**
 * DAG (Directed Acyclic Graph) Execution Engine Types
 */

import type { Msg } from '../messages';
import { DataType, NodeCategory, NodeSize, DynamicPortConfig, PortConstraint } from '../types';

export interface NodePortDefinition {
  id: string;             // Port ID (e.g. "key", "data", "iv", "output")
  name: string;           // Short display name (no parenthetical specs)
  dataType: DataType;     // "bytes" | "string" | "bool" | "int" | "any"
  required?: boolean;     // Whether input is required for execution
  spec?: string;          // Short structured hint shown as a badge (e.g. "16/24/32B", "PEM/DER")
  description?: string;   // Full explanation (node info panel / properties modal / tooltip)
  constraint?: PortConstraint; // Workflow Input output ports only: checked when the node runs
  defaultValue?: any;     // Fallback default value if port is unconnected
  /** When set, the port only exists (renders / connects / counts toward execution) while this returns true for the node's current properties. Ports without it always exist (PRD §3.4-7). */
  showWhen?: (properties: Record<string, any>) => boolean;
}

/** Filters a port list down to the ports that exist for the node's current properties (PRD §3.4-7). */
export function visiblePorts(ports: NodePortDefinition[], properties: Record<string, any>): NodePortDefinition[] {
  return ports.filter((p) => !p.showWhen || p.showWhen(properties || {}));
}

export type PropertyFieldType = 'text' | 'number' | 'select' | 'boolean' | 'textarea' | 'hex';

export interface PropertyFieldDefinition {
  id: string;
  label: string;
  type: PropertyFieldType;
  options?: { label: string; value: any }[]; // For select types
  defaultValue: any;
  description?: string;
  /** When set, the field is only rendered/counted while this returns true for the node's current (live-edited) properties. */
  showWhen?: (properties: Record<string, any>) => boolean;
  /** When set on a 'select' field, an (i) info button opens the matching static help page in a new tab (e.g. 'padding' -> padding.html, 'cipherMode' -> cipher-modes.html; help-docs.md §6.2). */
  helpTopic?: 'padding' | 'cipherMode';
  /**
   * Variable references (value-registry.md §4.2). Unset: follows the field type (hex/text/number/boolean/textarea).
   * A variable type makes e.g. a 'select' accept variables of that type; `false` opts the field out (Script code).
   */
  variable?: 'bytes' | 'string' | 'int' | 'bool' | false;
}

export interface NodeExecutionContext {
  nodeId: string;
  nodeLabel?: string;
  inputs: Record<string, any>;
  properties: Record<string, any>;
  inputPorts?: NodePortDefinition[];
  outputPorts?: NodePortDefinition[];
  log: (message: string, level?: 'info' | 'warn' | 'error') => void;
}

export type NodeExecutor = (context: NodeExecutionContext) => Promise<Record<string, any>>;

export interface NodeDefinition {
  type: string;                  // Unique node type identifier (e.g. "symmetric-aes-encrypt")
  label: string;                 // UI display label
  category: NodeCategory;        // "input" | "symmetric" | "asymmetric" | "pqc" | "hash" | "kdf" | "utility" | "custom"
  description: string;
  size?: NodeSize;               // 'basic' | 'small' | 'mini' (default width tier; see NODE_WIDTH_BY_SIZE)
  hidden?: boolean;              // Registered for execution but not offered in the palette (e.g. Link nodes are created from ports)
  dynamicInputs?: DynamicPortConfig;
  dynamicOutputs?: DynamicPortConfig;
  /** `properties.rows[portId].value` of fixed rows may hold a variable reference (value-registry.md §4.2, ValueSet). */
  rowValueRefs?: boolean;
  inputs: NodePortDefinition[];
  outputs: NodePortDefinition[];
  propertySchema: PropertyFieldDefinition[];
  execute: NodeExecutor;
  /**
   * Design-time check (node-catalog.md §2.2-8): returns the reason when the current connections break
   * the node's rules, else null. inputTypes holds the upstream dataType per connected input port id;
   * unconnected or `any` (undetermined) ports are absent, so the hook must skip them.
   */
  validate?: (ctx: { inputTypes: Record<string, DataType> }) => Msg | null;
  /** Host capability tokens this node needs (node-catalog.md §2.4). */
  requires?: string[];
  /** Error classification (D-02, execution-semantics.md §3.1). Unset behaves like 'none'. */
  errorProfile?:
    | { kind: 'none' }
    | { kind: 'fixed'; cases: { code: string; message: string }[] }
    | { kind: 'judgement'; port: string };
}

export interface DAGNodeState {
  id: string;
  type: string;
  inputs: Record<string, any>;
  outputs: Record<string, any>;
  properties: Record<string, any>;
  status: 'idle' | 'running' | 'success' | 'error';
  errorMessage?: string;
  /** Translatable form of `errorMessage` when the engine made it (i18n.md §6.2); absent for user-defined or unified errors */
  errorMsg?: Msg;
  errorCode?: string;
  /** True when this node's 'error' status is a chained skip from an upstream failure, not its own error (D-04 excludes these from taskError selection). */
  skipped?: boolean;
  durationMs?: number;
}

export interface DAGEdgeConnection {
  id: string;
  source: string;        // Source node ID
  sourceHandle: string;  // Source port ID
  target: string;        // Target node ID
  targetHandle: string;  // Target port ID
}

export interface DAGExecutionLog {
  id: string;
  timestamp: number;
  nodeId: string;
  nodeType: string;
  level: 'info' | 'warn' | 'error';
  message: string;
}

export interface DAGExecutionResult {
  success: boolean;
  order: string[];                     // Topological execution order
  stages: string[][];                  // Execution waves/stages (nodes in same stage can run in parallel)
  nodeOutputs: Record<string, Record<string, any>>; // nodeId -> portId -> value
  edgeValues: Record<string, any>;     // edgeId -> passed data value
  nodeStates: Record<string, DAGNodeState>;
  logs: DAGExecutionLog[];
  totalDurationMs: number;
  error?: string;
  /** Task-level representative error (D-04): the earliest-scheduled non-skipped ERROR node, if any. */
  taskError?: { nodeId: string; code: string; message: string };
}
