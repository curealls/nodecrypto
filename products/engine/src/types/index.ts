/**
 * Core Type Definitions for NodeCrypto Platform
 */

export type DataType =
  | 'bytes'
  | 'string'
  | 'bool'
  | 'int'
  | 'set'
  | 'any';

export type NodeSize = 'basic' | 'small' | 'mini';

// Node width standard (16px grid units, base = Basic 304px / 19 units):
// - Basic (19u): default size for fully-featured processing nodes (inputs + outputs + properties)
// - Small (13u, ~2/3 of Basic): output-only / minimal-property nodes (e.g. Static Value, Random Value)
// - Mini  (8u,  ~2/5 of Basic): compact terminal sink nodes (e.g. Output Inspector)
export const NODE_WIDTH_BY_SIZE: Record<NodeSize, number> = {
  basic: 304,
  small: 208,
  mini: 128,
};

export type NodeCategory =
  | 'input'
  | 'converter'
  | 'symmetric'
  | 'asymmetric'
  | 'pqc'
  | 'hash'
  | 'hash_mac'
  | 'kdf'
  | 'crc'
  | 'utility'
  | 'custom';

export type ExecutionState = 'idle' | 'running' | 'success' | 'error';

/** Workflow Input port value constraint (node-catalog.md ND-1.5). int bounds are decimal strings. */
export interface PortConstraint {
  /** Allowed lengths: a number, or "K*N" for any positive multiple of K (bytes/string only). */
  lengths?: (number | string)[];
  min?: number | string;
  max?: number | string;
}

export interface NodePortDefinition {
  id: string;             // Port ID (e.g. "key", "data", "iv")
  name: string;           // Short display label in UI (no parenthetical specs)
  dataType: DataType;     // Allowed data type
  required?: boolean;     // Whether this port is mandatory
  defaultValue?: any;     // Optional default / fallback value
  spec?: string;          // Short structured hint shown as a badge (e.g. "16/24/32B", "PEM/DER")
  description?: string;   // Full explanation shown in the node info panel / properties modal, and as tooltip
  constraint?: PortConstraint; // Workflow Input output ports only: checked when the node runs
  /** When set, the port only exists (renders / connects / counts toward execution) while this returns true for the node's current properties. Ports without it always exist (PRD §3.4-7). */
  showWhen?: (properties: Record<string, any>) => boolean;
}

export interface DynamicPortConfig {
  min?: number;
  max?: number;
  defaultNamePrefix?: string;
  defaultDataType?: DataType;
}

export interface OutputRecord {
  id: string;
  nodeId: string;
  nodeLabel: string;
  portId: string;
  dataType: DataType;
  rawValue: any;
  formattedPreview: string;
  timestamp: number;
}
