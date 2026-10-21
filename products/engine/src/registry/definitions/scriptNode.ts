/**
 * Script node (node-catalog.md ND-8.3). Runs engine/script/ over the node's ports; no UI dependency.
 */

import { NodeDefinition } from '../../dag/types';
import { NodeError } from '../../dag/errors';
import { fixedErrorProfile } from '../errorProfile';
import { tmsg } from '../../messages';
import { compile, runScript } from '../../script';
import type { ScriptValue } from '../../script';
import { ERROR_UNIFY_FIELDS } from './symmetricNodes';

export const SCRIPT_NODE_TYPE = 'utility-script';
export const SCRIPT_VERSION = 1;
export const DEFAULT_SCRIPT_CODE = '';

// Fixed cases: bytes-ops.md §4 and builtin-script.md §6.3. `fail(code, message)` codes are not listed
// here; they pass through as NodeError.code (runner.ts).
const CASES = [
  'BYTES_OUT_OF_RANGE', 'BYTES_LENGTH_MISMATCH', 'BYTES_INT_OVERFLOW', 'BYTES_INVALID_HEX', 'BYTES_INVALID_UTF8', 'BYTES_INVALID_ARGUMENT', 'BYTES_SIZE_LIMIT',
  'SCRIPT_COMPILE_ERROR', 'SCRIPT_DIVISION_BY_ZERO', 'SCRIPT_INDEX_OUT_OF_RANGE', 'SCRIPT_INVALID_ARGUMENT', 'SCRIPT_INVALID_ERROR_CODE',
  'SCRIPT_SIZE_LIMIT', 'SCRIPT_STEP_LIMIT', 'SCRIPT_TIMEOUT', 'SCRIPT_INTERNAL_ERROR',
];

/** Web time limit (builtin-script.md §9): scripts run on the main thread, so the UI freezes until then. */
export const WEB_TIME_LIMIT_MS = 3_000;

const MIN_SAFE = BigInt(Number.MIN_SAFE_INTEGER);
const MAX_SAFE = BigInt(Number.MAX_SAFE_INTEGER);

export const scriptNodes: NodeDefinition[] = [
  {
    type: SCRIPT_NODE_TYPE,
    label: 'Script',
    category: 'utility',
    description: 'Runs a built-in script (Python subset) over bytes/int/bool/string ports',
    size: 'basic',
    dynamicInputs: { min: 0, defaultNamePrefix: 'in', defaultDataType: 'bytes' },
    dynamicOutputs: { min: 0, defaultNamePrefix: 'out', defaultDataType: 'bytes' },
    inputs: [],
    outputs: [],
    propertySchema: [
      { id: 'code', label: 'Code', type: 'textarea', variable: false, defaultValue: DEFAULT_SCRIPT_CODE },
      // Never shown: showWhen is always false (edited only by version migration).
      { id: 'scriptVersion', label: 'Script Version', type: 'number', defaultValue: SCRIPT_VERSION, showWhen: () => false },
      ...ERROR_UNIFY_FIELDS,
    ],
    errorProfile: fixedErrorProfile(CASES),
    execute: async ({ inputs, properties, inputPorts = [], outputPorts = [], log }) => {
      if (properties.scriptVersion !== SCRIPT_VERSION) {
        throw new NodeError('SCRIPT_COMPILE_ERROR', tmsg('errors:script.unsupportedVersion', { version: properties.scriptVersion }));
      }
      const spec = (ports: typeof inputPorts) => ports.map((p) => ({ id: p.id, dataType: p.dataType }));
      const res = compile(String(properties.code ?? ''), { inputs: spec(inputPorts), outputs: spec(outputPorts) });
      if (!res.typed) {
        const d = res.diagnostics[0];
        throw new NodeError('SCRIPT_COMPILE_ERROR', d ? tmsg('errors:script.compileDiagnostic', { line: d.line, column: d.column, detail: d.message }) : tmsg('errors:script.compileFailed'));
      }

      const args: Record<string, ScriptValue> = {};
      for (const p of inputPorts) {
        const v = inputs[p.id];
        args[p.id] = p.dataType === 'int' && v !== undefined ? BigInt(v) : v;
      }
      const out = runScript(res.typed, args, { timeLimitMs: WEB_TIME_LIMIT_MS });
      const result: Record<string, any> = {};
      for (const p of outputPorts) {
        const v = out[p.id];
        result[p.id] = typeof v === 'bigint' && v >= MIN_SAFE && v <= MAX_SAFE ? Number(v) : v;
      }
      log(`Script executed (${outputPorts.length} output${outputPorts.length === 1 ? '' : 's'})`);
      return result;
    },
  },
];
