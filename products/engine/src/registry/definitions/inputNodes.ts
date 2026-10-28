/**
 * Input, Output, and Task Boundary Node Definitions
 */

import { NodeDefinition, PropertyFieldDefinition } from '../../dag/types';
import { NodeError } from '../../dag/errors';
import { fixedCase } from '../errorProfile';
import { tmsg } from '../../messages';
import { SWITCH_NODE_TYPE } from '../../dag/links';
import { utf8ToBytes, hexToBytes, bytesToHex } from '../../crypto/utils/encoding';
import { emitOutputRecord } from '../outputHandler';
import { checkConstraint } from '../../dag/portConstraint';

// errorProfile: none (T06, execution-semantics.md §3.1) for every node in this
// file. Static Value / User Input Dialog's bytes-type path does call hexToBytes internally, but
// per design decision this stays `none` rather than growing a `fixed` catalog for it.
const NONE_PROFILE = { kind: 'none' as const };

// Shared by Static Value / Random Value / User Input Dialog: all three pick their single output
// port's dataType via a "type" property (bytes/string/int/bool, never 'any' — see PRD 3.4 rule 6).
const VALUE_TYPE_OPTIONS = [
  { label: 'Bytes (Hex)', value: 'bytes' },
  { label: 'String (Text)', value: 'string' },
  { label: 'Int (Number)', value: 'int' },
  { label: 'Bool (True/False)', value: 'bool' },
];

function typeSelectField(defaultType: 'bytes' | 'string' | 'int' | 'bool'): PropertyFieldDefinition {
  return {
    id: 'type',
    label: 'Type',
    type: 'select',
    options: VALUE_TYPE_OPTIONS,
    defaultValue: defaultType,
    description: 'Data type of the value this node produces',
  };
}

// One value-editing widget per type, shown only while that type is selected (each widget kind
// already exists as a PropertyFieldType — hex/textarea/number/boolean — so no new field type is needed).
function makeTypedValueFields(
  idPrefix: string,
  labelPrefix: string,
  defaults: { bytes: string; string: string; int: number; bool: boolean }
): PropertyFieldDefinition[] {
  return [
    {
      id: `${idPrefix}Bytes`,
      label: `${labelPrefix} (Bytes)`,
      type: 'hex',
      defaultValue: defaults.bytes,
      showWhen: (p) => p.type === 'bytes',
    },
    {
      id: `${idPrefix}String`,
      label: `${labelPrefix} (String)`,
      type: 'textarea',
      defaultValue: defaults.string,
      showWhen: (p) => p.type === 'string',
    },
    {
      id: `${idPrefix}Int`,
      label: `${labelPrefix} (Int)`,
      type: 'number',
      defaultValue: defaults.int,
      showWhen: (p) => p.type === 'int',
    },
    {
      id: `${idPrefix}Bool`,
      label: `${labelPrefix} (Bool)`,
      type: 'select',
      options: [
        { label: 'True', value: true },
        { label: 'False', value: false },
      ],
      defaultValue: defaults.bool,
      variable: 'bool', // select, but accepts a bool variable (value-registry.md §4.2)
      showWhen: (p) => p.type === 'bool',
    },
  ];
}

// Value producers shared by Static Value / Random Value and the ValueSet node's fixed/random rows
// (node-catalog.md ND-1.1, ND-1.2, ND-1.11), so all three keep identical semantics.
function fixedValue(type: string, raw: any): any {
  if (type === 'string') return String(raw ?? '');
  if (type === 'int') return Number(raw) || 0;
  if (type === 'bool') return raw === true || raw === 'true';
  return hexToBytes(String(raw ?? '').replace(/\s+/g, ''));
}

function randomValue(type: string, opts: { length?: any; min?: any; max?: any }): any {
  if (type === 'string') {
    // Random string = CSPRNG-picked alphanumeric characters, not dictionary words — this is a
    // crypto workflow tool, not a wordlist generator.
    const length = Math.max(1, Math.min(4096, Number(opts.length) || 16));
    const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const rand = crypto.getRandomValues(new Uint8Array(length));
    return Array.from(rand, (b) => charset[b % charset.length]).join('');
  }
  if (type === 'int') {
    const min = Math.min(Number(opts.min) || 0, Number(opts.max) || 100);
    const max = Math.max(Number(opts.min) || 0, Number(opts.max) || 100);
    return min + (crypto.getRandomValues(new Uint32Array(1))[0] % (max - min + 1));
  }
  if (type === 'bool') return (crypto.getRandomValues(new Uint8Array(1))[0] & 1) === 1;
  const length = Math.max(1, Math.min(4096, Number(opts.length) || 16));
  return crypto.getRandomValues(new Uint8Array(length));
}

/** ValueSet node id (node-catalog.md ND-1.11). */
export const VALUE_SET_NODE_TYPE = 'input-value-set';
/** Reserved id of ValueSet's set output port; always the last of its outputs (workflow-spec.md §3.2.1). */
export const SET_PORT_ID = 'set';
export const SET_PORT = { id: SET_PORT_ID, name: 'Set', dataType: 'set' as const, description: 'All row values as one set' };

// A value's runtime type must match the row type it sits under (data-types.md §4.1).
const matchesType = (type: string, v: any) =>
  type === 'bytes' ? v instanceof Uint8Array : type === 'string' ? typeof v === 'string' : type === 'int' ? typeof v === 'number' || typeof v === 'bigint' : typeof v === 'boolean';

/**
 * Nodes whose first output port takes the data type chosen by a property (authoring.md §2.3, node-catalog.md §2.2-5).
 * The definition's own output type is only the default value of that property. `legacy` is the type of a saved node that
 * has no such property at all (a file written before the property existed): the CRC output used to be an `int`.
 */
const TYPE_DRIVEN_OUTPUT: Record<string, { prop: string; legacy?: string }> = {
  'input-static-value': { prop: 'type' },
  'input-random': { prop: 'type' },
  'input-dialog': { prop: 'type' },
  'utility-crc': { prop: 'outputType', legacy: 'int' },
};
export const isTypeDrivenOutput = (nodeType: string): boolean => nodeType in TYPE_DRIVEN_OUTPUT;
/** The property that sets the output type of `nodeType`, if any. */
export const typeDrivenProp = (nodeType: string): string | undefined => TYPE_DRIVEN_OUTPUT[nodeType]?.prop;
const VALUE_TYPE_NAMES = ['bytes', 'string', 'int', 'bool'];

/** Data type of the first output of a type-driven node for the given properties; `fallback` when the property holds no value type. */
export const typedOutputType = (nodeType: string, properties: Record<string, any>, fallback: string): string => {
  const c = TYPE_DRIVEN_OUTPUT[nodeType];
  const v = properties?.[c.prop];
  if (VALUE_TYPE_NAMES.includes(v)) return v;
  return v === undefined && c.legacy ? c.legacy : fallback;
};

export const inputNodes: NodeDefinition[] = [
  {
    type: 'input-static-value',
    label: 'Static Value',
    category: 'input',
    description: 'Provides a constant value of a user-selected type (bytes/string/int/bool)',
    size: 'small',
    inputs: [],
    outputs: [
      { id: 'value', name: 'Value', dataType: 'bytes', description: 'Constant value of the selected type' },
    ],
    propertySchema: [
      typeSelectField('bytes'),
      ...makeTypedValueFields('value', 'Value', {
        bytes: '00112233445566778899aabbccddeeff',
        string: 'Hello NodeCrypto!',
        int: 0,
        bool: false,
      }),
    ],
    errorProfile: NONE_PROFILE,
    execute: async ({ properties }) => {
      const type = properties.type || 'bytes';
      if (type === 'bool') return { value: Boolean(properties.valueBool) };
      const raw = type === 'string' ? properties.valueString : type === 'int' ? properties.valueInt : properties.valueBytes;
      return { value: fixedValue(type, raw) };
    },
  },
  {
    type: 'input-random',
    label: 'Random Value',
    category: 'input',
    description: 'Generates a cryptographically secure random value of a user-selected type (bytes/string/int/bool)',
    size: 'small',
    inputs: [],
    outputs: [
      // Output port id stays 'bytes' for backward compatibility with existing saved graphs even
      // when `type` selects string/int/bool — only dataType/name reflect the real value type.
      { id: 'bytes', name: 'Value', dataType: 'bytes', description: 'Cryptographically random value' },
    ],
    propertySchema: [
      typeSelectField('bytes'),
      {
        id: 'length',
        label: 'Length',
        type: 'number',
        defaultValue: 16,
        description: 'Byte length (Bytes type) or character count (String type)',
        showWhen: (p) => p.type !== 'int' && p.type !== 'bool',
      },
      {
        id: 'intMin',
        label: 'Min',
        type: 'number',
        defaultValue: 0,
        showWhen: (p) => p.type === 'int',
      },
      {
        id: 'intMax',
        label: 'Max',
        type: 'number',
        defaultValue: 100,
        showWhen: (p) => p.type === 'int',
      },
    ],
    errorProfile: NONE_PROFILE,
    execute: async ({ properties }) => ({
      bytes: randomValue(properties.type || 'bytes', { length: properties.length, min: properties.intMin, max: properties.intMax }),
    }),
  },

  {
    // ValueSet (node-catalog.md ND-1.11, workflow-spec.md §3.2.1): each output port is a row; its
    // mode/value live in properties.rows[portId]. A row with no entry yet (freshly added) is fixed
    // with the type's empty value. 'input' rows get a same-id input port (synced by the store).
    type: VALUE_SET_NODE_TYPE,
    label: 'ValueSet',
    rowValueRefs: true,
    category: 'input',
    description: 'A value set: each row is an output port whose value is fixed, random, or taken from its own input port',
    size: 'small',
    dynamicOutputs: {
      min: 2, // one row + the reserved set port
      defaultNamePrefix: 'Value',
      defaultDataType: 'bytes',
    },
    inputs: [],
    outputs: [{ id: 'out_1', name: 'Value 1', dataType: 'bytes', description: 'Value 1 output' }, SET_PORT],
    propertySchema: [],
    errorProfile: NONE_PROFILE,
    execute: async ({ inputs, properties, outputPorts }) => {
      const rows = properties.rows || {};
      const outputs: Record<string, any> = {};
      for (const port of (outputPorts || []).filter((p) => p.id !== SET_PORT_ID)) {
        const row = rows[port.id] || {};
        outputs[port.id] =
          row.mode === 'input' ? inputs[port.id]
          : row.mode === 'random' ? randomValue(port.dataType, row)
          : fixedValue(port.dataType, row.value);
      }
      outputs[SET_PORT_ID] = (outputPorts || []).filter((p) => p.id !== SET_PORT_ID).map((p) => outputs[p.id]);
      return outputs;
    },
  },

  {
    // Switch (node-catalog.md ND-1.12): unpacks the active set into the baseline set's row ports.
    // Output ports mirror the baseline (first connected) ValueSet and are synced by the store; the
    // runner only wires the active input's edge (links.ts getEffectiveEdges, D-07).
    type: SWITCH_NODE_TYPE,
    label: 'Switch',
    category: 'input',
    description: 'Picks one of several value sets and unpacks it into individual output ports',
    size: 'small',
    dynamicInputs: { min: 1, defaultNamePrefix: 'Set', defaultDataType: 'set' },
    inputs: [{ id: 'in_1', name: 'Set 1', dataType: 'set', required: false, description: 'Value set input' }],
    outputs: [],
    propertySchema: [],
    errorProfile: {
      kind: 'fixed',
      cases: [fixedCase('SET_SCHEMA_MISMATCH')],
    },
    execute: async ({ inputs, properties, inputPorts, outputPorts }) => {
      const active = properties.activeInput || (inputPorts || []).find((p) => inputs[p.id] !== undefined)?.id;
      const set = active ? inputs[active] : undefined;
      const rows = outputPorts || [];
      if (!Array.isArray(set) || set.length !== rows.length || rows.some((p, i) => !matchesType(p.dataType, set[i]))) {
        throw new NodeError('SET_SCHEMA_MISMATCH', tmsg('errors:node.SET_SCHEMA_MISMATCH'));
      }
      return Object.fromEntries(rows.map((p, i) => [p.id, set[i]]));
    },
  },

  // User Input Dialog (ND-1.2)
  {
    type: 'input-dialog',
    label: 'User Input Dialog',
    category: 'input',
    description: 'Prompts user for runtime input via dialog or fallback test value, of a user-selected type',
    inputs: [],
    outputs: [
      // Output port id stays 'string' for backward compatibility with existing saved graphs even
      // when `type` selects bytes/int/bool — only dataType/name reflect the real value type.
      { id: 'string', name: 'Value', dataType: 'string', description: 'User input value' },
    ],
    propertySchema: [
      typeSelectField('string'),
      {
        id: 'promptMessage',
        label: 'Prompt Message',
        type: 'text',
        defaultValue: 'Enter value:',
        description: 'Prompt message displayed to user',
      },
      ...makeTypedValueFields('default', 'Default Value', {
        bytes: '00112233445566778899aabbccddeeff',
        string: 'Hello NodeCrypto',
        int: 0,
        bool: false,
      }),
    ],
    errorProfile: NONE_PROFILE,
    execute: async ({ properties, log }) => {
      const type = properties.type || 'string';
      const promptMsg = String(properties.promptMessage || 'Enter value:');

      const defaultRaw =
        type === 'bytes' ? String(properties.defaultBytes ?? '')
        : type === 'int' ? String(properties.defaultInt ?? 0)
        : type === 'bool' ? String(Boolean(properties.defaultBool))
        : String(properties.defaultString ?? '');

      let raw = defaultRaw;
      if (typeof window !== 'undefined' && typeof window.prompt === 'function' && !properties.useMock) {
        const userInput = window.prompt(promptMsg, defaultRaw);
        if (userInput !== null) {
          raw = userInput;
        }
      }

      log(`User Input Dialog resolved (${type}): ${raw.length} chars`);

      if (type === 'bytes') {
        const cleanHex = raw.replace(/\s+/g, '');
        return { string: hexToBytes(cleanHex) };
      }
      if (type === 'int') {
        return { string: Number(raw) || 0 };
      }
      if (type === 'bool') {
        const normalized = raw.trim().toLowerCase();
        return { string: normalized === 'true' || normalized === '1' || normalized === 'yes' };
      }
      return { string: raw };
    },
  },
  {
    type: 'output-inspector',
    label: 'Output Inspector',
    category: 'input',
    description: 'Captures and displays inspected values in the Output console window',
    inputs: [
      { id: 'data', name: 'In', dataType: 'any', required: true, description: 'Data of any type to inspect' },
    ],
    outputs: [],
    propertySchema: [],
    errorProfile: NONE_PROFILE,
    execute: async ({ nodeId, nodeLabel, inputs, log }) => {
      const val = inputs.data !== undefined ? inputs.data : inputs.in;
      log(`Inspecting data of type: ${val instanceof Uint8Array ? 'bytes' : typeof val}`);

      let dataType: any = 'any';
      let formattedPreview = '';

      if (val instanceof Uint8Array) {
        dataType = 'bytes';
        formattedPreview = bytesToHex(val.slice(0, 32)) + (val.length > 32 ? '...' : '');
      } else if (typeof val === 'boolean') {
        dataType = 'bool';
        formattedPreview = val ? 'TRUE' : 'FALSE';
      } else if (typeof val === 'number' || typeof val === 'bigint') {
        dataType = 'int';
        formattedPreview = String(val);
      } else if (typeof val === 'string') {
        dataType = 'string';
        formattedPreview = val.length > 60 ? val.slice(0, 60) + '...' : val;
      } else {
        dataType = 'any';
        formattedPreview = typeof val === 'object' && val !== null ? JSON.stringify(val) : String(val ?? '');
      }

      const recordPayload = {
        nodeId: nodeId || 'output-inspector',
        nodeLabel: nodeLabel || 'Output Inspector',
        portId: 'data',
        dataType,
        rawValue: val,
        formattedPreview,
      };

      await emitOutputRecord(recordPayload);

      return {};
    },
  },
  {
    type: 'workflow-input',
    label: 'Workflow Input',
    category: 'input',
    description: 'Workflow ingress interface. Injects external API inputs or custom-node caller parameters.',
    size: 'small',
    dynamicOutputs: {
      min: 0,
      defaultNamePrefix: 'Arg',
      defaultDataType: 'bytes',
    },
    inputs: [],
    outputs: [],
    propertySchema: [],
    errorProfile: {
      kind: 'fixed' as const,
      cases: [fixedCase('INPUT_CONSTRAINT_VIOLATION')],
    },
    execute: async ({ properties, outputPorts, log }) => {
      log('Workflow Input activated');
      const outputs: Record<string, any> = {};

      // Prefer properties.injectedValues (set by useWorkflowStore/customNode wrappers) when
      // present: it holds exactly the current run's injected values, whereas `properties`
      // itself can accumulate stale keys from earlier runs (e.g. a removed dynamic port).
      // Bare `properties` is the fallback for direct/programmatic DAG execution (see
      // tests/dag/task_entry_exit.test.ts), which never sets injectedValues at all.
      const injected = properties.injectedValues || properties;

      for (const [key, val] of Object.entries(injected)) {
        if (key === 'injectedValues') continue;
        outputs[key] = val;
      }

      // execution-semantics.md §4.3: check each port's declared constraint before any downstream node runs
      for (const port of outputPorts || []) {
        const why = checkConstraint(port, outputs[port.id]);
        if (why) throw new NodeError('INPUT_CONSTRAINT_VIOLATION', why);
      }

      return outputs;
    },
  },
  {
    type: 'workflow-output',
    label: 'Workflow Output',
    category: 'input',
    description: 'Workflow egress interface. Gathers final pipeline results for API response or caller return.',
    size: 'small',
    dynamicInputs: {
      min: 0,
      defaultNamePrefix: 'Return',
      defaultDataType: 'bytes',
    },
    inputs: [],
    outputs: [],
    propertySchema: [],
    errorProfile: NONE_PROFILE,
    execute: async ({ inputs, log }) => {
      log(`Workflow Output gathered ${Object.keys(inputs).length} return values`);
      return {
        result: { ...inputs },
        ...inputs,
      };
    },
  },

  // 8. Webhook / API Input (ND-1.7)
  {
    type: 'input-webhook-api',
    label: 'Webhook / API Input',
    category: 'input',
    description: 'Fetches HTTP payload or Webhook response into workflow',
    inputs: [
      { id: 'url', name: 'URL Override', dataType: 'string', required: false },
      { id: 'body', name: 'Request Body', dataType: 'any', required: false },
    ],
    outputs: [
      { id: 'data', name: 'Response Bytes', dataType: 'bytes', description: 'Response byte payload' },
      { id: 'status', name: 'HTTP Status', dataType: 'int', description: 'Status code' },
    ],
    propertySchema: [
      {
        id: 'url',
        label: 'Endpoint URL',
        type: 'text',
        defaultValue: 'https://httpbin.org/get',
      },
      {
        id: 'method',
        label: 'HTTP Method',
        type: 'select',
        options: [
          { label: 'GET', value: 'GET' },
          { label: 'POST', value: 'POST' },
        ],
        defaultValue: 'GET',
      },
      {
        id: 'mockResponse',
        label: 'Mock Response (Offline / Fallback)',
        type: 'textarea',
        defaultValue: '{"status":"ok","source":"mock-api"}',
      },
    ],
    errorProfile: NONE_PROFILE,
    execute: async ({ inputs, properties, log }) => {
      const targetUrl = String(inputs.url || properties.url || 'https://httpbin.org/get');
      const method = properties.method || 'GET';
      const mockStr = String(properties.mockResponse ?? '{"status":"ok"}');

      let responseText = mockStr;
      let statusCode = 200;

      if (typeof fetch === 'function' && !properties.useMock) {
        try {
          log(`Sending HTTP ${method} to ${targetUrl}`);
          const res = await fetch(targetUrl, {
            method,
            body: method === 'POST' && inputs.body ? (typeof inputs.body === 'string' ? inputs.body : JSON.stringify(inputs.body)) : undefined,
          });
          statusCode = res.status;
          responseText = await res.text();
        } catch (err: any) {
          log(`HTTP request failed (${err?.message || err}). Using fallback mock response.`);
          responseText = mockStr;
          statusCode = 200;
        }
      } else {
        log('Using mock response for Webhook/API');
      }

      const bytes = utf8ToBytes(responseText);
      return {
        data: bytes,
        status: statusCode,
      };
    },
  },
  {
    // Link (TASK_031 / PRD [ND-1.21]): symbolic link to another node's output port. Created from a
    // port (right-click / grip drag), never from the palette. properties = { sourceNodeId, sourcePortId };
    // the runner adds an implicit edge source-port -> `in`, so this node only passes the value through.
    type: 'link',
    label: 'Link',
    category: 'input',
    description: 'Symbolic link to an output port. Copy freely to avoid tangled connection lines.',
    size: 'small',
    hidden: true,
    inputs: [{ id: 'in', name: 'In', dataType: 'any', required: true, description: 'Value of the linked output port' }],
    outputs: [{ id: 'out', name: 'Out', dataType: 'any', description: 'Same value as the linked output port' }],
    propertySchema: [],
    errorProfile: NONE_PROFILE,
    execute: async ({ inputs }) => ({ out: inputs.in }),
  },
  {
    // Link Box (TASK_031 P2 / PRD [ND-1.22]): a React Flow parent node that groups link children
    // (drag one in/out to add/remove it -- see settleLinkMembership). No ports; not part of the DAG.
    type: 'link-box',
    label: 'Link Box',
    category: 'input',
    description: 'Groups links into a named set (e.g. Key/IV/AAD) that moves together.',
    hidden: false,
    inputs: [],
    outputs: [],
    propertySchema: [],
    errorProfile: NONE_PROFILE,
    execute: async () => ({}),
  },
];
