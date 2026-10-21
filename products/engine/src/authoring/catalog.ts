/**
 * Node catalog generator (authoring.md §3).
 * Exports the registry as plain JSON for AI authors; `showWhen` functions become `visibleWhen` terms (§3.3).
 */
import type { NodeRegistry } from '../registry/nodeRegistry';
import type { NodeDefinition, PropertyFieldDefinition } from '../dag/types';
import { fieldVarType } from '../variables/reference';
import pkg from '../../package.json';

export const CATALOG_VERSION = 1;
const MAX_COMBINATIONS = 256;
// Same order as the NodeCategory union (node-catalog.md §3 table order); `custom` is never catalogued.
const CATEGORY_ORDER = ['input', 'converter', 'symmetric', 'asymmetric', 'pqc', 'hash', 'hash_mac', 'kdf', 'crc', 'utility'];

/** OR of terms; a term is AND of `property id -> allowed values`. */
export type VisibleWhen = Record<string, any[]>[];
type Props = Record<string, any>;

const same = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b);

function axes(def: NodeDefinition): [string, any[]][] {
  return def.propertySchema.flatMap((f): [string, any[]][] =>
    f.type === 'select' ? [[f.id, (f.options ?? []).map((o) => o.value)]] : f.type === 'boolean' ? [[f.id, [true, false]]] : []);
}

function combinations(def: NodeDefinition): Props[] {
  const base: Props = Object.fromEntries(def.propertySchema.map((f) => [f.id, f.defaultValue]));
  let combos: Props[] = [base];
  for (const [id, values] of axes(def)) combos = combos.flatMap((c) => values.map((v) => ({ ...c, [id]: v })));
  if (combos.length > MAX_COMBINATIONS) throw new Error(`Node '${def.type}': ${combos.length} property combinations exceed ${MAX_COMBINATIONS} (authoring.md §3.3)`);
  return combos;
}

/**
 * Where a port/property of `def` exists, as `visibleWhen`. Returns undefined when always visible, `[]` when never.
 * `show` is the item's showWhen; only select/boolean properties of `def` are varied (others stay at their default).
 */
export function visibleWhen(def: NodeDefinition, show: ((p: Props) => boolean) | undefined): VisibleWhen | undefined {
  if (!show) return undefined;
  const combos = combinations(def);
  const visible = combos.filter(show);
  if (visible.length === combos.length) return undefined;
  if (!visible.length) return [];

  // Relevant properties: changing only that one flips visibility for some combination.
  const ax = axes(def);
  const relevant = ax.filter(([id, values]) => combos.some((c) => values.some((v) => show({ ...c, [id]: v }) !== show(c)))).map(([id]) => id);

  let terms: Record<string, any[]>[] = [];
  for (const c of visible) {
    const t = Object.fromEntries(relevant.map((id) => [id, [c[id]]]));
    if (!terms.some((x) => same(x, t))) terms.push(t);
  }
  // Merge terms that differ in exactly one property (greedy, not guaranteed minimal).
  for (let merged = true; merged; ) {
    merged = false;
    outer: for (let i = 0; i < terms.length; i++) {
      for (let j = i + 1; j < terms.length; j++) {
        const diff = relevant.filter((id) => !same(terms[i][id], terms[j][id]));
        if (diff.length !== 1) continue;
        const id = diff[0];
        terms[i] = { ...terms[i], [id]: [...terms[i][id], ...terms[j][id]] };
        terms.splice(j, 1);
        merged = true;
        break outer;
      }
    }
  }
  const values = new Map(ax);
  return terms.map((t) => Object.fromEntries(relevant.map((id) => [id, [...t[id]].sort((a, b) => values.get(id)!.findIndex((v) => same(v, a)) - values.get(id)!.findIndex((v) => same(v, b)))])));
}

const compact = <T extends object>(o: T) => Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined)) as T;

function port(def: NodeDefinition, p: NodeDefinition['inputs'][number], isInput: boolean) {
  return compact({
    id: p.id,
    name: p.name,
    dataType: p.dataType,
    required: isInput ? Boolean(p.required) : undefined,
    spec: p.spec,
    description: p.description,
    visibleWhen: visibleWhen(def, p.showWhen),
  });
}

function property(def: NodeDefinition, f: PropertyFieldDefinition) {
  return compact({
    id: f.id,
    label: f.label,
    type: f.type,
    options: f.type === 'select' ? (f.options ?? []).map((o) => o.value) : undefined,
    defaultValue: f.defaultValue,
    description: f.description,
    visibleWhen: visibleWhen(def, f.showWhen),
    variable: fieldVarType(f),
  });
}

function errorProfile(def: NodeDefinition) {
  const p = def.errorProfile;
  if (!p || p.kind === 'none') return undefined;
  return p.kind === 'fixed' ? { kind: 'fixed', codes: p.cases.map((c) => c.code) } : { kind: 'judgement', port: p.port };
}

export function generateCatalog(registry: NodeRegistry) {
  const rank = (c: string) => (CATEGORY_ORDER.includes(c) ? CATEGORY_ORDER.indexOf(c) : CATEGORY_ORDER.length);
  const defs = registry.getAll().filter((d) => !d.hidden && d.category !== 'custom')
    .sort((a, b) => rank(a.category) - rank(b.category) || (a.type < b.type ? -1 : a.type > b.type ? 1 : 0));
  return {
    catalogVersion: CATALOG_VERSION,
    engineVersion: pkg.version,
    nodes: defs.map((d) => compact({
      type: d.type,
      label: d.label,
      category: d.category,
      description: d.description,
      inputs: d.inputs.map((p) => port(d, p, true)),
      outputs: d.outputs.map((p) => port(d, p, false)),
      dynamicInputs: d.dynamicInputs,
      dynamicOutputs: d.dynamicOutputs,
      properties: d.propertySchema.map((f) => property(d, f)),
      errorProfile: errorProfile(d),
      requires: d.requires,
    })),
  };
}
