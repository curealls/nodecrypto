/**
 * Auto layout for nodes without a position (authoring.md §2.5): column = schedule stage, row = order within the stage.
 * Deliberately naive; people tidy up on the canvas.
 */
import { DAGScheduler } from '../dag/scheduler';

const ORIGIN = 64;
const COLUMN = 400;
const ROW = 320;

/** Returns `nodes` with `position` filled in where it was missing; nodes that have one keep it. */
export function autoLayout<N extends { id: string; position?: { x: number; y: number } }>(
  nodes: N[],
  edges: { source: string; target: string }[]
): (N & { position: { x: number; y: number } })[] {
  const plan = DAGScheduler.schedule(nodes.map((n) => n.id), edges as any);
  const stage = new Map<string, number>();
  plan.stages.forEach((ids, s) => ids.forEach((id) => stage.set(id, s)));
  const rows: number[] = []; // next free row per stage
  return nodes.map((n) => {
    // Nodes left out of a cyclic plan go to one extra column; the validator reports the cycle.
    const s = stage.get(n.id) ?? plan.stages.length;
    const r = rows[s] ?? 0;
    rows[s] = r + 1;
    return { ...n, position: n.position ?? { x: ORIGIN + COLUMN * s, y: ORIGIN + ROW * r } };
  });
}
