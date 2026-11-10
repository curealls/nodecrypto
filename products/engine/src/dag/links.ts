/**
 * Link (symbolic link to an output port) helpers — TASK_031 / PRD [ND-1.21].
 *
 * A link node stores its target in `properties = { sourceNodeId, sourcePortId }` and is a
 * pass-through node. The runner turns that reference into an implicit edge (getEffectiveEdges),
 * so scheduling, cycle detection, partial runs and failure propagation need no special cases.
 */

import type { DAGEdgeConnection } from './types';
import { GROUP_BAND, bodyOf, frameOf, isGroupNode, normalizeGroupData } from './groupNode';

export const SWITCH_NODE_TYPE = 'switch';

export const LINK_NODE_TYPE = 'link';
/** Implicit edges are never stored in the store; their ids carry this prefix. */
export const LINK_EDGE_PREFIX = 'link:';
/** Standalone link chip default size in px (rows are 32px so they stack in a Link Box); width is user-resizable down to LINK_MIN_WIDTH. */
export const LINK_NODE_SIZE = { width: 160, height: 32 } as const;
/** Minimum link width (user-resizable), about half the default -- small enough for a short name, still grabbable. */
export const LINK_MIN_WIDTH = 80;

export const LINK_BOX_NODE_TYPE = 'link-box';
/** Default Link Box width (user-resizable) and the horizontal padding a row keeps on each side. */
export const LINK_BOX_WIDTH = 208;
export const LINK_ROW_SIDE_PADDING = 8;
/** Box can't shrink narrower than what it takes to hold one row at LINK_MIN_WIDTH. */
export const LINK_BOX_MIN_WIDTH = LINK_MIN_WIDTH + LINK_ROW_SIDE_PADDING * 2;
export const LINK_ROW_HEIGHT = 32;
/** Vertical gap between stacked rows so adjacent dashed borders don't visually merge. */
export const LINK_ROW_GAP = 4;
const LINK_BOX_HEADER_HEIGHT = 32;
/** Breathing room above the first row and below the last, so rows don't crowd the header/bottom edge. */
const LINK_BOX_TOP_INSET = LINK_ROW_GAP;
const LINK_BOX_FOOTER_HEIGHT = 8;
/** Box height for n links (n=0 still reserves one row for the empty-state hint). */
export const linkBoxHeight = (childCount: number): number => {
  const n = Math.max(1, childCount);
  return LINK_BOX_HEADER_HEIGHT + LINK_BOX_TOP_INSET + LINK_ROW_HEIGHT * n + LINK_ROW_GAP * (n - 1) + LINK_BOX_FOOTER_HEIGHT;
};

/** A node's current (user-resized) width, falling back to a default when it's never been resized. */
export const currentNodeWidth = (n: StoreNodeLike | undefined, fallback: number): number => {
  const w = n?.data?.customWidth ?? (n?.style as any)?.width;
  return typeof w === 'number' ? w : fallback;
};
/** A Link Box's current row content width: its own width minus the padding on each side. */
const rowWidthOf = (box: StoreNodeLike | undefined): number =>
  Math.max(LINK_MIN_WIDTH, currentNodeWidth(box, LINK_BOX_WIDTH) - LINK_ROW_SIDE_PADDING * 2);

/** Minimal store-node shape (React Flow node with CryptoNodeData). */
interface StoreNodeLike {
  id: string;
  data?: any;
  parentId?: string;
  position?: { x: number; y: number };
  style?: any;
  measured?: { width?: number; height?: number };
  // React Flow renders `node.width ?? node.style?.width` -- a stale top-level width left over from
  // an earlier resize would silently shadow a fresh `style.width`, so every place here that sets a
  // link/box's `style.width` also clears these to let `style` be the single source of truth.
  width?: number;
  height?: number;
}

/** Minimal DAG-runner node shape. */
interface DagNodeLike {
  id: string;
  type: string;
  properties?: Record<string, any>;
}

export interface LinkRef {
  sourceNodeId: string;
  sourcePortId: string;
}

export const isLinkNode = (n: StoreNodeLike): boolean => (n.data?.nodeType || n.data?.type) === LINK_NODE_TYPE;
export const isLinkBoxNode = (n: StoreNodeLike): boolean => (n.data?.nodeType || n.data?.type) === LINK_BOX_NODE_TYPE;

/** Ancestor chain length (0 = top level). A missing parent ends the chain; a cycle can't loop forever. */
const depthOf = (byId: Map<string, StoreNodeLike>, n: StoreNodeLike): number => {
  let d = 0;
  for (let p = n.parentId && byId.get(n.parentId); p && d < byId.size; p = p.parentId && byId.get(p.parentId)) d++;
  return d;
};

/** React Flow requires every parent to appear before its children: stable sort by nesting depth. */
export function sortParentsFirst<N extends StoreNodeLike>(nodes: N[]): N[] {
  const byId = new Map<string, StoreNodeLike>(nodes.map((n) => [n.id, n]));
  const depth = new Map(nodes.map((n) => [n.id, depthOf(byId, n)]));
  return [...nodes].sort((a, b) => depth.get(a.id)! - depth.get(b.id)!);
}

/** Canvas position of a node: its `position` plus every ancestor's (positions are parent-relative). */
export function absolutePosition(nodes: StoreNodeLike[] | Map<string, StoreNodeLike>, n: StoreNodeLike): { x: number; y: number } {
  const byId = nodes instanceof Map ? nodes : new Map(nodes.map((m) => [m.id, m]));
  let x = n.position?.x ?? 0;
  let y = n.position?.y ?? 0;
  const seen = new Set([n.id]);
  for (let p = n.parentId && byId.get(n.parentId); p && !seen.has(p.id); p = p.parentId && byId.get(p.parentId)) {
    seen.add(p.id);
    x += p.position?.x ?? 0;
    y += p.position?.y ?? 0;
  }
  return { x, y };
}

/** The given ids plus all their descendants (children, grandchildren, ...). */
export function withDescendants(nodes: StoreNodeLike[], ids: Iterable<string>): Set<string> {
  const out = new Set(ids);
  for (let grew = true; grew; ) {
    grew = false;
    for (const n of nodes) {
      if (n.parentId && out.has(n.parentId) && !out.has(n.id)) {
        out.add(n.id);
        grew = true;
      }
    }
  }
  return out;
}

/**
 * Re-stacks a box's child links into rows (ordered by their current y, LINK_ROW_GAP apart) sized to
 * the box's own (possibly user-resized) width, and updates the box's height to fit. Pure. The box's
 * width itself is left as-is -- this never resets a resize, only reflows what's inside it.
 */
export function layoutLinkBoxRows<N extends StoreNodeLike>(nodes: N[], boxId: string): N[] {
  const box = nodes.find((n) => n.id === boxId);
  const rowWidth = rowWidthOf(box);
  const rowX = (currentNodeWidth(box, LINK_BOX_WIDTH) - rowWidth) / 2;
  const kids = nodes.filter((n) => n.parentId === boxId).sort((a, b) => (a.position?.y ?? 0) - (b.position?.y ?? 0));
  const rowIndex = new Map(kids.map((k, i) => [k.id, i]));
  return nodes.map((n) => {
    if (n.id === boxId) {
      return { ...n, style: { ...(n.style || {}), height: linkBoxHeight(kids.length) } };
    }
    const i = rowIndex.get(n.id);
    if (i === undefined) return n;
    return {
      ...n,
      position: { x: rowX, y: LINK_BOX_HEADER_HEIGHT + LINK_BOX_TOP_INSET + (LINK_ROW_HEIGHT + LINK_ROW_GAP) * i },
      width: undefined,
      height: undefined,
      style: { width: rowWidth, height: LINK_ROW_HEIGHT },
    };
  });
}

/** Rendered size of a node: measured by React Flow, else what the node itself records. */
export const sizeOf = (n: StoreNodeLike): { w: number; h: number } => ({
  w: n.measured?.width ?? n.width ?? n.style?.width ?? n.data?.width ?? n.data?.customWidth ?? 0,
  h: n.measured?.height ?? n.height ?? n.style?.height ?? n.data?.height ?? 0,
});

type Rect = { x: number; y: number; width: number; height: number };
/** A Group's body (frame minus caption band) on the canvas. */
const groupBody = (group: StoreNodeLike, at: { x: number; y: number }): Rect => {
  const g = normalizeGroupData(group.data);
  return bodyOf({ ...at, width: g.width, height: g.height }, g.captionSide, GROUP_BAND[g.captionScale]);
};

/**
 * Widens a Group so the given children (already its children) lie inside its body. Growing left/up moves the
 * Group's position and shifts every child's relative position back, so nothing moves on screen.
 */
function growGroup<N extends StoreNodeLike>(nodes: N[], groupId: string, childIds: Set<string>): N[] {
  const group = nodes.find((n) => n.id === groupId);
  if (!group) return nodes;
  const g = normalizeGroupData(group.data);
  const band = GROUP_BAND[g.captionScale];
  const body = bodyOf({ x: 0, y: 0, width: g.width, height: g.height }, g.captionSide, band);
  let [x0, y0, x1, y1] = [body.x, body.y, body.x + body.width, body.y + body.height];
  for (const c of nodes) {
    if (!childIds.has(c.id) || c.parentId !== groupId) continue;
    const { w, h } = sizeOf(c);
    x0 = Math.min(x0, c.position?.x ?? 0);
    y0 = Math.min(y0, c.position?.y ?? 0);
    x1 = Math.max(x1, (c.position?.x ?? 0) + w);
    y1 = Math.max(y1, (c.position?.y ?? 0) + h);
  }
  const f = frameOf({ x: x0, y: y0, width: x1 - x0, height: y1 - y0 }, g.captionSide, band);
  if (f.x === 0 && f.y === 0 && f.width === g.width && f.height === g.height) return nodes;
  return nodes.map((n) => {
    if (n.id === groupId) {
      const { width, height } = f;
      return { ...n, position: { x: (n.position?.x ?? 0) + f.x, y: (n.position?.y ?? 0) + f.y }, width, height, style: { ...n.style, width, height }, data: { ...n.data, width, height } };
    }
    return n.parentId === groupId ? { ...n, position: { x: (n.position?.x ?? 0) - f.x, y: (n.position?.y ?? 0) - f.y } } : n;
  });
}

/** Moves a top-level node into `group`, keeping its canvas position. */
const attachToGroup = <N extends StoreNodeLike>(n: N, group: StoreNodeLike, a: { x: number; y: number }, groupAbs: { x: number; y: number }): N => ({
  ...n,
  parentId: group.id,
  position: { x: a.x - groupAbs.x, y: a.y - groupAbs.y },
});

/**
 * Recomputes membership for objects that were just placed (dragged, added, pasted), then re-lays-out
 * every touched Link Box. No ReactFlow instance needed: positions are parent-relative, so summing up
 * the ancestor chain (absolutePosition) gives the canvas position the hit test needs.
 *
 * Only top-level placed objects are judged (a child follows its parent). A Link goes to a Link Box first,
 * then to a Group; everything else goes to the Group whose body holds its center, or out of its Group when
 * none does. A Group is never judged (it is not put in a Group, and moving one absorbs nothing).
 * Only `parentId` and positions change, so edges are untouched and canvas positions stay the same.
 */
export function settleLinkMembership<N extends StoreNodeLike>(nodes: N[], draggedIds: string[]): N[] {
  const byId = new Map<string, StoreNodeLike>(nodes.map((n) => [n.id, n]));
  const abs = (n: StoreNodeLike) => absolutePosition(byId, n);
  const boxes = nodes.filter(isLinkBoxNode);
  const groups = nodes.filter(isGroupNode).reverse(); // later in the array is drawn on top, so it wins
  const dropped = new Set(draggedIds);
  const touchedBoxes = new Set<string>();
  const grownGroups = new Map<string, Set<string>>();
  const updates = new Map<string, N>();

  for (const id of draggedIds) {
    const node = byId.get(id) as N | undefined;
    if (!node || isGroupNode(node) || (node.parentId && dropped.has(node.parentId))) continue;
    const link = isLinkNode(node);
    const a = abs(node);
    const oldParent = node.parentId ? byId.get(node.parentId) : undefined;
    if (link && oldParent && isLinkBoxNode(oldParent)) touchedBoxes.add(oldParent.id);

    const { w, h } = link ? { w: oldParent && isLinkBoxNode(oldParent) ? rowWidthOf(oldParent) : currentNodeWidth(node, LINK_NODE_SIZE.width), h: LINK_ROW_HEIGHT } : sizeOf(node);
    const cx = a.x + w / 2;
    const cy = a.y + h / 2;
    const box = link
      ? boxes.find((b) => {
          const p = abs(b);
          const boxW = currentNodeWidth(b, LINK_BOX_WIDTH);
          const kidCount = nodes.filter((n) => n.parentId === b.id).length;
          return cx >= p.x && cx <= p.x + boxW && cy >= p.y && cy <= p.y + linkBoxHeight(kidCount);
        })
      : undefined;

    if (!box) {
      const target = groups.find((gr) => {
        const b = groupBody(gr, abs(gr));
        return cx >= b.x && cx <= b.x + b.width && cy >= b.y && cy <= b.y + b.height;
      });
      if (target) {
        updates.set(id, { ...attachToGroup(node, target, a, abs(target)), ...(link ? { width: undefined, height: undefined, style: { width: currentNodeWidth(node, LINK_NODE_SIZE.width), height: LINK_NODE_SIZE.height } } : {}) });
        grownGroups.set(target.id, (grownGroups.get(target.id) ?? new Set()).add(id));
        continue;
      }
      if (!link) {
        // out of a Group (a Link Box child that isn't a Link can't exist, so only a Group parent matters)
        if (oldParent && isGroupNode(oldParent)) updates.set(id, { ...node, parentId: undefined, position: a });
        continue;
      }
    }

    if (box) {
      touchedBoxes.add(box.id);
      // width/height are cleared here too (not just below in layoutLinkBoxRows) so a link that
      // carried a stale top-level width from an earlier standalone resize can't shadow the row
      // width `style` is about to set (React Flow renders `node.width ?? node.style?.width`).
      const boxAbs = abs(box);
      updates.set(id, {
        ...node,
        parentId: box.id,
        position: { x: a.x - boxAbs.x, y: a.y - boxAbs.y },
        width: undefined,
        height: undefined,
      });
    } else {
      updates.set(id, {
        ...node,
        parentId: undefined,
        position: a,
        width: undefined,
        height: undefined,
        style: { width: currentNodeWidth(node, LINK_NODE_SIZE.width), height: LINK_NODE_SIZE.height },
      });
    }
  }

  let result = nodes.map((n) => updates.get(n.id) ?? n);
  for (const boxId of touchedBoxes) {
    if (result.some((n) => n.id === boxId)) result = layoutLinkBoxRows(result, boxId);
  }
  for (const [groupId, ids] of grownGroups) result = growGroup(result, groupId, ids);
  return sortParentsFirst(result);
}

/**
 * What dropping the objects right now would do to Groups, for the drag-time hint: Groups that would take an
 * object in ('join') and Groups an object would leave ('leave'). Same judgement as settleLinkMembership; changes nothing.
 */
export function previewGroupDrop(nodes: StoreNodeLike[], placedIds: string[]): Record<string, 'join' | 'leave'> {
  const after = new Map(settleLinkMembership(nodes, placedIds).map((n) => [n.id, n]));
  const before = new Map(nodes.map((n) => [n.id, n]));
  const out: Record<string, 'join' | 'leave'> = {};
  for (const id of placedIds) {
    const was = before.get(id)?.parentId;
    const now = after.get(id)?.parentId;
    if (was === now) continue;
    if (now && isGroupNode(before.get(now))) out[now] = 'join';
    if (was && isGroupNode(before.get(was)) && out[was] !== 'join') out[was] = 'leave';
  }
  return out;
}

/**
 * After a Group was resized: takes in every top-level object (not a Group, not already inside anything)
 * whose whole body now lies inside the Group's body.
 */
export function absorbIntoGroup<N extends StoreNodeLike>(nodes: N[], groupId: string): N[] {
  const group = nodes.find((n) => n.id === groupId);
  if (!group || !isGroupNode(group)) return nodes;
  const byId = new Map<string, StoreNodeLike>(nodes.map((n) => [n.id, n]));
  const groupAbs = absolutePosition(byId, group);
  const body = groupBody(group, groupAbs);
  const taken = new Set<string>();
  const result = nodes.map((n) => {
    if (n.id === groupId || n.parentId || isGroupNode(n)) return n;
    const a = absolutePosition(byId, n);
    const { w, h } = sizeOf(n);
    if (a.x < body.x || a.y < body.y || a.x + w > body.x + body.width || a.y + h > body.y + body.height) return n;
    taken.add(n.id);
    return attachToGroup(n, group, a, groupAbs);
  });
  return taken.size ? sortParentsFirst(result) : nodes;
}

export const linkRefOf = (n: StoreNodeLike): LinkRef | null => {
  const p = n.data?.properties;
  return p?.sourceNodeId && p?.sourcePortId ? { sourceNodeId: p.sourceNodeId, sourcePortId: p.sourcePortId } : null;
};

/** Store nodes -> the shape getEffectiveEdges / the runner expects. */
export const toDagNodes = (nodes: StoreNodeLike[]): DagNodeLike[] =>
  nodes.map((n) => ({ id: n.id, type: n.data?.nodeType || n.data?.type, properties: n.data?.properties }));

/**
 * Appends one implicit edge (source port -> link `in`) per link node whose source exists.
 * Links whose source is gone get no edge, so they fail with "Missing required inputs".
 */
export function getEffectiveEdges(
  nodes: DagNodeLike[],
  edges: DAGEdgeConnection[],
  { includeInactive = false }: { includeInactive?: boolean } = {}
): DAGEdgeConnection[] {
  // D-07: a Switch depends only on its active input's edge; the others carry no dependency.
  if (!includeInactive) {
    const active = new Map(nodes.filter((n) => n.type === SWITCH_NODE_TYPE && n.properties?.activeInput).map((n) => [n.id, n.properties!.activeInput]));
    if (active.size) edges = edges.filter((e) => !active.has(e.target) || active.get(e.target) === e.targetHandle);
  }
  const ids = new Set(nodes.map((n) => n.id));
  const implicit: DAGEdgeConnection[] = nodes
    .filter((n) => n.type === LINK_NODE_TYPE && n.properties?.sourceNodeId && ids.has(n.properties.sourceNodeId))
    .map((n) => ({
      id: `${LINK_EDGE_PREFIX}${n.id}`,
      source: n.properties!.sourceNodeId,
      sourceHandle: n.properties!.sourcePortId,
      target: n.id,
      targetHandle: 'in',
    }));
  return implicit.length ? [...edges, ...implicit] : edges;
}

/** True if adding source -> target would close a cycle (links included). PRD [3.4-9]. */
export function wouldCreateCycle(
  nodes: DagNodeLike[],
  edges: DAGEdgeConnection[],
  source: string,
  target: string
): boolean {
  if (source === target) return true;
  const next = new Map<string, string[]>();
  // Cycle check keeps the inactive Switch edges (execution-semantics.md §2.2)
  for (const e of getEffectiveEdges(nodes, edges, { includeInactive: true })) {
    next.set(e.source, [...(next.get(e.source) || []), e.target]);
  }
  // Can `target` already reach `source`? Then the new edge would loop back.
  const seen = new Set<string>();
  const stack = [target];
  while (stack.length) {
    const cur = stack.pop()!;
    if (cur === source) return true;
    if (seen.has(cur)) continue;
    seen.add(cur);
    stack.push(...(next.get(cur) || []));
  }
  return false;
}

/** Links pointing at a node (any port) or at one specific port. */
export function findLinksOfSource<T extends StoreNodeLike>(nodes: T[], nodeId: string, portId?: string): T[] {
  return nodes.filter((n) => {
    if (!isLinkNode(n)) return false;
    const ref = linkRefOf(n);
    return ref?.sourceNodeId === nodeId && (portId === undefined || ref.sourcePortId === portId);
  });
}

export interface CascadeOptions {
  removedNodeIds?: string[];
  /** Output ports that stop existing (dynamic port removed / hidden by showWhen). */
  removedPorts?: { nodeId: string; portId: string }[];
}

export interface CascadeResult<N, E> {
  nodes: N[];
  edges: E[];
  /** Links removed because their source node/port went away (excludes ids passed in removedNodeIds). */
  removedLinkCount: number;
  /** Edges removed only because a removed link carried them. */
  removedLinkEdgeCount: number;
}

/**
 * Removes the requested nodes plus every link that points at a removed node or port, and all edges
 * touching anything removed. Single choke point so delete / port removal / paste / import agree.
 */
export function cascadeLinks<N extends StoreNodeLike, E extends { source: string; target: string; sourceHandle?: string | null }>(
  nodes: N[],
  edges: E[],
  { removedNodeIds = [], removedPorts = [] }: CascadeOptions
): CascadeResult<N, E> {
  // A removed node's descendants (e.g. a deleted Link Box's links) go with it, however deep.
  const removed = withDescendants(nodes, removedNodeIds);
  const existing = new Set(nodes.map((n) => n.id));
  const linkIds = new Set<string>();
  for (const n of nodes) {
    if (removed.has(n.id) || !isLinkNode(n)) continue;
    const ref = linkRefOf(n);
    if (!ref) continue;
    const portGone = removedPorts.some((p) => p.nodeId === ref.sourceNodeId && p.portId === ref.sourcePortId);
    // A link whose source is not on this canvas at all (bad import / stale paste) is an orphan: drop it too.
    if (removed.has(ref.sourceNodeId) || portGone || !existing.has(ref.sourceNodeId)) linkIds.add(n.id);
  }
  linkIds.forEach((id) => removed.add(id));

  const keptEdges = edges.filter(
    (e) =>
      !removed.has(e.source) &&
      !removed.has(e.target) &&
      !removedPorts.some((p) => p.nodeId === e.source && p.portId === e.sourceHandle)
  );
  const removedLinkEdgeCount = edges.filter((e) => linkIds.has(e.source) && !removedNodeIds.includes(e.target)).length;

  // A box that survives but lost a child link needs its rows/height recomputed (only Link Boxes have rows).
  const boxIds = new Set(nodes.filter(isLinkBoxNode).map((n) => n.id));
  const affectedBoxes = new Set(
    nodes.filter((n) => removed.has(n.id) && n.parentId && !removed.has(n.parentId) && boxIds.has(n.parentId)).map((n) => n.parentId!)
  );
  let keptNodes = nodes.filter((n) => !removed.has(n.id));
  for (const boxId of affectedBoxes) keptNodes = layoutLinkBoxRows(keptNodes, boxId);

  return {
    nodes: keptNodes,
    edges: keptEdges,
    removedLinkCount: linkIds.size,
    removedLinkEdgeCount,
  };
}

/** "원본 노드 · 포트" text for tooltips, or null when the source is gone (the UI shows its own text). A link's own display name is its data.label (the port name at creation, user-editable). */
export function linkSourceLabel(nodes: StoreNodeLike[], ref: LinkRef | null): string | null {
  const src = ref && nodes.find((n) => n.id === ref.sourceNodeId);
  if (!src || !ref) return null;
  const port = (src.data.outputs || []).find((p: any) => p.id === ref.sourcePortId);
  return `${src.data.label} · ${port?.name ?? ref.sourcePortId}`;
}
