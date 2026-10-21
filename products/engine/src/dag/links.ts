/**
 * Link (symbolic link to an output port) helpers — TASK_031 / PRD [ND-1.21].
 *
 * A link node stores its target in `properties = { sourceNodeId, sourcePortId }` and is a
 * pass-through node. The runner turns that reference into an implicit edge (getEffectiveEdges),
 * so scheduling, cycle detection, partial runs and failure propagation need no special cases.
 */

import type { DAGEdgeConnection } from './types';

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

/** React Flow requires a parent node to appear before its children in the nodes array. */
export function sortParentsFirst<N extends StoreNodeLike>(nodes: N[]): N[] {
  return [...nodes.filter((n) => !n.parentId), ...nodes.filter((n) => n.parentId)];
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

/**
 * Recomputes Link Box membership for links that just finished being dragged, then re-lays-out every
 * touched box. No ReactFlow instance needed: a link's `position` is always relative to its current
 * parentId (or absolute if none), so old-parent-position + relative-position = absolute position —
 * that's all "is this link's center inside a box's bounds now" needs.
 */
export function settleLinkMembership<N extends StoreNodeLike>(nodes: N[], draggedIds: string[]): N[] {
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const abs = (n: N): { x: number; y: number } => {
    const pos = n.position || { x: 0, y: 0 };
    const parent = n.parentId && byId.get(n.parentId);
    return parent ? { x: (parent.position?.x ?? 0) + pos.x, y: (parent.position?.y ?? 0) + pos.y } : pos;
  };
  const boxes = nodes.filter(isLinkBoxNode);
  const touchedBoxes = new Set<string>();
  const updates = new Map<string, N>();

  for (const id of draggedIds) {
    const link = byId.get(id);
    if (!link || !isLinkNode(link)) continue;
    if (link.parentId) touchedBoxes.add(link.parentId);

    const a = abs(link);
    const oldParentBox = link.parentId ? byId.get(link.parentId) : undefined;
    const w = link.parentId ? rowWidthOf(oldParentBox) : currentNodeWidth(link, LINK_NODE_SIZE.width);
    const cx = a.x + w / 2;
    const cy = a.y + LINK_ROW_HEIGHT / 2;
    const box = boxes.find((b) => {
      const p = b.position!;
      const boxW = currentNodeWidth(b, LINK_BOX_WIDTH);
      const kidCount = nodes.filter((n) => n.parentId === b.id).length;
      return cx >= p.x && cx <= p.x + boxW && cy >= p.y && cy <= p.y + linkBoxHeight(kidCount);
    });

    if (box) {
      touchedBoxes.add(box.id);
      // width/height are cleared here too (not just below in layoutLinkBoxRows) so a link that
      // carried a stale top-level width from an earlier standalone resize can't shadow the row
      // width `style` is about to set (React Flow renders `node.width ?? node.style?.width`).
      updates.set(id, {
        ...link,
        parentId: box.id,
        position: { x: a.x - box.position!.x, y: a.y - box.position!.y },
        width: undefined,
        height: undefined,
      });
    } else {
      updates.set(id, {
        ...link,
        parentId: undefined,
        position: a,
        width: undefined,
        height: undefined,
        style: { width: currentNodeWidth(link, LINK_NODE_SIZE.width), height: LINK_NODE_SIZE.height },
      });
    }
  }

  let result = nodes.map((n) => updates.get(n.id) ?? n);
  for (const boxId of touchedBoxes) {
    if (result.some((n) => n.id === boxId)) result = layoutLinkBoxRows(result, boxId);
  }
  return sortParentsFirst(result);
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
  const removed = new Set(removedNodeIds);
  // A removed node's children (e.g. a deleted Link Box's links) go with it. One level of nesting exists.
  for (const n of nodes) {
    if (n.parentId && removed.has(n.parentId)) removed.add(n.id);
  }
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

  // A box that survives but lost a child link needs its rows/height recomputed.
  const affectedBoxes = new Set(
    nodes.filter((n) => removed.has(n.id) && n.parentId && !removed.has(n.parentId)).map((n) => n.parentId!)
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
