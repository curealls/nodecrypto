/**
 * DAG Topological Scheduler with Cycle Detection and Parallel Stage Partitioning
 */

import { DAGEdgeConnection } from './types';

export interface SchedulePlan {
  order: string[];              // Linear sequential execution order
  stages: string[][];           // Parallel execution stages (nodes in each stage can run concurrently)
  hasCycle: boolean;
  cycleNodes?: string[];
}

export class DAGScheduler {
  /**
   * Schedules execution of a DAG using Kahn's algorithm.
   * Returns topological order and partitioned parallel stages.
   */
  public static schedule(nodeIds: string[], edges: DAGEdgeConnection[]): SchedulePlan {
    // 1. Filter edges that connect between active nodes
    const validNodeSet = new Set(nodeIds);
    const validEdges = edges.filter(
      (e) => validNodeSet.has(e.source) && validNodeSet.has(e.target)
    );

    // 2. Build adjacency list and in-degree map
    const inDegree = new Map<string, number>();
    const adjList = new Map<string, string[]>();

    for (const id of nodeIds) {
      inDegree.set(id, 0);
      adjList.set(id, []);
    }

    for (const edge of validEdges) {
      adjList.get(edge.source)!.push(edge.target);
      inDegree.set(edge.target, (inDegree.get(edge.target) || 0) + 1);
    }

    // 3. Find all nodes with in-degree 0 (roots of DAG)
    let currentWave: string[] = [];
    for (const [id, deg] of inDegree.entries()) {
      if (deg === 0) {
        currentWave.push(id);
      }
    }

    const order: string[] = [];
    const stages: string[][] = [];

    // 4. Wave-based Kahn's algorithm
    while (currentWave.length > 0) {
      stages.push([...currentWave]);
      order.push(...currentWave);

      const nextWave: string[] = [];

      for (const node of currentWave) {
        const neighbors = adjList.get(node) || [];
        for (const neighbor of neighbors) {
          const newDeg = inDegree.get(neighbor)! - 1;
          inDegree.set(neighbor, newDeg);
          if (newDeg === 0) {
            nextWave.push(neighbor);
          }
        }
      }

      currentWave = nextWave;
    }

    // 5. Cycle check: if processed nodes < total nodes, a cycle exists
    if (order.length < nodeIds.length) {
      const remainingNodes = nodeIds.filter((id) => (inDegree.get(id) || 0) > 0);
      return {
        order: [],
        stages: [],
        hasCycle: true,
        cycleNodes: remainingNodes,
      };
    }

    return {
      order,
      stages,
      hasCycle: false,
    };
  }

  /**
   * Finds all upstream ancestor nodes required to compute a specific target node.
   */
  public static getAncestors(targetNodeId: string, edges: DAGEdgeConnection[]): string[] {
    const ancestors = new Set<string>();
    const queue = [targetNodeId];

    // Build reverse adjacency list (target -> sources)
    const reverseAdj = new Map<string, string[]>();
    for (const edge of edges) {
      if (!reverseAdj.has(edge.target)) {
        reverseAdj.set(edge.target, []);
      }
      reverseAdj.get(edge.target)!.push(edge.source);
    }

    while (queue.length > 0) {
      const curr = queue.shift()!;
      const parents = reverseAdj.get(curr) || [];
      for (const parent of parents) {
        if (!ancestors.has(parent)) {
          ancestors.add(parent);
          queue.push(parent);
        }
      }
    }

    return Array.from(ancestors);
  }
}
