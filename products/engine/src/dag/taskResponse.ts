import { bytesToHex } from '../crypto/utils/encoding';

type TaskError = { nodeId: string; code: string; message: string };

export type TaskResponse =
  | { status: 'success'; executionTimeMs: number; outputs: Record<string, unknown> }
  | { status: 'error'; error: TaskError };

/**
 * Builds the task response exactly as api-spec.md §2.1/§2.2 define it.
 * Error wins over any Task Exit output (D-05, no partial success).
 */
export function buildTaskResponse(
  exitNodes: { inputs?: { id: string; name: string }[]; outputValues?: Record<string, unknown> }[],
  taskError: TaskError | null,
  executionTimeMs: number
): TaskResponse {
  if (taskError) {
    const { code, message, nodeId } = taskError; // key order as in the spec example
    return { status: 'error', error: { code, message, nodeId } };
  }

  const outputs: Record<string, unknown> = {};
  for (const node of exitNodes) {
    for (const port of node.inputs || []) {
      const v = node.outputValues?.[port.id];
      outputs[port.name] = v instanceof Uint8Array ? bytesToHex(v) : v;
    }
  }
  return { status: 'success', executionTimeMs, outputs };
}
