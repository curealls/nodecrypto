import { Msg, formatMsg } from '../messages';

/**
 * Node execution error carrying an error code (T03, execution-semantics.md §3).
 * A plain `throw new Error(msg)` from a node's execute() still works; the runner falls back to
 * code 'UNKNOWN_ERROR' for it. The message may be a translatable `Msg` (i18n.md §6.2): `message` then
 * holds its English text and `msg` lets the UI translate it.
 */
export class NodeError extends Error {
  code: string;
  msg?: Msg;

  constructor(code: string, message: string | Msg) {
    super(typeof message === 'string' ? message : formatMsg(message));
    this.name = 'NodeError';
    this.code = code;
    if (typeof message !== 'string') this.msg = message;
  }
}
