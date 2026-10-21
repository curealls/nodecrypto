import { formatMsg, tmsg } from '../messages';

/** `fixed` error profile helpers shared by every node definition file (execution-semantics.md §3.1). The case message is the English text of errors:node.<code> (i18n.md §6.2). */
export const fixedCase = (code: string) => ({ code, message: formatMsg(tmsg(`errors:node.${code}`)) });
export const fixedErrorProfile = (codes: string[]) => ({ kind: 'fixed' as const, cases: codes.map(fixedCase) });
