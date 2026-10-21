/**
 * Translatable engine messages (i18n.md §6). The engine never holds a translated sentence:
 * it holds a key + params, and the English text for the key doubles as the default `message`.
 * Key form: `<namespace>:<dotted.path>` into locales/<lang>/<namespace>.json (errors, script).
 * Deliberately free of i18next/React so the engine stays shareable with the API container.
 */
import errorsEn from './locales/en/errors.json';
import scriptEn from './locales/en/script.json';

export type MsgParams = Record<string, string | number | bigint | boolean | Msg | null | undefined>;
export interface Msg { key: string; params?: MsgParams }
export const isMsg = (v: unknown): v is Msg => typeof v === 'object' && v !== null && typeof (v as Msg).key === 'string';

const EN: Record<string, unknown> = { errors: errorsEn, script: scriptEn };

export const tmsg = (key: string, params?: MsgParams): Msg => ({ key, params });

const lookup = (key: string): string | undefined => {
  const [ns, path] = key.split(':');
  const v = path?.split('.').reduce<any>((o, k) => o?.[k], EN[ns]);
  return typeof v === 'string' ? v : undefined;
};

/** English default text of a message; an unknown key shows the key itself so a missing entry is visible. */
export function formatMsg({ key, params = {} }: Msg): string {
  return (lookup(key) ?? key).replace(/\{\{\s*(\w+)\s*\}\}/g, (_, n) => (isMsg(params[n]) ? formatMsg(params[n] as Msg) : String(params[n] ?? '')));
}
