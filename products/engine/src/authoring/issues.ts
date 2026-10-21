/** Problem item shared by the draft loader and the validator (authoring.md §4.1). */
import { tmsg, type Msg, type MsgParams } from '../messages';

export interface Issue {
  code: string;
  /** JSON location in the input, e.g. `edges[3].to`. */
  path: string;
  msg: Msg;
  hint?: string;
}

/** Message key is `errors:authoring.<code>`; its English text doubles as the default message. */
export const issue = (code: string, path: string, params?: MsgParams, hint?: string): Issue => ({
  code,
  path,
  msg: tmsg(`errors:authoring.${code}`, params),
  ...(hint ? { hint } : {}),
});

/** Edit distance with adjacent transpositions (optimal string alignment), used to suggest the nearest name. */
export function editDistance(a: string, b: string): number {
  const d: number[][] = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
  for (let j = 1; j <= b.length; j++) d[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
    }
  }
  return d[a.length][b.length];
}

/** Up to `n` candidates within edit distance 3 of `word`, nearest first. */
export const nearest = (word: string, candidates: string[], n = 3): string[] =>
  candidates.map((c) => [c, editDistance(word, c)] as const).filter(([, d]) => d <= 3).sort((a, b) => a[1] - b[1]).slice(0, n).map(([c]) => c);
