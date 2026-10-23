import type { NodePackage } from './package';

/** Share link body (package-format.md §6.5): `1.<base64url(deflate-raw(UTF-8 JSON))>`. */
export const SHARE_VERSION = 1;
/** Decompressed JSON limit in bytes (zip-bomb guard). */
export const SHARE_MAX_INFLATED = 2 * 1024 * 1024;
/** Whole-link length thresholds, applied by the caller to the full URL. */
export const SHARE_WARN_LENGTH = 8000;
export const SHARE_MAX_LENGTH = 64000;

export type ShareErrorCode =
  | 'SHARE_BAD_FORMAT'
  | 'SHARE_UNSUPPORTED_VERSION'
  | 'SHARE_BAD_ENCODING'
  | 'SHARE_BAD_DEFLATE'
  | 'SHARE_TOO_LARGE'
  | 'SHARE_BAD_JSON';

export class ShareError extends Error {
  constructor(public code: ShareErrorCode, message: string) {
    super(message);
    this.name = 'ShareError';
  }
}

async function pipe(data: Uint8Array, stream: CompressionStream | DecompressionStream, limit = Infinity): Promise<Uint8Array> {
  const w = stream.writable.getWriter();
  // The writer rejects too when the reader fails; the reader loop below reports the error.
  w.write(data as BufferSource).then(() => w.close()).catch(() => {});
  const chunks: Uint8Array[] = [];
  let total = 0;
  const r = stream.readable.getReader();
  for (;;) {
    const { done, value } = await r.read();
    if (done) break;
    total += value.length;
    if (total > limit) {
      await r.cancel();
      throw new ShareError('SHARE_TOO_LARGE', 'Share link content is too large.');
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let pos = 0;
  for (const c of chunks) { out.set(c, pos); pos += c.length; }
  return out;
}

export async function encodeShare(pkg: NodePackage): Promise<string> {
  const packed = await pipe(new TextEncoder().encode(JSON.stringify(pkg)), new CompressionStream('deflate-raw'));
  let bin = '';
  for (let i = 0; i < packed.length; i += 0x8000) bin += String.fromCharCode(...packed.subarray(i, i + 0x8000));
  const b64 = btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return `${SHARE_VERSION}.${b64}`;
}

export async function decodeShare(text: string): Promise<NodePackage> {
  const dot = text.indexOf('.');
  const version = dot > 0 ? text.slice(0, dot) : '';
  const body = text.slice(dot + 1);
  if (!/^\d+$/.test(version) || !body) throw new ShareError('SHARE_BAD_FORMAT', 'Share link is not in the form <version>.<body>.');
  if (Number(version) !== SHARE_VERSION) {
    throw new ShareError('SHARE_UNSUPPORTED_VERSION', `Share link version ${version} is not supported. It may come from a newer app.`);
  }
  // A base64 body can never be 1 mod 4 long (a cut-off link).
  if (!/^[A-Za-z0-9_-]+$/.test(body) || body.length % 4 === 1) {
    throw new ShareError('SHARE_BAD_ENCODING', 'Share link is damaged (invalid or cut-off encoding).');
  }
  const bin = atob(body.replace(/-/g, '+').replace(/_/g, '/'));
  const packed = Uint8Array.from(bin, (c) => c.charCodeAt(0));
  let raw: Uint8Array;
  try {
    raw = await pipe(packed, new DecompressionStream('deflate-raw'), SHARE_MAX_INFLATED);
  } catch (e) {
    if (e instanceof ShareError) throw e;
    throw new ShareError('SHARE_BAD_DEFLATE', 'Share link is damaged (cannot decompress).');
  }
  try {
    const json = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(raw));
    if (json === null || typeof json !== 'object' || Array.isArray(json)) throw new Error('not an object');
    return json as NodePackage;
  } catch {
    throw new ShareError('SHARE_BAD_JSON', 'Share link content is not a valid JSON object.');
  }
}
