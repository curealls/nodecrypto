import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { deflateRawSync } from 'node:zlib';
import { encodeShare, decodeShare, ShareError, SHARE_WARN_LENGTH, SHARE_MAX_LENGTH } from 'nodecrypto-engine/dag/shareLink';

const dir = new URL('../../../../examples/workflows/', import.meta.url);
const files = readdirSync(dir).filter((f) => f.endsWith('.ncw'));
const b64url = (b: Buffer) => b.toString('base64url');
const code = async (text: string) => decodeShare(text).then(() => 'ok', (e) => (e instanceof ShareError ? e.code : String(e)));

describe('share link codec', () => {
  it('round-trips every example and stays within the length limits', async () => {
    const rows: string[] = [];
    for (const f of files) {
      const src = readFileSync(new URL(f, dir), 'utf-8');
      const pkg = JSON.parse(src);
      const link = await encodeShare(pkg);
      expect(await decodeShare(link)).toEqual(pkg);
      expect(link).toMatch(/^1\.[A-Za-z0-9_-]+$/);
      expect(link.length).toBeLessThan(SHARE_MAX_LENGTH);
      rows.push(`${f}\t${src.length}\t${link.length}`);
    }
    console.log(`file\tjson chars\tlink chars (warn ${SHARE_WARN_LENGTH})\n${rows.join('\n')}`);
  });

  it('round-trips Korean and emoji text', async () => {
    const pkg: any = { format: 'nodecrypto', manifest: { label: '해시 계산 🔐', description: '設定 ✓' } };
    expect(await decodeShare(await encodeShare(pkg))).toEqual(pkg);
  });

  it('rejects malformed links with the documented codes', async () => {
    const ok = await encodeShare({ format: 'nodecrypto' } as any);
    const body = ok.slice(2);
    expect(await code('abc')).toBe('SHARE_BAD_FORMAT');
    expect(await code('.abc')).toBe('SHARE_BAD_FORMAT');
    expect(await code('1.')).toBe('SHARE_BAD_FORMAT');
    expect(await code('x.abc')).toBe('SHARE_BAD_FORMAT');
    expect(await code(`2.${body}`)).toBe('SHARE_UNSUPPORTED_VERSION');
    expect(await code(`1.${body}+/=`)).toBe('SHARE_BAD_ENCODING');
    expect(await code(`1.${body.slice(0, 4 * Math.floor(body.length / 4) + 1)}`)).toBe('SHARE_BAD_ENCODING');
    expect(await code(`1.${body.slice(0, body.length - 4)}`)).toBe('SHARE_BAD_DEFLATE');
    expect(await code(`1.${b64url(deflateRawSync('not json'))}`)).toBe('SHARE_BAD_JSON');
    expect(await code(`1.${b64url(deflateRawSync('[1]'))}`)).toBe('SHARE_BAD_JSON');
    expect(await code(`1.${b64url(deflateRawSync(Buffer.from([0xff, 0xfe])))}`)).toBe('SHARE_BAD_JSON');
  });

  it('rejects content that inflates beyond 2 MiB', async () => {
    const bomb = deflateRawSync(Buffer.from(`{"a":"${'x'.repeat(3 * 1024 * 1024)}"}`));
    expect(await code(`1.${b64url(bomb)}`)).toBe('SHARE_TOO_LARGE');
  });
});
