import { describe, it, expect } from 'vitest';
import {
  bytesToHex,
  hexToBytes,
  bytesToBase64,
  base64ToBytes,
  bytesToBase58,
  base58ToBytes,
  bytesToString,
  stringToBytes,
  bytesToMultibase,
  multibaseToBytes,
} from 'nodecrypto-engine/crypto/utils/encoding';
import { defaultNodeRegistry } from 'nodecrypto-engine/registry/nodeRegistry';

describe('Data Type Refactoring & Converter Nodes (TASK_005)', () => {
  const helloBytes = new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f]); // "Hello"

  describe('1. Encoding / Decoding Utilities', () => {
    it('handles Hex encoding and decoding with prefix/spaces', () => {
      expect(bytesToHex(helloBytes)).toBe('48656c6c6f');
      expect(bytesToHex(helloBytes, { separator: 'space' })).toBe('48 65 6c 6c 6f');
      expect(bytesToHex(helloBytes, { uppercase: true })).toBe('48656C6C6F');
      expect(bytesToHex(helloBytes, { prefix0x: true, uppercase: true })).toBe('0x48656C6C6F');

      expect(hexToBytes('48656c6c6f')).toEqual(helloBytes);
      expect(hexToBytes('0x48656c6c6f')).toEqual(helloBytes);
      expect(hexToBytes('48 65 6c 6c 6f')).toEqual(helloBytes);
    });

    it('handles Base64 standard and URL-safe with padding options', () => {
      const data = new Uint8Array([0xfb, 0xff, 0xfe]);
      const b64Std = bytesToBase64(data, { urlSafe: false, padding: true });
      expect(b64Std).toBe('+//+');
      expect(base64ToBytes(b64Std)).toEqual(data);

      const b64Url = bytesToBase64(data, { urlSafe: true, padding: false });
      expect(b64Url).toBe('-__-');
      expect(base64ToBytes(b64Url)).toEqual(data);
    });

    it('handles Base58 Bitcoin and Flickr alphabets with leading zeros', () => {
      expect(bytesToBase58(helloBytes, 'btc')).toBe('9Ajdvzr');
      expect(base58ToBytes('9Ajdvzr', 'btc')).toEqual(helloBytes);

      // Leading zero bytes preservation in Base58
      const leadingZeros = new Uint8Array([0x00, 0x00, 0x48, 0x65]);
      const b58Btc = bytesToBase58(leadingZeros, 'btc');
      expect(b58Btc.startsWith('11')).toBe(true);
      expect(base58ToBytes(b58Btc, 'btc')).toEqual(leadingZeros);

      // Flickr alphabet
      const b58Flickr = bytesToBase58(helloBytes, 'flickr');
      expect(base58ToBytes(b58Flickr, 'flickr')).toEqual(helloBytes);
    });

    it('handles String encoding and decoding (UTF-8, Latin1, ASCII)', () => {
      expect(bytesToString(helloBytes, 'utf-8')).toBe('Hello');
      expect(stringToBytes('Hello', 'utf-8')).toEqual(helloBytes);

      const koreanStr = '안녕하세요 NodeCrypto';
      const korBytes = stringToBytes(koreanStr, 'utf-8');
      expect(bytesToString(korBytes, 'utf-8')).toBe(koreanStr);
    });

    it('handles Multibase encoding and decoding with standard prefixes', () => {
      // base16 (f)
      const mbHex = bytesToMultibase(helloBytes, 'base16');
      expect(mbHex).toBe('f48656c6c6f');
      expect(multibaseToBytes(mbHex).bytes).toEqual(helloBytes);
      expect(multibaseToBytes(mbHex).base).toBe('base16');

      // base58btc (z)
      const mbBtc = bytesToMultibase(helloBytes, 'base58btc');
      expect(mbBtc).toBe('z9Ajdvzr');
      expect(multibaseToBytes(mbBtc).bytes).toEqual(helloBytes);

      // base64 (m)
      const mb64 = bytesToMultibase(helloBytes, 'base64');
      expect(mb64.startsWith('m')).toBe(true);
      expect(multibaseToBytes(mb64).bytes).toEqual(helloBytes);

      // base64url (u)
      const mb64url = bytesToMultibase(helloBytes, 'base64url');
      expect(mb64url.startsWith('u')).toBe(true);
      expect(multibaseToBytes(mb64url).bytes).toEqual(helloBytes);
    });
  });

  describe('2. Converter Micro Nodes Execution', () => {
    it('executes converter-bytes-to-hex and converter-hex-to-bytes', async () => {
      const b2h = defaultNodeRegistry.get('converter-bytes-to-hex')!;
      const h2b = defaultNodeRegistry.get('converter-hex-to-bytes')!;
      expect(b2h).toBeDefined();
      expect(h2b).toBeDefined();

      const b2hRes = await b2h.execute({
        inputs: { bytes: helloBytes },
        properties: { case: 'upper', separator: 'space' },
        log: () => {},
      });
      expect(b2hRes.string).toBe('48 65 6C 6C 6F');

      const h2bRes = await h2b.execute({
        inputs: { string: b2hRes.string },
        properties: {},
        log: () => {},
      });
      expect(h2bRes.bytes).toEqual(helloBytes);
    });

    it('executes converter-bytes-to-base64 and converter-base64-to-bytes', async () => {
      const b2b64 = defaultNodeRegistry.get('converter-bytes-to-base64')!;
      const b642b = defaultNodeRegistry.get('converter-base64-to-bytes')!;
      expect(b2b64).toBeDefined();
      expect(b642b).toBeDefined();

      const b2b64Res = await b2b64.execute({
        inputs: { bytes: helloBytes },
        properties: { urlSafe: true, padding: false },
        log: () => {},
      });
      expect(b2b64Res.string).toBe('SGVsbG8');

      const b642bRes = await b642b.execute({
        inputs: { string: 'SGVsbG8' },
        properties: {},
        log: () => {},
      });
      expect(b642bRes.bytes).toEqual(helloBytes);
    });

    it('executes converter-bytes-to-base58 and converter-base58-to-bytes', async () => {
      const b2b58 = defaultNodeRegistry.get('converter-bytes-to-base58')!;
      const b582b = defaultNodeRegistry.get('converter-base58-to-bytes')!;
      expect(b2b58).toBeDefined();
      expect(b582b).toBeDefined();

      const b2b58Res = await b2b58.execute({
        inputs: { bytes: helloBytes },
        properties: { alphabet: 'btc' },
        log: () => {},
      });
      expect(b2b58Res.string).toBe('9Ajdvzr');

      const b582bRes = await b582b.execute({
        inputs: { string: '9Ajdvzr' },
        properties: { alphabet: 'btc' },
        log: () => {},
      });
      expect(b582bRes.bytes).toEqual(helloBytes);
    });

    it('executes converter-bytes-to-string and converter-string-to-bytes', async () => {
      const b2s = defaultNodeRegistry.get('converter-bytes-to-string')!;
      const s2b = defaultNodeRegistry.get('converter-string-to-bytes')!;
      expect(b2s).toBeDefined();
      expect(s2b).toBeDefined();

      const b2sRes = await b2s.execute({
        inputs: { bytes: helloBytes },
        properties: { encoding: 'utf-8' },
        log: () => {},
      });
      expect(b2sRes.string).toBe('Hello');

      const s2bRes = await s2b.execute({
        inputs: { string: 'Hello' },
        properties: { encoding: 'utf-8' },
        log: () => {},
      });
      expect(s2bRes.bytes).toEqual(helloBytes);
    });

    it('executes converter-bytes-to-multibase and converter-multibase-to-bytes', async () => {
      const b2mb = defaultNodeRegistry.get('converter-bytes-to-multibase')!;
      const mb2b = defaultNodeRegistry.get('converter-multibase-to-bytes')!;
      expect(b2mb).toBeDefined();
      expect(mb2b).toBeDefined();

      const b2mbRes = await b2mb.execute({
        inputs: { bytes: helloBytes },
        properties: { base: 'base58btc' },
        log: () => {},
      });
      expect(b2mbRes.string).toBe('z9Ajdvzr');

      const mb2bRes = await mb2b.execute({
        inputs: { string: 'z9Ajdvzr' },
        properties: {},
        log: () => {},
      });
      expect(mb2bRes.bytes).toEqual(helloBytes);
    });

    it('handles invalid inputs gracefully in converters', async () => {
      const h2b = defaultNodeRegistry.get('converter-hex-to-bytes')!;
      await expect(
        h2b.execute({
          inputs: { string: 'not-a-valid-hex-zzz' },
          properties: {},
          log: () => {},
        })
      ).rejects.toThrow();

      const mb2b = defaultNodeRegistry.get('converter-multibase-to-bytes')!;
      await expect(
        mb2b.execute({
          inputs: { string: 'x_invalid_prefix' },
          properties: {},
          log: () => {},
        })
      ).rejects.toThrow();
    });
  });
});
