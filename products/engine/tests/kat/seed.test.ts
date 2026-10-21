import { describe, expect, it } from 'vitest';
import { generateSeedRoundKeys, seedDecrypt, seedEncrypt } from '../../src/crypto/symmetric/seed';

// SEED-128 known answers: KISA "SEED 128 Algorithm Test Vectors" (the same four vectors as RFC 4269 Appendix B.1-B.4),
// with the round keys (Ki,0 Ki,1) printed there. null: the round key is not legible in the source document.
// Only the 16-byte key path is standardized; there is no standard vector for 32-byte keys.
const hex = (s: string) => Uint8Array.from(s.match(/../g) ?? [], (x) => parseInt(x, 16));
const toHex = (b: Uint8Array) => Buffer.from(b).toString('hex');
const word = (n: number) => n.toString(16).padStart(8, '0');

const VECTORS: { name: string; key: string; plaintext: string; ciphertext: string; roundKeys: ([string, string] | null)[] }[] = [
  {
    name: 'vector 1 (key 00..00)',
    key: '00000000000000000000000000000000',
    plaintext: '000102030405060708090a0b0c0d0e0f',
    ciphertext: '5ebac6e0054e166819aff1cc6d346cdb',
    roundKeys: [
      ['7c8f8c7e', 'c737a22c'],
      ['ff276cdb', 'a7ca684a'],
      ['2f9d01a1', '70049e41'],
      ['ae59b3c4', '4245e90c'],
      ['a1d6400f', 'dbc1394e'],
      ['85963508', '0c5f1fcb'],
      ['b684bda7', '61a4aeae'],
      null,
      ['76cc05d5', 'e97a7394'],
      ['50ac6f92', '1b2666e5'],
      ['65b7904a', '8ec3a7b3'],
      ['2f7e2e22', 'a2b121b9'],
      ['4d0bfde4', '4e888d9b'],
      ['631c8ddc', '4378a6c4'],
      ['216af65f', '7878c031'],
      ['71891150', '98b255b0'],
    ],
  },
  {
    name: 'vector 2 (key 00 01..0F)',
    key: '000102030405060708090a0b0c0d0e0f',
    plaintext: '00000000000000000000000000000000',
    ciphertext: 'c11f22f20140505084483597e4370f43',
    roundKeys: [
      ['c119f584', '5ae033a0'],
      ['62947390', 'a600ad14'],
      ['f6f6544e', '596c4b49'],
      ['c1a3de02', 'ce483c49'],
      ['5e742e6d', '7e25163d'],
      ['8299d2b4', '790a46ce'],
      ['ea67d836', '55f354f2'],
      ['c47329fb', 'f50db634'],
      ['2bd30235', '51679ce6'],
      ['fa8d6b76', 'a9f37e02'],
      ['8b99cc60', '0f6092d4'],
      ['bdaefcfa', '489c2242'],
      ['f6357c14', 'cfccb126'],
      ['a0aa6d85', 'f8c10774'],
      ['47f4fec5', '353ae1ba'],
      ['feccea48', 'a4ef9f9b'],
    ],
  },
  {
    name: 'vector 3 (key 47 06 48 08..)',
    key: '4706480851e61be85d74bfb3fd956185',
    plaintext: '83a2f8a288641fb9a4e9a5cc2f131c7d',
    ciphertext: 'ee54d13ebcae706d226bc3142cd40d4a',
    roundKeys: [
      ['56be4a0f', 'e9f62877'],
      ['68bcb66c', '078911dd'],
      ['5b82740b', 'fd24d09b'],
      ['8d608015', 'a120e0be'],
      ['810a75ae', '1bf223e5'],
      ['f9c0d2d0', '0f676c02'],
      ['8f9b5c84', '8a7c8ddd'],
      ['d4ab4896', '18e93447'],
      ['cf090f51', '5a4c8202'],
      ['4ec3196f', '61b1a0dc'],
      ['244e07c1', 'd0d10b12'],
      ['69917c6c', '7ff94fb3'],
      ['9a7eb482', '723b5738'],
      ['b97522c5', '39cc6349'],
      ['ffc2afd5', '1412e731'],
      ['a9af7241', 'a3e67359'],
    ],
  },
  {
    name: 'vector 4 (key 28 DB C3 BC..)',
    key: '28dbc3bc49ffd87dcfa509b11d422be7',
    plaintext: 'b41e6be2eba84a148e2eed84593c5ec7',
    ciphertext: '9b9b7bfcd1813cb95d0b3618f40f5122',
    roundKeys: [
      ['b2b11b63', '2ee9e2d1'],
      ['11967260', '71a62f24'],
      ['2e017a5a', '35dad7a7'],
      ['1b2ab5ff', 'a3ada69f'],
      ['519c9903', 'da90aaee'],
      ['29fd95ad', 'b94c3f13'],
      ['6f629d19', '8ace692f'],
      ['30a26e73', '2f22338e'],
      ['9721073a', '98ee8dae'],
      ['c597a8a9', '27dcdc97'],
      ['f5163a00', '5ffd0003'],
      ['5cbe65da', 'a73403e4'],
      ['7d5cf070', '1d3b8092'],
      ['388c702b', '1baa4945'],
      ['87d1ab5a', 'fa13fb5c'],
      ['c97d7eed', '90724a6e'],
    ],
  },
];

describe('SEED-128 known answer tests (KISA test vectors, RFC 4269 Appendix B)', () => {
  it.each(VECTORS)('$name: ECB encrypt and decrypt', ({ key, plaintext, ciphertext }) => {
    const enc = seedEncrypt({ key: hex(key), plaintext: hex(plaintext), mode: 'ECB', padding: 'None' });
    expect(toHex(enc.ciphertext)).toBe(ciphertext);
    expect(toHex(seedDecrypt({ key: hex(key), ciphertext: hex(ciphertext), mode: 'ECB', padding: 'None' }))).toBe(plaintext);
  });

  it.each(VECTORS)('$name: round keys', ({ key, roundKeys }) => {
    const got = generateSeedRoundKeys(hex(key)).map(([a, b]) => [word(a), word(b)]);
    expect(got).toHaveLength(16);
    roundKeys.forEach((rk, i) => rk && expect(got[i]).toEqual(rk));
  });
});
