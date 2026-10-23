/**
 * Minimal DER reader for RSA keys: SPKI (public) and PKCS#8 (private) only (node-catalog.md ND-5.10).
 * No PEM, no PKCS#1. Integers come back as big-endian unsigned bytes without the sign-padding 00.
 */

import { NodeError } from '../../dag/errors';
import { tmsg } from '../../messages';

export type RsaKeyType = 'Public' | 'Private';

export interface RsaComponents {
  n: Uint8Array;
  e: Uint8Array;
  d?: Uint8Array;
  p?: Uint8Array;
  q?: Uint8Array;
  dp?: Uint8Array;
  dq?: Uint8Array;
  qInv?: Uint8Array;
}

const TAG_INTEGER = 0x02;
const TAG_BIT_STRING = 0x03;
const TAG_OCTET_STRING = 0x04;
const TAG_NULL = 0x05;
const TAG_OID = 0x06;
const TAG_SEQUENCE = 0x30;

const OID_RSA_ENCRYPTION = '2a864886f70d010101';
const OID_RSASSA_PSS = '2a864886f70d01010a';

const fail = (detail: string): never => {
  throw new NodeError('INVALID_KEY_FORMAT', tmsg('errors:crypto.rsaKeyFormat', { detail }));
};

const toHex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

interface Tlv { tag: number; value: Uint8Array; end: number }

function readTlv(buf: Uint8Array, pos: number): Tlv {
  if (pos + 2 > buf.length) fail('truncated DER');
  const tag = buf[pos];
  let len = buf[pos + 1];
  let start = pos + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4) fail('unsupported DER length encoding');
    if (start + n > buf.length) fail('truncated DER');
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + buf[start + i];
    start += n;
  }
  if (start + len > buf.length) fail('truncated DER');
  return { tag, value: buf.subarray(start, start + len), end: start + len };
}

function readChildren(seq: Uint8Array): Tlv[] {
  const out: Tlv[] = [];
  for (let pos = 0; pos < seq.length; ) {
    const t = readTlv(seq, pos);
    out.push(t);
    pos = t.end;
  }
  return out;
}

function expect(t: Tlv | undefined, tag: number, what: string): Uint8Array {
  if (!t || t.tag !== tag) return fail(`unexpected DER structure (expected ${what})`);
  return t.value;
}

function parseSequence(der: Uint8Array): Tlv[] {
  const top = readTlv(der, 0);
  if (top.tag !== TAG_SEQUENCE) fail('not a DER SEQUENCE (PEM text is not supported)');
  if (top.end !== der.length) fail('trailing bytes after DER structure');
  return readChildren(top.value);
}

function checkAlgorithm(alg: Uint8Array) {
  const [oid, params, extra] = readChildren(alg);
  const id = toHex(expect(oid, TAG_OID, 'algorithm OID'));
  if (id === OID_RSASSA_PSS) fail('RSASSA-PSS keys are not supported (only rsaEncryption)');
  if (id !== OID_RSA_ENCRYPTION) fail('not an RSA key (algorithm OID is not rsaEncryption)');
  if (extra || (params && (params.tag !== TAG_NULL || params.value.length))) fail('invalid rsaEncryption parameters');
}

function readInteger(t: Tlv | undefined): Uint8Array {
  const v = expect(t, TAG_INTEGER, 'INTEGER');
  if (!v.length || (v[0] & 0x80)) fail('invalid INTEGER');
  let i = 0;
  while (i < v.length - 1 && v[i] === 0) i++;
  const out = v.slice(i);
  if (out.length === 1 && out[0] === 0) fail('RSA component is zero');
  return out;
}

export function decodeRsaKey(der: Uint8Array, keyType: RsaKeyType): RsaComponents {
  const outer = parseSequence(der);
  const isPrivate = outer[0]?.tag === TAG_INTEGER;
  if (isPrivate !== (keyType === 'Private')) {
    fail(`input is not a ${keyType === 'Private' ? 'PKCS#8 private' : 'SPKI public'} key`);
  }

  if (!isPrivate) {
    if (outer.length !== 2) fail('invalid SPKI structure');
    checkAlgorithm(expect(outer[0], TAG_SEQUENCE, 'AlgorithmIdentifier'));
    const bits = expect(outer[1], TAG_BIT_STRING, 'BIT STRING');
    if (bits[0] !== 0) fail('invalid BIT STRING');
    const [n, e, extra] = parseSequence(bits.subarray(1));
    if (extra) fail('invalid RSAPublicKey');
    return { n: readInteger(n), e: readInteger(e) };
  }

  if (outer.length < 3) fail('invalid PKCS#8 structure');
  if (expect(outer[0], TAG_INTEGER, 'version').length !== 1 || outer[0].value[0] !== 0) fail('unsupported PKCS#8 version');
  checkAlgorithm(expect(outer[1], TAG_SEQUENCE, 'AlgorithmIdentifier'));
  const [ver, n, e, d, p, q, dp, dq, qInv, extra] = parseSequence(expect(outer[2], TAG_OCTET_STRING, 'OCTET STRING'));
  if (extra || !qInv) fail('invalid RSAPrivateKey');
  if (expect(ver, TAG_INTEGER, 'version').length !== 1 || ver.value[0] !== 0) fail('unsupported RSAPrivateKey version');
  return {
    n: readInteger(n), e: readInteger(e), d: readInteger(d), p: readInteger(p),
    q: readInteger(q), dp: readInteger(dp), dq: readInteger(dq), qInv: readInteger(qInv),
  };
}

// ---------------------------------------------------------------------------------------------
// Encoder: N, e (, d) -> SPKI / PKCS#8 DER. p and q are recovered from N, e, d (ND-5.9).
// ---------------------------------------------------------------------------------------------

const invalid = (detail: string): never => {
  throw new NodeError('RSA_COMPONENTS_INVALID', tmsg('errors:crypto.rsaComponentsInvalid', { detail }));
};

const MAX_FACTOR_ATTEMPTS = 100;

function toBigInt(b: Uint8Array, name: string): bigint {
  let v = 0n;
  for (const x of b) v = (v << 8n) | BigInt(x);
  if (v === 0n) invalid(`${name} is empty or zero`);
  return v;
}

function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let result = 1n;
  base %= mod;
  for (; exp > 0n; exp >>= 1n) {
    if (exp & 1n) result = (result * base) % mod;
    base = (base * base) % mod;
  }
  return result;
}

function gcd(a: bigint, b: bigint): bigint {
  while (b) [a, b] = [b, a % b];
  return a;
}

function modInverse(a: bigint, m: bigint): bigint {
  let [r0, r1, s0, s1] = [m, a % m, 0n, 1n];
  while (r1) {
    const q = r0 / r1;
    [r0, r1] = [r1, r0 - q * r1];
    [s0, s1] = [s1, s0 - q * s1];
  }
  return ((s0 % m) + m) % m;
}

/** Recovers {p, q} (p > q) from (N, e, d): NIST SP 800-56B Rev.2 Appendix C, with a fixed base sequence. */
function recoverPrimes(n: bigint, e: bigint, d: bigint): { p: bigint; q: bigint } {
  let r = e * d - 1n;
  let t = 0;
  while (!(r & 1n)) { r >>= 1n; t++; }
  let p = 0n;
  for (let g = 2n; g < 2n + BigInt(MAX_FACTOR_ATTEMPTS) && !p; g++) {
    const shared = gcd(g, n);
    if (shared > 1n && shared < n) { p = shared; break; }
    let x = modPow(g, r, n);
    if (x === 1n || x === n - 1n) continue;
    for (let i = 0; i < t; i++) {
      const y = (x * x) % n;
      if (y === 1n) { p = gcd(x - 1n, n); break; }
      if (y === n - 1n) break;
      x = y;
    }
    if (p === 1n || p === n) p = 0n;
  }
  if (!p) invalid('could not recover p and q from N, e and d');
  let q = n / p;
  if (p < q) [p, q] = [q, p];
  return { p, q };
}

const derLen = (n: number) => {
  if (n < 0x80) return [n];
  const bytes: number[] = [];
  for (let v = n; v > 0; v = Math.floor(v / 256)) bytes.unshift(v % 256);
  return [0x80 | bytes.length, ...bytes];
};

const concat = (...parts: Uint8Array[]) => Uint8Array.from(parts.flatMap((p) => Array.from(p)));
const tlv = (tag: number, ...value: Uint8Array[]) => {
  const body = concat(...value);
  return concat(Uint8Array.from([tag, ...derLen(body.length)]), body);
};

function derInteger(v: bigint): Uint8Array {
  const bytes: number[] = [];
  for (let x = v; x > 0n; x >>= 8n) bytes.unshift(Number(x & 0xffn));
  if (!bytes.length) bytes.push(0);
  if (bytes[0] & 0x80) bytes.unshift(0);
  return tlv(TAG_INTEGER, Uint8Array.from(bytes));
}

const rsaAlgorithmId = () =>
  tlv(TAG_SEQUENCE, tlv(TAG_OID, Uint8Array.from(OID_RSA_ENCRYPTION.match(/../g)!.map((h) => parseInt(h, 16)))), tlv(TAG_NULL));

function checkPublic(nBytes: Uint8Array, eBytes: Uint8Array) {
  const n = toBigInt(nBytes, 'N');
  const e = toBigInt(eBytes, 'e');
  if (n < 3n || !(n & 1n)) invalid('N must be an odd integer greater than 1');
  if (e < 3n || !(e & 1n)) invalid('e must be an odd integer of at least 3');
  if (e >= n) invalid('e must be smaller than N');
  return { n, e };
}

export function encodeRsaPublicKey(nBytes: Uint8Array, eBytes: Uint8Array): Uint8Array {
  const { n, e } = checkPublic(nBytes, eBytes);
  const rsaPublicKey = tlv(TAG_SEQUENCE, derInteger(n), derInteger(e));
  return tlv(TAG_SEQUENCE, rsaAlgorithmId(), tlv(TAG_BIT_STRING, Uint8Array.of(0), rsaPublicKey));
}

export function encodeRsaPrivateKey(c: { n: Uint8Array; e: Uint8Array; d: Uint8Array }): Uint8Array {
  const { n, e } = checkPublic(c.n, c.e);
  const d = toBigInt(c.d, 'd');
  if (d <= 1n || d >= n) invalid('d must satisfy 1 < d < N');
  const { p, q } = recoverPrimes(n, e, d);
  const lambda = ((p - 1n) / gcd(p - 1n, q - 1n)) * (q - 1n);
  if (p * q !== n || (e * d - 1n) % lambda !== 0n) invalid('d does not match N and e');
  const rsaPrivateKey = tlv(
    TAG_SEQUENCE,
    ...[0n, n, e, d, p, q, d % (p - 1n), d % (q - 1n), modInverse(q, p)].map(derInteger),
  );
  return tlv(TAG_SEQUENCE, derInteger(0n), rsaAlgorithmId(), tlv(TAG_OCTET_STRING, rsaPrivateKey));
}
