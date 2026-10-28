import { secp256k1 } from '@noble/curves/secp256k1.js';
import { p256, p384, p521 } from '@noble/curves/nist.js';
import { weierstrass, ecdsa } from '@noble/curves/abstract/weierstrass.js';
import { sha256, sha384, sha512 } from '@noble/hashes/sha2.js';
import { NodeError } from '../../dag/errors';
import { tmsg } from '../../messages';

// @noble/curves throws plain Error for invalid key material (wrong length, out-of-range scalar,
// point not on curve). Reclassify into NodeError so asymmetricPqcNodes.ts's `fixed` errorProfile
// reflects what can actually be thrown.
function classifyLibraryError(err: unknown): NodeError {
  if (err instanceof NodeError) return err;
  const msg = err instanceof Error ? err.message : String(err);
  if (/expected|invalid|scalar|out of range|point/i.test(msg)) {
    return new NodeError('INVALID_KEY_MATERIAL', tmsg('errors:crypto.keyMaterial', { detail: msg }));
  }
  return new NodeError('UNKNOWN_ERROR', msg);
}

export type EccCurve =
  | 'secp256k1'
  | 'p256'
  | 'p384'
  | 'p521'
  | 'brainpoolP256r1'
  | 'brainpoolP384r1'
  | 'brainpoolP512r1';

export interface EccKeyPair {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
}

// RFC 5639 Brainpool Curves
const brainpoolP256r1Curve = ecdsa(
  weierstrass({
    p: BigInt('0xA9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377'),
    a: BigInt('0x7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9'),
    b: BigInt('0x26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6'),
    Gx: BigInt('0x8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262'),
    Gy: BigInt('0x547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997'),
    n: BigInt('0xA9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7'),
    h: BigInt(1),
  }),
  sha256
);

const brainpoolP384r1Curve = ecdsa(
  weierstrass({
    p: BigInt('0x8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC53'),
    a: BigInt('0x7BC382C63D8C150C3C72080ACE05AFA0C2BEA28E4FB22787139165EFBA91F90F8AA5814A503AD4EB04A8C7DD22CE2826'),
    b: BigInt('0x04A8C7DD22CE28268B39B55416F0447C2FB77DE107DCD2A62E880EA53EEB62D57CB4390295DBC9943AB78696FA504C11'),
    Gx: BigInt('0x1D1C64F068CF45FFA2A63A81B7C13F6B8847A3E77EF14FE3DB7FCAFE0CBD10E8E826E03436D646AAEF87B2E247D4AF1E'),
    Gy: BigInt('0x8ABE1D7520F9C2A45CB1EB8E95CFD55262B70B29FEEC5864E19C054FF99129280E4646217791811142820341263C5315'),
    n: BigInt('0x8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7CF3AB6AF6B7FC3103B883202E9046565'),
    h: BigInt(1),
  }),
  sha384
);

const brainpoolP512r1Curve = ecdsa(
  weierstrass({
    p: BigInt('0xAADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3'),
    a: BigInt('0x7830A3318B603B89E2327145AC234CC594CBDD8D3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CA'),
    b: BigInt('0x3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CADC083E67984050B75EBAE5DD2809BD638016F723'),
    Gx: BigInt('0x81AEE4BDD82ED9645A21322E9C4C6A9385ED9F70B5D916C1B43B62EEF4D0098EFF3B1F78E2D0D48D50D1687B93B97D5F7C6D5047406A5E688B352209BCB9F822'),
    Gy: BigInt('0x7DDE385D566332ECC0EABFA9CF7822FDF209F70024A57B1AA000C55B881F8111B2DCDE494A5F485E5BCA4BD88A2763AED1CA2B2FA8F0540678CD1E0F3AD80892'),
    n: BigInt('0xAADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA70330870553E5C414CA92619418661197FAC10471DB1D381085DDADDB58796829CA90069'),
    h: BigInt(1),
  }),
  sha512
);

function getCurveImpl(curve: EccCurve): any {
  switch (curve) {
    case 'secp256k1':
      return secp256k1;
    case 'p256':
      return p256;
    case 'p384':
      return p384;
    case 'p521':
      return p521;
    case 'brainpoolP256r1':
      return brainpoolP256r1Curve;
    case 'brainpoolP384r1':
      return brainpoolP384r1Curve;
    case 'brainpoolP512r1':
      return brainpoolP512r1Curve;
    default:
      throw new NodeError('UNSUPPORTED_ALGORITHM', `Unsupported ECC curve: ${curve}`);
  }
}

export function eccGenerateKeyPair(curve: EccCurve = 'p256'): EccKeyPair {
  const impl = getCurveImpl(curve);
  const kp = impl.keygen();
  // Return uncompressed public key if available or default representation
  const pub = impl.getPublicKey(kp.secretKey, false);
  return { privateKey: kp.secretKey, publicKey: pub };
}

export function eccSign(msgHash: Uint8Array, privateKey: Uint8Array, curve: EccCurve = 'p256'): Uint8Array {
  try {
    const impl = getCurveImpl(curve);
    // The input already is the digest (the node pre-hashes with SHA-256): sign it as is, never hash it again (node-catalog.md ND-5.5).
    return impl.sign(msgHash, privateKey, { prehash: false });
  } catch (err) {
    throw classifyLibraryError(err);
  }
}

export function eccVerify(signature: Uint8Array, msgHash: Uint8Array, publicKey: Uint8Array, curve: EccCurve = 'p256'): boolean {
  try {
    const impl = getCurveImpl(curve);
    // lowS: false accepts the high-S form too: both are valid ECDSA and other implementations (OpenSSL) produce either one.
    return impl.verify(signature, msgHash, publicKey, { prehash: false, lowS: false });
  } catch {
    return false;
  }
}

export type EcdhFormat = 'raw_x' | 'compressed' | 'uncompressed' | 'sha256_kdf';

/**
 * Computes Elliptic Curve Diffie-Hellman (ECDH) shared secret (NIST SP 800-56A / RFC 5903).
 *
 * @param privateKey Private key scalar (Uint8Array or hex string)
 * @param otherPublicKey Peer public key point (uncompressed or compressed)
 * @param curve Target elliptic curve
 * @param format Output format: 'raw_x' (NIST standard X-coord), 'compressed', 'uncompressed', 'sha256_kdf'
 * @returns Shared secret bytes
 */
export function eccSharedSecret(
  privateKey: Uint8Array,
  otherPublicKey: Uint8Array,
  curve: EccCurve = 'p256',
  format: EcdhFormat = 'raw_x'
): Uint8Array {
  try {
    const impl = getCurveImpl(curve);
    if (format === 'uncompressed') {
      return impl.getSharedSecret(privateKey, otherPublicKey, false);
    }
    const compressed = impl.getSharedSecret(privateKey, otherPublicKey, true);
    if (format === 'compressed') {
      return compressed;
    }
    const rawX = compressed.slice(1);
    if (format === 'sha256_kdf') {
      return sha256(rawX);
    }
    return rawX; // default: raw X-coordinate (NIST SP 800-56A / RFC 5903 standard)
  } catch (err) {
    throw classifyLibraryError(err);
  }
}
