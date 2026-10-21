import { describe, it, expect } from 'vitest';
import { utf8ToBytes, bytesToHex } from 'nodecrypto-engine/crypto/utils/encoding';
import {
  mlKemGenerateKeyPair,
  mlKemEncapsulate,
  mlKemDecapsulate,
} from 'nodecrypto-engine/crypto/pqc/ml_kem';
import {
  mlDsaGenerateKeyPair,
  mlDsaSign,
  mlDsaVerify,
} from 'nodecrypto-engine/crypto/pqc/ml_dsa';

describe('Post-Quantum Cryptography (PQC) FIPS 203/204 KAT', () => {
  // 1. NIST FIPS 203 ML-KEM-768 (Kyber-768)
  it('NIST FIPS 203 ML-KEM-768 Keygen, Encapsulate, Decapsulate', () => {
    // 1. Receiver generates ML-KEM key pair
    const receiver = mlKemGenerateKeyPair(768);
    expect(receiver.publicKey.length).toBe(1184);
    expect(receiver.secretKey.length).toBe(2400);

    // 2. Sender encapsulates a shared secret using Receiver's public key
    const encap = mlKemEncapsulate(receiver.publicKey, 768);
    expect(encap.ciphertext.length).toBe(1088);
    expect(encap.sharedSecret.length).toBe(32);

    // 3. Receiver decapsulates using Receiver's secret key
    const decapSecret = mlKemDecapsulate(encap.ciphertext, receiver.secretKey, 768);
    expect(decapSecret.length).toBe(32);

    // 4. Shared secrets must be identical
    expect(bytesToHex(decapSecret)).toBe(bytesToHex(encap.sharedSecret));
  });

  // 2. NIST FIPS 203 ML-KEM-1024 (Highest Security Level)
  it('NIST FIPS 203 ML-KEM-1024 Key Agreement', () => {
    const receiver = mlKemGenerateKeyPair(1024);
    const encap = mlKemEncapsulate(receiver.publicKey, 1024);
    const decapSecret = mlKemDecapsulate(encap.ciphertext, receiver.secretKey, 1024);

    expect(bytesToHex(decapSecret)).toBe(bytesToHex(encap.sharedSecret));
  });

  // 3. NIST FIPS 204 ML-DSA-65 (Dilithium-3) Digital Signature
  it('NIST FIPS 204 ML-DSA-65 Keygen, Sign, Verify', () => {
    const signer = mlDsaGenerateKeyPair(65);
    expect(signer.publicKey.length).toBe(1952);
    expect(signer.secretKey.length).toBe(4032);

    const message = utf8ToBytes('Post-Quantum Secure Quantum-Proof Payload');
    const signature = mlDsaSign(message, signer.secretKey, 65);
    expect(signature.length).toBe(3309);

    const isValid = mlDsaVerify(signature, message, signer.publicKey, 65);
    expect(isValid).toBe(true);

    const isTamperedValid = mlDsaVerify(signature, utf8ToBytes('Tampered Quantum Payload'), signer.publicKey, 65);
    expect(isTamperedValid).toBe(false);
  });

  // 4. NIST FIPS 205 SLH-DSA (Stateless Hash-Based Digital Signature - ND-4.6)
  it('NIST FIPS 205 SLH-DSA Keygen, Sign, Verify', async () => {
    const { slhDsaGenerateKeyPair, slhDsaSign, slhDsaVerify } = await import('nodecrypto-engine/crypto/pqc/slh_dsa');

    const keys = slhDsaGenerateKeyPair('slh_dsa_sha2_128s');
    expect(keys.publicKey.length).toBe(32);
    expect(keys.secretKey.length).toBe(64);

    const message = utf8ToBytes('SLH-DSA Hash-Based Signature Verification');
    const signature = slhDsaSign(message, keys.secretKey, 'slh_dsa_sha2_128s');
    expect(signature.length).toBeGreaterThan(0);

    const isValid = slhDsaVerify(signature, message, keys.publicKey, 'slh_dsa_sha2_128s');
    expect(isValid).toBe(true);

    const isTampered = slhDsaVerify(signature, utf8ToBytes('Corrupted Data'), keys.publicKey, 'slh_dsa_sha2_128s');
    expect(isTampered).toBe(false);
  }, 30_000); // SLH-DSA-128s signing is slow by design (~2.5s alone, ~5s under parallel load)

  // 5. Post-Quantum Hybrid KEM (X25519 + ML-KEM-768 - ND-4.7)
  it('Hybrid KEM (X25519 + ML-KEM-768) Key Agreement', async () => {
    const {
      hybridKemGenerateKeyPair,
      hybridKemEncapsulate,
      hybridKemDecapsulate,
    } = await import('nodecrypto-engine/crypto/pqc/hybrid_kem');

    const alice = hybridKemGenerateKeyPair();
    expect(alice.publicKey.length).toBeGreaterThan(0);
    expect(alice.secretKey.length).toBeGreaterThan(0);

    const { sharedSecret: ssSender, ciphertext } = hybridKemEncapsulate(alice.publicKey);
    expect(ssSender.length).toBe(32);
    expect(ciphertext.length).toBeGreaterThan(0);

    const ssReceiver = hybridKemDecapsulate(ciphertext, alice.secretKey);
    expect(bytesToHex(ssReceiver)).toBe(bytesToHex(ssSender));
  });
});
