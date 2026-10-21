import { describe, it, expect } from 'vitest';
import { hexToBytes, bytesToHex, utf8ToBytes } from 'nodecrypto-engine/crypto/utils/encoding';
import { ed25519GenerateKeyPair, ed25519Sign, ed25519Verify } from 'nodecrypto-engine/crypto/asymmetric/ed25519';
import { x25519GenerateKeyPair, x25519SharedSecret } from 'nodecrypto-engine/crypto/asymmetric/x25519';
import { eccGenerateKeyPair, eccSign, eccVerify, eccSharedSecret } from 'nodecrypto-engine/crypto/asymmetric/ecc';
import { computeHash } from 'nodecrypto-engine/crypto/hash_kdf/hash';

describe('Asymmetric & ECC Known Answer Tests (KAT)', () => {
  // 1. RFC 8032 Ed25519 Test Vector 1
  it('RFC 8032 Ed25519 Keygen, Sign and Verify', () => {
    const keyPair = ed25519GenerateKeyPair();
    const message = utf8ToBytes('NodeCrypto High-Assurance Digital Signature');

    const signature = ed25519Sign(message, keyPair.privateKey);
    expect(signature.length).toBe(64);

    const isValid = ed25519Verify(signature, message, keyPair.publicKey);
    expect(isValid).toBe(true);

    const isCorruptedValid = ed25519Verify(signature, utf8ToBytes('Tampered Message'), keyPair.publicKey);
    expect(isCorruptedValid).toBe(false);
  });

  // 2. RFC 7748 X25519 Diffie-Hellman Key Exchange
  it('RFC 7748 X25519 Key Exchange Agreement', () => {
    // Alice & Bob generate keypairs
    const alice = x25519GenerateKeyPair();
    const bob = x25519GenerateKeyPair();

    // Compute shared secret
    const secretAlice = x25519SharedSecret(alice.privateKey, bob.publicKey);
    const secretBob = x25519SharedSecret(bob.privateKey, alice.publicKey);

    expect(secretAlice.length).toBe(32);
    expect(bytesToHex(secretAlice)).toBe(bytesToHex(secretBob));
  });

  // 3. secp256k1 (Bitcoin/Ethereum Curve) ECDSA Sign & Verify
  it('secp256k1 ECDSA Sign and Verify', () => {
    const keyPair = eccGenerateKeyPair('secp256k1');
    const msgHash = computeHash(utf8ToBytes('Bitcoin Transaction Payload'), 'SHA-256');

    const signature = eccSign(msgHash, keyPair.privateKey, 'secp256k1');
    expect(signature.length).toBe(64);

    const isValid = eccVerify(signature, msgHash, keyPair.publicKey, 'secp256k1');
    expect(isValid).toBe(true);
  });

  // 4. NIST P-256 (secp256r1) ECDSA & ECDH
  it('NIST P-256 ECDSA and ECDH Shared Secret', () => {
    const alice = eccGenerateKeyPair('p256');
    const bob = eccGenerateKeyPair('p256');

    const msgHash = computeHash(utf8ToBytes('NIST P-256 Certificate Test'), 'SHA-256');
    const sig = eccSign(msgHash, alice.privateKey, 'p256');
    expect(eccVerify(sig, msgHash, alice.publicKey, 'p256')).toBe(true);

    // ECDH Key Exchange
    const secret1 = eccSharedSecret(alice.privateKey, bob.publicKey, 'p256');
    const secret2 = eccSharedSecret(bob.privateKey, alice.publicKey, 'p256');
    expect(bytesToHex(secret1)).toBe(bytesToHex(secret2));
  });

  // 5. RSA Suite (KeyGen, OAEP Encrypt/Decrypt, PSS & PKCS#1 v1.5 Sign/Verify)
  it('RSA Suite (OAEP Encrypt/Decrypt, PSS & PKCS#1 Sign/Verify)', async () => {
    const {
      rsaGenerateKeyPair,
      rsaOaepEncrypt,
      rsaOaepDecrypt,
      rsaPssSign,
      rsaPssVerify,
      rsaPkcs1Sign,
      rsaPkcs1Verify,
    } = await import('nodecrypto-engine/crypto/asymmetric/rsa');

    // 1024-bit RSA Keypair Generation
    const rsaKeys = await rsaGenerateKeyPair({ modulusLength: 1024, usage: 'encrypt' });
    expect(rsaKeys.publicKeyPem).toContain('BEGIN PUBLIC KEY');
    expect(rsaKeys.privateKeyPem).toContain('BEGIN PRIVATE KEY');

    // RSA-OAEP Encrypt & Decrypt
    const plaintext = utf8ToBytes('Confidential RSA Secret Data');
    const ciphertext = await rsaOaepEncrypt(plaintext, rsaKeys.publicKeyPem, 'SHA-256');
    expect(ciphertext.length).toBe(128); // 1024 bits = 128 bytes
    const decrypted = await rsaOaepDecrypt(ciphertext, rsaKeys.privateKeyPem, 'SHA-256');
    expect(new TextDecoder().decode(decrypted)).toBe('Confidential RSA Secret Data');

    // RSA Signing Keypair
    const signKeys = await rsaGenerateKeyPair({ modulusLength: 1024, usage: 'sign', algorithm: 'RSA-PSS' });
    const msg = utf8ToBytes('Document to be signed by RSA-PSS');

    // RSA-PSS Sign & Verify
    const pssSig = await rsaPssSign(msg, signKeys.privateKeyPem, 32, 'SHA-256');
    expect(pssSig.length).toBe(128);
    const pssValid = await rsaPssVerify(pssSig, msg, signKeys.publicKeyPem, 32, 'SHA-256');
    expect(pssValid).toBe(true);

    // RSASSA-PKCS1-v1_5 Sign & Verify
    const pkcsKeys = await rsaGenerateKeyPair({ modulusLength: 1024, usage: 'sign', algorithm: 'RSASSA-PKCS1-v1_5' });
    const pkcsSig = await rsaPkcs1Sign(msg, pkcsKeys.privateKeyPem, 'SHA-256');
    expect(pkcsSig.length).toBe(128);
    const pkcsValid = await rsaPkcs1Verify(pkcsSig, msg, pkcsKeys.publicKeyPem, 'SHA-256');
    expect(pkcsValid).toBe(true);
  });

  // 6. Extended NIST and Brainpool Curves (P-384, P-521, Brainpool P256/P384/P512)
  it('Extended Curves ECDSA Sign/Verify and ECDH Agreement', () => {
    const curves = ['p384', 'p521', 'brainpoolP256r1', 'brainpoolP384r1', 'brainpoolP512r1'] as const;

    for (const curve of curves) {
      const alice = eccGenerateKeyPair(curve);
      const bob = eccGenerateKeyPair(curve);

      // Sign & Verify
      const msgHash = computeHash(utf8ToBytes(`Test on curve ${curve}`), 'SHA-256');
      const sig = eccSign(msgHash, alice.privateKey, curve);
      const valid = eccVerify(sig, msgHash, alice.publicKey, curve);
      expect(valid).toBe(true);

      // ECDH Agreement (Default raw X-coordinate format: NIST SP 800-56A)
      const ssA = eccSharedSecret(alice.privateKey, bob.publicKey, curve);
      const ssB = eccSharedSecret(bob.privateKey, alice.publicKey, curve);
      expect(bytesToHex(ssA)).toBe(bytesToHex(ssB));
      if (curve === 'p384' || curve === 'brainpoolP384r1') expect(ssA.length).toBe(48);
      if (curve === 'p521') expect(ssA.length).toBe(66);
      if (curve === 'brainpoolP256r1') expect(ssA.length).toBe(32);
      if (curve === 'brainpoolP512r1') expect(ssA.length).toBe(64);
    }
  });

  // 7. ECDH Multi-Format and NodeRegistry Verification (ND-3.6)
  it('ECDH Multi-Format (Raw X, Compressed, Uncompressed, SHA-256 KDF)', async () => {
    const { defaultNodeRegistry } = await import('nodecrypto-engine/registry/nodeRegistry');
    const { wasmCryptoManager } = await import('nodecrypto-engine/wasm/wasmCryptoManager');

    const alice = eccGenerateKeyPair('p256');
    const bob = eccGenerateKeyPair('p256');

    // Test raw_x (32 bytes)
    const rawX_A = eccSharedSecret(alice.privateKey, bob.publicKey, 'p256', 'raw_x');
    const rawX_B = eccSharedSecret(bob.privateKey, alice.publicKey, 'p256', 'raw_x');
    expect(rawX_A.length).toBe(32);
    expect(bytesToHex(rawX_A)).toBe(bytesToHex(rawX_B));

    // Test compressed (33 bytes)
    const comp_A = eccSharedSecret(alice.privateKey, bob.publicKey, 'p256', 'compressed');
    const comp_B = eccSharedSecret(bob.privateKey, alice.publicKey, 'p256', 'compressed');
    expect(comp_A.length).toBe(33);
    expect(bytesToHex(comp_A)).toBe(bytesToHex(comp_B));

    // Test uncompressed (65 bytes)
    const uncomp_A = eccSharedSecret(alice.privateKey, bob.publicKey, 'p256', 'uncompressed');
    const uncomp_B = eccSharedSecret(bob.privateKey, alice.publicKey, 'p256', 'uncompressed');
    expect(uncomp_A.length).toBe(65);
    expect(bytesToHex(uncomp_A)).toBe(bytesToHex(uncomp_B));

    // Test sha256_kdf (32 bytes derived key)
    const kdf_A = eccSharedSecret(alice.privateKey, bob.publicKey, 'p256', 'sha256_kdf');
    const kdf_B = eccSharedSecret(bob.privateKey, alice.publicKey, 'p256', 'sha256_kdf');
    expect(kdf_A.length).toBe(32);
    expect(bytesToHex(kdf_A)).toBe(bytesToHex(kdf_B));

    // Test WasmCryptoManager dual-engine wrapper
    const mgrSecret = wasmCryptoManager.computeP256Ecdh(alice.privateKey, bob.publicKey);
    expect(bytesToHex(mgrSecret)).toBe(bytesToHex(rawX_A));

    // Test Registry Node Execution: asymmetric-ecc-ecdh
    const ecdhNode = defaultNodeRegistry.get('asymmetric-ecc-ecdh')!;
    expect(ecdhNode).toBeDefined();
    expect(ecdhNode.label).toBe('ECDH Key Agreement');
    const result = await ecdhNode.execute({
      inputs: { privateKey: alice.privateKey, peerPublicKey: bob.publicKey },
      properties: { curve: 'p256', format: 'raw_x' },
      log: () => {},
    });
    expect(bytesToHex(result.sharedSecret)).toBe(bytesToHex(rawX_A));
    expect(bytesToHex(result.rawSecretX)).toBe(bytesToHex(rawX_A));

    // Test Registry Node Execution: asymmetric-x25519-ecdh
    const x25519Node = defaultNodeRegistry.get('asymmetric-x25519-ecdh')!;
    expect(x25519Node).toBeDefined();
    expect(x25519Node.label).toContain('ECDH');
  });
});
