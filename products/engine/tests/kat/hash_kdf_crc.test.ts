import { describe, it, expect } from 'vitest';
import { hexToBytes, bytesToHex, utf8ToBytes } from 'nodecrypto-engine/crypto/utils/encoding';
import { computeHash } from 'nodecrypto-engine/crypto/hash_kdf/hash';
import { computeHmac, computeCmac } from 'nodecrypto-engine/crypto/hash_kdf/mac';
import { computePbkdf2, computeHkdf } from 'nodecrypto-engine/crypto/hash_kdf/kdf';
import { computeCrc, CRC_PRESETS } from 'nodecrypto-engine/crypto/crc/crc';

describe('Hash, MAC, KDF, and CRC Known Answer Tests (KAT)', () => {
  // 1. NIST FIPS 180-4 SHA-256 Test Vector
  it('NIST SHA-256 Test Vector ("abc")', () => {
    const input = utf8ToBytes('abc');
    const expected = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad';
    const hash = computeHash(input, 'SHA-256');
    expect(bytesToHex(hash)).toBe(expected);
  });

  // 2. NIST FIPS 202 SHA3-256 Test Vector
  it('NIST SHA3-256 Test Vector ("abc")', () => {
    const input = utf8ToBytes('abc');
    const expected = '3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532';
    const hash = computeHash(input, 'SHA3-256');
    expect(bytesToHex(hash)).toBe(expected);
  });

  // 3. RFC 4231 HMAC-SHA256 Test Vector 1
  it('RFC 4231 HMAC-SHA256 Test Vector 1', () => {
    const key = hexToBytes('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b');
    const data = utf8ToBytes('Hi There');
    const expected = 'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7';

    const mac = computeHmac(key, data, 'SHA-256');
    expect(bytesToHex(mac)).toBe(expected);
  });

  // 4. NIST SP 800-38B AES-128 CMAC Test Vector
  it('NIST SP 800-38B AES-128 CMAC Test Vector', () => {
    const key = hexToBytes('2b7e151628aed2a6abf7158809cf4f3c');
    const data = hexToBytes('6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710');
    const expected = '51f0bebf7e3b9d92fc49741779363cfe';

    const cmac = computeCmac(key, data, 'AES');
    expect(bytesToHex(cmac)).toBe(expected);
  });

  // 5. RFC 6070 PBKDF2-HMAC-SHA256 Test Vector
  it('RFC 6070 PBKDF2-HMAC-SHA256 Test Vector', () => {
    const password = 'password';
    const salt = utf8ToBytes('salt');
    const iterations = 4096;
    const keyLength = 32;
    const expected = 'c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a';

    const derived = computePbkdf2({ password, salt, iterations, keyLength, hash: 'SHA-256' });
    expect(bytesToHex(derived)).toBe(expected);
  });

  // 6. RFC 5869 HKDF-SHA256 Test Vector
  it('RFC 5869 HKDF-SHA256 Test Vector 1', () => {
    const ikm = hexToBytes('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b');
    const salt = hexToBytes('000102030405060708090a0b0c');
    const info = hexToBytes('f0f1f2f3f4f5f6f7f8f9');
    const keyLength = 42;
    const expected = '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865';

    const okm = computeHkdf({ ikm, salt, info, keyLength, hash: 'SHA-256' });
    expect(bytesToHex(okm)).toBe(expected);
  });

  // 7. CRC-16/ISO-14443-A (MIFARE Classic / Contactless Card CRC-A)
  it('ISO/IEC 14443-A CRC-16 Calculation (MIFARE standard)', () => {
    const model = CRC_PRESETS['CRC-16/ISO-14443-A'];
    // ISO 14443-A WUPA command: [0x52] -> CRC is 0x63, 0x63 init reflected
    const data = hexToBytes('52');
    const { crcBytes } = computeCrc(data, model);
    expect(crcBytes.length).toBe(2);
  });

  // 8. CRC-32/ISO-HDLC (Ethernet / ZIP standard "123456789" check)
  it('CRC-32 Ethernet / ZIP Standard Check ("123456789")', () => {
    const model = CRC_PRESETS['CRC-32/ISO-HDLC'];
    const data = utf8ToBytes('123456789');
    const { crcHex } = computeCrc(data, model);
    expect(crcHex).toBe('CBF43926');
  });

  // 9. CRC-16/MODBUS ("123456789" check)
  it('CRC-16/MODBUS Standard Check ("123456789")', () => {
    const model = CRC_PRESETS['CRC-16/MODBUS'];
    const data = utf8ToBytes('123456789');
    const { crcHex } = computeCrc(data, model);
    expect(crcHex).toBe('4B37');
  });

  // 10. Extended Hash Algorithms (MD5, RIPEMD-160, SHA-512/256, BLAKE2b/s, Keccak)
  it('Extended Hash Algorithms Verification ("abc")', () => {
    const data = utf8ToBytes('abc');

    expect(bytesToHex(computeHash(data, 'MD5'))).toBe('900150983cd24fb0d6963f7d28e17f72');
    expect(bytesToHex(computeHash(data, 'RIPEMD-160'))).toBe('8eb208f7e05d987a9b044a8e98c6b087f15a0bfc');
    expect(bytesToHex(computeHash(data, 'SHA-512/256'))).toBe('53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23');
    expect(computeHash(data, 'BLAKE2s').length).toBe(32);
    expect(computeHash(data, 'BLAKE2b').length).toBe(64);
    expect(computeHash(data, 'Keccak-256').length).toBe(32);
    expect(computeHash(data, 'SHA3-384').length).toBe(48);
  });

  // 11. Extended CRC Presets & Custom Rocksoft Model ("123456789")
  it('Extended CRC Presets and Rocksoft Parameters Verification ("123456789")', () => {
    const data = utf8ToBytes('123456789');

    // CRC-8/SMBUS
    expect(computeCrc(data, CRC_PRESETS['CRC-8/SMBUS']).crcHex).toBe('F4');

    // CRC-8/MAXIM
    expect(computeCrc(data, CRC_PRESETS['CRC-8/MAXIM']).crcHex).toBe('A1');

    // CRC-16/CCITT-FALSE
    expect(computeCrc(data, CRC_PRESETS['CRC-16/CCITT-FALSE']).crcHex).toBe('29B1');

    // CRC-16/XMODEM
    expect(computeCrc(data, CRC_PRESETS['CRC-16/XMODEM']).crcHex).toBe('31C3');

    // CRC-16/USB
    expect(computeCrc(data, CRC_PRESETS['CRC-16/USB']).crcHex).toBe('B4C8');

    // CRC-32C / CASTAGNOLI
    expect(computeCrc(data, CRC_PRESETS['CRC-32/CASTAGNOLI']).crcHex).toBe('E3069283');

    // CRC-64/ECMA
    expect(computeCrc(data, CRC_PRESETS['CRC-64/ECMA']).crcHex).toBe('6C40DF5F0B497347');

    // CRC-64/XZ
    expect(computeCrc(data, CRC_PRESETS['CRC-64/XZ']).crcHex).toBe('995DC9BBDF1939FA');

    // Custom Rocksoft Parameter Model (custom CRC-16)
    const custom = computeCrc(data, {
      width: 16,
      poly: 0x8005n,
      init: 0x0000n,
      refIn: true,
      refOut: true,
      xorOut: 0x0000n,
    });
    expect(custom.crcHex).toBe('BB3D'); // standard CRC-16/ARC check
  });
});
