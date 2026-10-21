/**
 * Universal Parametric CRC Engine (Rocksoft Model)
 * Supports arbitrary CRC width (8, 16, 24, 32, 64-bit) with custom Polynomial,
 * Init value, RefIn, RefOut, and XorOut masks.
 */

export interface CrcModel {
  name?: string;
  width: number;       // 8, 16, 24, 32, 64
  poly: bigint;        // Polynomial without leading highest bit
  init: bigint;        // Initial register value
  refIn: boolean;      // Reflect input bytes
  refOut: boolean;     // Reflect output CRC
  xorOut: bigint;      // Final XOR value
}

// Standard Industrial, Storage & Smart Card Presets
export const CRC_PRESETS: Record<string, CrcModel> = {
  'CRC-8/SMBUS': {
    name: 'CRC-8/SMBUS',
    width: 8,
    poly: 0x07n,
    init: 0x00n,
    refIn: false,
    refOut: false,
    xorOut: 0x00n,
  },
  'CRC-8/MAXIM': {
    name: 'CRC-8/MAXIM (Dallas/1-Wire)',
    width: 8,
    poly: 0x31n,
    init: 0x00n,
    refIn: true,
    refOut: true,
    xorOut: 0x00n,
  },
  'CRC-16/CCITT-FALSE': {
    name: 'CRC-16/CCITT-FALSE',
    width: 16,
    poly: 0x1021n,
    init: 0xffffn,
    refIn: false,
    refOut: false,
    xorOut: 0x0000n,
  },
  'CRC-16/MODBUS': {
    name: 'CRC-16/MODBUS',
    width: 16,
    poly: 0x8005n,
    init: 0xffffn,
    refIn: true,
    refOut: true,
    xorOut: 0x0000n,
  },
  'CRC-16/XMODEM': {
    name: 'CRC-16/XMODEM',
    width: 16,
    poly: 0x1021n,
    init: 0x0000n,
    refIn: false,
    refOut: false,
    xorOut: 0x0000n,
  },
  'CRC-16/USB': {
    name: 'CRC-16/USB',
    width: 16,
    poly: 0x8005n,
    init: 0xffffn,
    refIn: true,
    refOut: true,
    xorOut: 0xffffn,
  },
  'CRC-16/ISO-14443-A': {
    name: 'CRC-16/ISO-14443-A (MIFARE/NFC)',
    width: 16,
    poly: 0x1021n,
    init: 0x6363n,
    refIn: true,
    refOut: true,
    xorOut: 0x0000n,
  },
  'CRC-32/ISO-HDLC': {
    name: 'CRC-32 (Ethernet/PNG/ZIP)',
    width: 32,
    poly: 0x04c11db7n,
    init: 0xffffffffn,
    refIn: true,
    refOut: true,
    xorOut: 0xffffffffn,
  },
  'CRC-32/CASTAGNOLI': {
    name: 'CRC-32C (Castagnoli / iSCSI)',
    width: 32,
    poly: 0x1edc6f41n,
    init: 0xffffffffn,
    refIn: true,
    refOut: true,
    xorOut: 0xffffffffn,
  },
  'CRC-64/ECMA': {
    name: 'CRC-64/ECMA-182',
    width: 64,
    poly: 0x42f0e1eba9ea3693n,
    init: 0x0000000000000000n,
    refIn: false,
    refOut: false,
    xorOut: 0x0000000000000000n,
  },
  'CRC-64/XZ': {
    name: 'CRC-64/XZ (GO-ISO)',
    width: 64,
    poly: 0x42f0e1eba9ea3693n,
    init: 0xffffffffffffffffn,
    refIn: true,
    refOut: true,
    xorOut: 0xffffffffffffffffn,
  },
};

function reflectBits(val: bigint, bitCount: number): bigint {
  let reflected = 0n;
  for (let i = 0; i < bitCount; i++) {
    if ((val & (1n << BigInt(i))) !== 0n) {
      reflected |= 1n << BigInt(bitCount - 1 - i);
    }
  }
  return reflected;
}

export function computeCrc(data: Uint8Array, model: CrcModel): { crcBigInt: bigint; crcBytes: Uint8Array; crcHex: string } {
  const width = model.width;
  const mask = (1n << BigInt(width)) - 1n;
  const topBit = 1n << BigInt(width - 1);

  let reg = model.init & mask;

  for (let i = 0; i < data.length; i++) {
    let byte = BigInt(data[i]);
    if (model.refIn) {
      byte = reflectBits(byte, 8);
    }

    reg ^= byte << BigInt(width - 8);

    for (let bit = 0; bit < 8; bit++) {
      if ((reg & topBit) !== 0n) {
        reg = ((reg << 1n) ^ model.poly) & mask;
      } else {
        reg = (reg << 1n) & mask;
      }
    }
  }

  if (model.refOut) {
    reg = reflectBits(reg, width);
  }

  const finalCrc = (reg ^ model.xorOut) & mask;

  // Convert to Bytes (Big-Endian or Little-Endian per standard)
  const byteLen = Math.ceil(width / 8);
  const bytes = new Uint8Array(byteLen);
  for (let b = 0; b < byteLen; b++) {
    bytes[b] = Number((finalCrc >> BigInt((byteLen - 1 - b) * 8)) & 0xffn);
  }

  const hex = finalCrc.toString(16).padStart(byteLen * 2, '0').toUpperCase();

  return { crcBigInt: finalCrc, crcBytes: bytes, crcHex: hex };
}
