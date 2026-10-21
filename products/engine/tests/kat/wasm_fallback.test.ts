import { describe, it, expect } from 'vitest';
import { wasmCryptoManager } from 'nodecrypto-engine/wasm/wasmCryptoManager';

describe('WASM & Fallback Architecture (CR-1, CR-2)', () => {
  it('WasmCryptoManager initializes cleanly in Fallback mode when WASM asset is absent', async () => {
    const initialized = await wasmCryptoManager.init();
    // In headless test environment without wasm build, it gracefully reports fallback
    expect(wasmCryptoManager.getStatus()).toBe('fallback');
    expect(wasmCryptoManager.isFallback()).toBe(true);

    const engineInfo = wasmCryptoManager.getEngineInfo();
    expect(engineInfo.engine).toBe('typescript_fallback');
    expect(engineInfo.version).toBe('1.0.0-ts-fallback');
  });
});
