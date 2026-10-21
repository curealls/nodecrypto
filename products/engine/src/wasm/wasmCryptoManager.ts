/**
 * NodeCrypto WebAssembly Cryptographic Runtime Manager (CR-1, CR-2)
 *
 * Implements dual-engine architecture:
 * 1. High-Performance Rust WASM Core (when wasm binary is compiled and loaded)
 * 2. High-Assurance Pure TypeScript / WebCrypto / Noble Fallback Core (guaranteed 100% platform availability)
 */

import { eccSharedSecret } from '../crypto/asymmetric/ecc';
import { x25519SharedSecret } from '../crypto/asymmetric/x25519';

export type WasmEngineStatus = 'uninitialized' | 'loading' | 'ready' | 'fallback';

export interface WasmModuleInterface {
  nodecrypto_version?: () => string;
  wasm_p256_ecdh?: (privateKey: Uint8Array, peerPublicKey: Uint8Array) => Uint8Array;
  wasm_x25519_ecdh?: (privateKey: Uint8Array, peerPublicKey: Uint8Array) => Uint8Array;
}

export class WasmCryptoManager {
  private static instance: WasmCryptoManager;
  private status: WasmEngineStatus = 'uninitialized';
  private wasmModule: WasmModuleInterface | null = null;
  private initPromise: Promise<boolean> | null = null;

  private constructor() {}

  public static getInstance(): WasmCryptoManager {
    if (!WasmCryptoManager.instance) {
      WasmCryptoManager.instance = new WasmCryptoManager();
    }
    return WasmCryptoManager.instance;
  }

  /**
   * Initializes the WASM engine. If the WASM binary is unavailable,
   * gracefully falls back to the native TypeScript/Noble engine.
   */
  public async init(): Promise<boolean> {
    if (this.status === 'ready') return true;
    if (this.status === 'fallback') return false;
    if (this.initPromise) return this.initPromise;

    this.initPromise = (async () => {
      this.status = 'loading';
      try {
        // Attempt dynamic import of compiled wasm package if present
        if (typeof window !== 'undefined' && (window as any).__NODECRYPTO_WASM__) {
          this.wasmModule = (window as any).__NODECRYPTO_WASM__;
          this.status = 'ready';
          console.info('[NodeCrypto Engine] Rust WebAssembly Core loaded successfully.');
          return true;
        }

        // Check if WebAssembly is supported in current environment
        if (typeof WebAssembly === 'undefined') {
          throw new Error('WebAssembly is not supported in this runtime');
        }

        // In vitest / CLI environment or when wasm binary hasn't been built yet,
        // activate the pure TypeScript fallback.
        this.status = 'fallback';
        return false;
      } catch (err) {
        this.status = 'fallback';
        return false;
      }
    })();

    return this.initPromise;
  }

  public getStatus(): WasmEngineStatus {
    return this.status;
  }

  public isWasmAvailable(): boolean {
    return this.status === 'ready' && this.wasmModule !== null;
  }

  public isFallback(): boolean {
    return this.status === 'fallback' || this.status === 'uninitialized';
  }

  public getEngineInfo(): { engine: 'wasm' | 'typescript_fallback'; version: string } {
    if (this.isWasmAvailable() && this.wasmModule?.nodecrypto_version) {
      return {
        engine: 'wasm',
        version: this.wasmModule.nodecrypto_version(),
      };
    }
    return {
      engine: 'typescript_fallback',
      version: '1.0.0-ts-fallback',
    };
  }

  public getWasmModule(): WasmModuleInterface | null {
    return this.wasmModule;
  }

  public computeP256Ecdh(privateKey: Uint8Array, peerPublicKey: Uint8Array): Uint8Array {
    if (this.isWasmAvailable() && this.wasmModule?.wasm_p256_ecdh) {
      try {
        return this.wasmModule.wasm_p256_ecdh(privateKey, peerPublicKey);
      } catch (err) {
        console.warn('[WasmCryptoManager] wasm_p256_ecdh failed, falling back to TS engine:', err);
      }
    }
    return eccSharedSecret(privateKey, peerPublicKey, 'p256', 'raw_x');
  }

  public computeX25519Ecdh(privateKey: Uint8Array, peerPublicKey: Uint8Array): Uint8Array {
    if (this.isWasmAvailable() && this.wasmModule?.wasm_x25519_ecdh) {
      try {
        return this.wasmModule.wasm_x25519_ecdh(privateKey, peerPublicKey);
      } catch (err) {
        console.warn('[WasmCryptoManager] wasm_x25519_ecdh failed, falling back to TS engine:', err);
      }
    }
    return x25519SharedSecret(privateKey, peerPublicKey);
  }
}

export const wasmCryptoManager = WasmCryptoManager.getInstance();
