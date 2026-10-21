import { describe, it, expect } from 'vitest';
import { DAGRunner } from 'nodecrypto-engine/dag/runner';
import { defaultNodeRegistry } from 'nodecrypto-engine/registry/nodeRegistry';
import { DAGEdgeConnection } from 'nodecrypto-engine/dag/types';
import { bytesToUtf8, bytesToHex } from 'nodecrypto-engine/crypto/utils/encoding';

describe('End-to-End Cryptographic DAG Pipeline Execution', () => {
  const registry = defaultNodeRegistry.getMap();

  it('executes AES-256-GCM Encrypt -> Decrypt roundtrip DAG pipeline', async () => {
    const rawPlaintext = 'Top Secret NodeCrypto Protocol Data 2026';
    const rawKeyHex = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';

    const nodes = [
      { id: 'node-text', type: 'input-static-value', properties: { type: 'string', valueString: rawPlaintext } },
      { id: 'node-key', type: 'input-static-value', properties: { type: 'bytes', valueBytes: rawKeyHex } },
      { id: 'node-encrypt', type: 'symmetric-aes-encrypt', properties: { mode: 'GCM', padding: 'PKCS7' } },
      { id: 'node-decrypt', type: 'symmetric-aes-decrypt', properties: { mode: 'GCM', padding: 'PKCS7' } },
      { id: 'node-inspector', type: 'output-inspector', properties: {} },
    ];

    const edges: DAGEdgeConnection[] = [
      // Wire text & key into Encrypt
      { id: 'e1', source: 'node-text', sourceHandle: 'value', target: 'node-encrypt', targetHandle: 'plaintext' },
      { id: 'e2', source: 'node-key', sourceHandle: 'value', target: 'node-encrypt', targetHandle: 'key' },

      // Wire Encrypt outputs & key into Decrypt. No nonce edge: AES no longer has an "IV/Nonce
      // Used" output (PRD §4.3 A4), and both sides independently default an omitted nonce to the
      // same deterministic 0-fill (PRD §4.3 A3), so GCM round-trips correctly without wiring it.
      { id: 'e3', source: 'node-encrypt', sourceHandle: 'ciphertext', target: 'node-decrypt', targetHandle: 'ciphertext' },
      { id: 'e5', source: 'node-encrypt', sourceHandle: 'tag', target: 'node-decrypt', targetHandle: 'tag' },
      { id: 'e6', source: 'node-key', sourceHandle: 'value', target: 'node-decrypt', targetHandle: 'key' },

      // Wire Decrypt output into Inspector
      { id: 'e7', source: 'node-decrypt', sourceHandle: 'plaintext', target: 'node-inspector', targetHandle: 'data' },
    ];

    const result = await DAGRunner.execute(nodes, edges, registry);

    expect(result.success).toBe(true);
    expect(result.order.length).toBe(5);

    // Verify all nodes succeeded
    for (const node of nodes) {
      expect(result.nodeStates[node.id].status).toBe('success');
    }

    // Check final decrypted output captured in Inspector inputs
    const capturedData = result.nodeStates['node-inspector'].inputs.data;
    expect(bytesToUtf8(capturedData)).toBe(rawPlaintext);
  });

  it('executes Ed25519 Sign -> Verify DAG pipeline', async () => {
    const message = 'Official Blockchain Verification Certificate';

    const nodes = [
      { id: 'msg-node', type: 'input-static-value', properties: { type: 'string', valueString: message } },
      { id: 'key-node', type: 'input-random', properties: { length: 32 } }, // 32-byte seed
      { id: 'sign-node', type: 'asymmetric-ed25519-sign', properties: {} },
      { id: 'verify-node', type: 'asymmetric-ed25519-verify', properties: {} },
    ];

    const edges: DAGEdgeConnection[] = [
      // Feed message and private key into sign
      { id: 'e1', source: 'msg-node', sourceHandle: 'value', target: 'sign-node', targetHandle: 'message' },
      { id: 'e2', source: 'key-node', sourceHandle: 'bytes', target: 'sign-node', targetHandle: 'privateKey' },

      // Feed message, signature, and generated public key into verify
      { id: 'e3', source: 'msg-node', sourceHandle: 'value', target: 'verify-node', targetHandle: 'message' },
      { id: 'e4', source: 'sign-node', sourceHandle: 'signature', target: 'verify-node', targetHandle: 'signature' },
      { id: 'e5', source: 'key-node', sourceHandle: 'bytes', target: 'verify-node', targetHandle: 'publicKey' },
    ];

    // For Ed25519, the public key is derived from the private key;
    // We can also test Ed25519 directly with ECC keygen node:
    const keygenNodes = [
      { id: 'msg-node', type: 'input-static-value', properties: { type: 'string', valueString: message } },
      { id: 'ecc-keygen', type: 'asymmetric-ecc-keygen', properties: { curve: 'secp256k1' } },
      { id: 'ecc-sign', type: 'asymmetric-ecc-sign', properties: { curve: 'secp256k1', autoHash: true } },
      { id: 'ecc-verify', type: 'asymmetric-ecc-verify', properties: { curve: 'secp256k1', autoHash: true } },
    ];

    const keygenEdges: DAGEdgeConnection[] = [
      { id: 'k1', source: 'msg-node', sourceHandle: 'value', target: 'ecc-sign', targetHandle: 'data' },
      { id: 'k2', source: 'ecc-keygen', sourceHandle: 'privateKey', target: 'ecc-sign', targetHandle: 'privateKey' },
      { id: 'k3', source: 'msg-node', sourceHandle: 'value', target: 'ecc-verify', targetHandle: 'data' },
      { id: 'k4', source: 'ecc-sign', sourceHandle: 'signature', target: 'ecc-verify', targetHandle: 'signature' },
      { id: 'k5', source: 'ecc-keygen', sourceHandle: 'publicKey', target: 'ecc-verify', targetHandle: 'publicKey' },
    ];

    const result = await DAGRunner.execute(keygenNodes, keygenEdges, registry);
    expect(result.success).toBe(true);
    expect(result.nodeOutputs['ecc-verify'].isValid).toBe(true);
  });

  it('executes Post-Quantum ML-KEM-768 Key Encapsulation DAG pipeline', async () => {
    const nodes = [
      { id: 'pqc-keygen', type: 'pqc-mlkem-keygen', properties: { variant: 768 } },
      { id: 'pqc-encaps', type: 'pqc-mlkem-encaps', properties: { variant: 768 } },
      { id: 'pqc-decaps', type: 'pqc-mlkem-decaps', properties: { variant: 768 } },
    ];

    const edges: DAGEdgeConnection[] = [
      // Public key goes to Encaps
      { id: 'e1', source: 'pqc-keygen', sourceHandle: 'publicKey', target: 'pqc-encaps', targetHandle: 'publicKey' },
      // Ciphertext from Encaps goes to Decaps
      { id: 'e2', source: 'pqc-encaps', sourceHandle: 'ciphertext', target: 'pqc-decaps', targetHandle: 'ciphertext' },
      // Secret key from Keygen goes to Decaps
      { id: 'e3', source: 'pqc-keygen', sourceHandle: 'secretKey', target: 'pqc-decaps', targetHandle: 'secretKey' },
    ];

    const result = await DAGRunner.execute(nodes, edges, registry);

    expect(result.success).toBe(true);
    const senderSecret = result.nodeOutputs['pqc-encaps'].sharedSecret;
    const receiverSecret = result.nodeOutputs['pqc-decaps'].sharedSecret;

    expect(bytesToHex(senderSecret)).toBe(bytesToHex(receiverSecret));
  });

  it('executes Hash -> CRC utility pipeline', async () => {
    const nodes = [
      { id: 'text-in', type: 'input-static-value', properties: { type: 'string', valueString: 'NodeCrypto Multi-Format Pipeline' } },
      { id: 'hash-node', type: 'hash-digest', properties: { algorithm: 'SHA-256' } },
      { id: 'crc-node', type: 'utility-crc', properties: { preset: 'CRC-32/ISO-HDLC' } },
    ];

    const edges: DAGEdgeConnection[] = [
      { id: 'e1', source: 'text-in', sourceHandle: 'value', target: 'hash-node', targetHandle: 'data' },
      { id: 'e2', source: 'hash-node', sourceHandle: 'digest', target: 'crc-node', targetHandle: 'data' },
    ];

    const result = await DAGRunner.execute(nodes, edges, registry);
    expect(result.success).toBe(true);
    expect(bytesToHex(result.nodeOutputs['hash-node'].digest).length).toBe(64); // 32 bytes hex
    expect(typeof result.nodeOutputs['crc-node'].checksum).toBe('number');
  });

  it('gracefully isolates error and skips downstream nodes when a node fails', async () => {
    const nodes = [
      // Invalid key size (only 5 bytes instead of 16/24/32 bytes)
      { id: 'text-in', type: 'input-static-value', properties: { type: 'string', valueString: 'Valid Plaintext' } },
      { id: 'invalid-key', type: 'input-static-value', properties: { type: 'bytes', valueBytes: '1122334455' } },
      { id: 'failing-aes', type: 'symmetric-aes-encrypt', properties: { mode: 'GCM' } },
      { id: 'downstream-output', type: 'output-inspector', properties: {} },
    ];

    const edges: DAGEdgeConnection[] = [
      { id: 'e1', source: 'text-in', sourceHandle: 'value', target: 'failing-aes', targetHandle: 'plaintext' },
      { id: 'e2', source: 'invalid-key', sourceHandle: 'value', target: 'failing-aes', targetHandle: 'key' },
      { id: 'e3', source: 'failing-aes', sourceHandle: 'ciphertext', target: 'downstream-output', targetHandle: 'data' },
    ];

    const result = await DAGRunner.execute(nodes, edges, registry);

    expect(result.success).toBe(false);
    expect(result.nodeStates['failing-aes'].status).toBe('error');
    expect(result.nodeStates['failing-aes'].errorMessage).toBeDefined();

    // Downstream node should be skipped / error isolated
    expect(result.nodeStates['downstream-output'].status).toBe('error');
    expect(result.nodeStates['downstream-output'].errorMessage).toContain('Skipped');
  });
});
