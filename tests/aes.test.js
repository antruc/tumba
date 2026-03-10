import { describe, it, expect } from 'vitest';
import aes from '../lib/aes.js';
import { TextEncoder, TextDecoder } from 'util';
import { Buffer } from 'node:buffer';

const encoder = new TextEncoder();
const decoder = new TextDecoder();

const password = 'test-password';
const salt = encoder.encode('test-salt');
const iterations = 100000;

describe('AES module', () => {
  it('should derive a CryptoKey', async () => {
    const key = await aes.secretKey(password, salt, iterations);

    expect(key).toBeDefined();
    expect(key.type).toBe('secret');
    expect(key.algorithm.name).toBe('AES-GCM');
    expect(key.algorithm.length).toBe(256);
  });

  it('should encrypt and return iv and cipher', async () => {
    const plaintext = encoder.encode('hello world');

    const result = await aes.encrypt(plaintext, password, salt, iterations);

    expect(result).toHaveProperty('iv');
    expect(result).toHaveProperty('cipher');
    expect(result.iv).toHaveLength(12);
    expect(result.cipher.length).toBeGreaterThan(0);
  });

  it('should decrypt what it encrypts', async () => {
    const plaintext = encoder.encode('super secret message');

    const { iv, cipher } = await aes.encrypt(plaintext, password, salt, iterations);
    const combined = Buffer.concat([Buffer.from(iv), Buffer.from(cipher)]);

    const decrypted = await aes.decrypt(combined, password, salt, iterations);

    expect(decoder.decode(decrypted)).toBe('super secret message');
  });

  it('should fail decryption with wrong password', async () => {
    const plaintext = encoder.encode('secret');
    const { iv, cipher } = await aes.encrypt(plaintext, password, salt, iterations);
    const combined = Buffer.concat([Buffer.from(iv), Buffer.from(cipher)]);

    await expect(aes.decrypt(combined, 'wrong-password', salt, iterations))
      .rejects.toThrow();
  });

  it('should generate random IVs for each encryption', async () => {
    const plaintext = encoder.encode('same message');

    const result1 = await aes.encrypt(plaintext, password, salt, iterations);
    const result2 = await aes.encrypt(plaintext, password, salt, iterations);

    expect(result1.iv).not.toEqual(result2.iv);
  });

  it('should produce consistent decryption with same inputs', async () => {
    const plaintext = encoder.encode('test message');

    // Encrypt/decrypt first time
    const { iv: iv1, cipher: cipher1 } = await aes.encrypt(plaintext, password, salt, iterations);
    const combined1 = Buffer.concat([Buffer.from(iv1), Buffer.from(cipher1)]);
    const decrypted1 = await aes.decrypt(combined1, password, salt, iterations);

    // Encrypt/decrypt second time
    const { iv: iv2, cipher: cipher2 } = await aes.encrypt(plaintext, password, salt, iterations);
    const combined2 = Buffer.concat([Buffer.from(iv2), Buffer.from(cipher2)]);
    const decrypted2 = await aes.decrypt(combined2, password, salt, iterations);

    expect(decoder.decode(decrypted1)).toBe('test message');
    expect(decoder.decode(decrypted2)).toBe('test message');
  });
});
