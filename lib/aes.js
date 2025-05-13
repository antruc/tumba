import { webcrypto } from 'crypto';
import { Buffer } from 'node:buffer';

const aes = {
  async secretKey(password, salt, iterations) {
    // Convert the password to a buffer
    const encodedPassword = new TextEncoder().encode(password);

    const algorithm = {
      name: 'PBKDF2',
      hash: 'SHA-256',
      salt: salt,
      iterations: iterations,
    };

    // Import the key from a raw binary buffer
    const key = await webcrypto.subtle.importKey(
      'raw',
      encodedPassword,
      algorithm.name,
      false,
      ['deriveKey'],
    );

    const derivedAlgo = { name: 'AES-GCM', length: 256 };

    // Derive a key using the PBKDF2 algorithm and a specified number of iterations
    const keyResult = await webcrypto.subtle.deriveKey(
      algorithm,
      key,
      derivedAlgo,
      false,
      ['encrypt', 'decrypt'],
    );

    return keyResult;
  },

  async encrypt(plaintext, password, salt, iterations) {
    // Generate a random iv
    const ivUint8 = webcrypto.getRandomValues(new Uint8Array(12));

    const algorithm = { name: 'AES-GCM', iv: ivUint8 };

    const key = await this.secretKey(password, salt, iterations);

    // Encrypt the plaintext using the algorithm and the derived key
    const ciphertext = await webcrypto.subtle.encrypt(
      algorithm,
      key,
      plaintext,
    );

    // Convert the ciphertext to a buffer
    const ciphertextToUint8 = new Uint8Array(ciphertext);

    return { iv: ivUint8, cipher: ciphertextToUint8 };
  },

  async decrypt(ciphertext, password, salt, iterations) {
    // Convert the ciphertext to a buffer
    const ciphertextToBuffer = Buffer.from(ciphertext);

    // Extract the iv
    const ivBuffer = ciphertextToBuffer.subarray(0, 12);
    const ivToUint8 = new Uint8Array(ivBuffer);

    const algorithm = { name: 'AES-GCM', iv: ivToUint8 };

    const key = await this.secretKey(password, salt, iterations);

    // Extract the ciphertext
    const ciphertextBuffer = ciphertextToBuffer.subarray(12);
    const ciphertextToUint8 = new Uint8Array(ciphertextBuffer);

    // Decrypt the ciphertext using the derived key
    const plaintext = await webcrypto.subtle.decrypt(
      algorithm,
      key,
      ciphertextToUint8,
    );
    const plaintextToBuffer = Buffer.from(plaintext);

    return plaintextToBuffer;
  },
};

export default aes;
