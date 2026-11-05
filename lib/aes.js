const aes = {
  async secretKey(password, salt, iterations) {
    const key = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(password),
      'PBKDF2',
      false,
      ['deriveKey'],
    );

    // Derive an AES-GCM 256 key with PBKDF2-SHA256
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
      key,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt'],
    );
  },

  async encrypt(plaintext, password, salt, iterations) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await this.secretKey(password, salt, iterations);
    const cipher = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      plaintext,
    );

    return { iv, cipher: new Uint8Array(cipher) };
  },

  // combined = iv(12) + cipher
  async decrypt(combined, password, salt, iterations) {
    const key = await this.secretKey(password, salt, iterations);
    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: combined.subarray(0, 12) },
      key,
      combined.subarray(12),
    );

    return Buffer.from(plaintext);
  },
};

export default aes;
