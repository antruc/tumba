import { webcrypto } from 'crypto'
import { Buffer } from 'node:buffer'

const aes = {
  async secretKey(password, salt, iterations) {
    const encodedPassword = new TextEncoder().encode(password)

    const algorithm = {
      name: 'PBKDF2',
      hash: 'SHA-256',
      salt: salt,
      iterations: iterations
    }

    const key = await webcrypto.subtle.importKey(
      'raw',
      encodedPassword,
      algorithm.name,
      false,
      ['deriveKey']
    )

    const derivedAlgo = { name: 'AES-GCM', length: 256 }

    const keyResult = await webcrypto.subtle.deriveKey(
      algorithm,
      key,
      derivedAlgo,
      false,
      ['encrypt', 'decrypt']
    )

    return keyResult
  },

  async encrypt(plaintext, password, salt, iterations) {
    const ivUint8 = webcrypto.getRandomValues(new Uint8Array(12))

    const algorithm = { name: 'AES-GCM', iv: ivUint8 }

    const key = await this.secretKey(password, salt, iterations)

    const ciphertext = await webcrypto.subtle.encrypt(algorithm, key, plaintext)
    const ciphertextToUint8 = new Uint8Array(ciphertext)

    return { iv: ivUint8, cipher: ciphertextToUint8 }
  },

  async decrypt(ciphertext, password, salt, iterations) {
    const ciphertextToBuffer = Buffer.from(ciphertext)

    const ivBuffer = ciphertextToBuffer.subarray(0, 12)
    const ivToUint8 = new Uint8Array(ivBuffer)

    const algorithm = { name: 'AES-GCM', iv: ivToUint8 }

    const key = await this.secretKey(password, salt, iterations)

    const ciphertextBuffer = ciphertextToBuffer.subarray(12)
    const ciphertextToUint8 = new Uint8Array(ciphertextBuffer)

    const plaintext = await webcrypto.subtle.decrypt(
      algorithm,
      key,
      ciphertextToUint8
    )
    const plaintextToBuffer = Buffer.from(plaintext)

    return plaintextToBuffer
  }
}

export default aes
