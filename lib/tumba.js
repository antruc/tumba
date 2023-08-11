import { readFile, mkdir } from 'node:fs/promises'
import { createWriteStream } from 'node:fs'
import { webcrypto } from 'node:crypto'
import aes from './aes.js'
import { Buffer } from 'node:buffer'
import { fileTypeFromBuffer } from 'file-type'

const tumba = {
  async encrypt(plaintext, password, iterations, out) {
    const fileBuffer = await readFile(plaintext)
    const fileToUint8 = new Uint8Array(fileBuffer)

    const randomSalt = webcrypto.getRandomValues(new Uint8Array(16))

    const ciphertext = await aes.encrypt(
      fileToUint8,
      password,
      randomSalt,
      iterations
    )

    const fileToBuffer = Buffer.concat([
      randomSalt,
      ciphertext.iv,
      ciphertext.cipher
    ])

    const outDir = out.length > 0 ? `${out}/` : out
    if (out.length > 0) {
      await mkdir(out)
    }

    const randomId = webcrypto.getRandomValues(new Uint8Array(6))
    const randomFileName = Buffer.from(randomId).toString('hex')

    const writeStream = createWriteStream(`${outDir}${randomFileName}.tumba`)
    writeStream.on('open', function () {
      writeStream.write(fileToBuffer)
    })
  },

  async decrypt(ciphertext, password, iterations, out) {
    const file = await readFile(ciphertext)

    const fileBuffer = file.subarray(16, file.length)
    const fileToUint8 = new Uint8Array(fileBuffer)

    const saltBuffer = file.subarray(0, 16)
    const saltToUint8 = new Uint8Array(saltBuffer)

    const plaintext = await aes.decrypt(
      fileToUint8,
      password,
      saltToUint8,
      iterations
    )

    const outDir = out.length > 0 ? `${out}/` : out
    if (out.length > 0) {
      await mkdir(out)
    }

    const fileName = ciphertext.replace('.tumba', '')

    const fileType = await fileTypeFromBuffer(plaintext)
    const fileExt = typeof fileType === 'undefined' ? '' : `.${fileType.ext}`

    const writeStream = createWriteStream(`${outDir}${fileName}${fileExt}`)
    writeStream.on('open', function () {
      writeStream.write(plaintext)
    })
  }
}

export default tumba
