import { readFile, mkdir } from 'node:fs/promises';
import { createWriteStream } from 'node:fs';
import { webcrypto } from 'node:crypto';
import aes from './aes.js';
import { Buffer } from 'node:buffer';
import { fileTypeFromBuffer } from 'file-type';

const tumba = {
  async encrypt(plaintext, password, iterations, out) {
    // Load the file into a buffer
    const fileBuffer = await readFile(plaintext);
    // Convert the buffer to an Uint8Array
    const fileToUint8 = new Uint8Array(fileBuffer);

    // Generate a random salt
    const randomSalt = webcrypto.getRandomValues(new Uint8Array(16));

    // Encrypt the file using AES
    const ciphertext = await aes.encrypt(
      fileToUint8,
      password,
      randomSalt,
      iterations,
    );

    // Concatenate the random salt, iv, and cipher
    const fileToBuffer = Buffer.concat([
      randomSalt,
      ciphertext.iv,
      ciphertext.cipher,
    ]);

    const outDir = out.length > 0 ? `${out}/` : out;
    if (out.length > 0) {
      // Create the output directory if it doesn't exist
      await mkdir(out);
    }
    //Generate a random file name
    const randomId = webcrypto.getRandomValues(new Uint8Array(5));
    const randomFileName = Buffer.from(randomId).toString('hex');

    // Create a writeStream for writing the buffer to a file
    const writeStream = createWriteStream(`${outDir}${randomFileName}.tumba`);
    writeStream.on('open', function () {
      writeStream.write(fileToBuffer);
    });

    console.log('File encrypted successfully');
    console.log(`${randomFileName}.tumba created`);
  },

  async decrypt(ciphertext, password, iterations, out) {
    try {
      const file = await readFile(ciphertext);

      // Extract ciphertext
      const fileBuffer = file.subarray(16, file.length);
      const fileToUint8 = new Uint8Array(fileBuffer);

      // Extract salt
      const saltBuffer = file.subarray(0, 16);
      const saltToUint8 = new Uint8Array(saltBuffer);

      // Decrypt the encrypted data using AES
      const plaintext = await aes.decrypt(
        fileToUint8,
        password,
        saltToUint8,
        iterations,
      );

      const outDir = out.length > 0 ? `${out}/` : out;
      if (out.length > 0) {
        await mkdir(out);
      }
      // Remove '.tumba' from file name
      const fileName = ciphertext.replace('.tumba', '');

      // Get file type if possible
      const fileType = await fileTypeFromBuffer(plaintext);
      const fileExt = typeof fileType === 'undefined' ? '' : `.${fileType.ext}`;

      const writeStream = createWriteStream(`${outDir}${fileName}${fileExt}`);
      writeStream.on('open', function () {
        writeStream.write(plaintext);
      });
      console.log('File decrypted successfully');

    } catch (error) {
      if (error instanceof Error && error.name === 'OperationError') {
        console.log('Error: file is corrupted or incorrect password');
      } else {
        throw error;
      }
    }
  },
};

export default tumba;
