import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { webcrypto } from 'node:crypto';
import path from 'node:path';
import aes from './aes.js';
import { Buffer } from 'node:buffer';
import { fileTypeFromBuffer } from 'file-type';

// File layout: SIGNATURE(4) + iterations(4 BE) + salt(16) + iv(12) + cipher.
// SIGNATURE is a fixed binary container marker (leading 0x7F keeps tools from
// guessing "text"); it carries no version or content info.
// The cipher decrypts to: MAGIC(4) + nameLen(2 BE) + originalName + fileData.
// MAGIC lives *inside* the ciphertext: it identifies format/version and is
// verified only after a successful decrypt, so nothing about the version or
// contents leaks in plaintext.
// Files without SIGNATURE are legacy (salt(16) + iv(12) + cipher, no name).
const SIGNATURE = Buffer.from([0x7f, 0x54, 0x4d, 0x42]); // \x7F T M B
const MAGIC = Buffer.from('TMB1');

const tumba = {
  async encrypt(plaintext, password, iterations, out) {
    try {
      const data = await readFile(plaintext);

      // Encrypted payload: version magic + original name + data.
      const nameBuf = Buffer.from(path.basename(plaintext), 'utf8');
      const nameLenBuf = Buffer.alloc(2);
      nameLenBuf.writeUInt16BE(nameBuf.length);
      const payload = Buffer.concat([MAGIC, nameLenBuf, nameBuf, data]);

      const salt = webcrypto.getRandomValues(new Uint8Array(16));
      const { iv, cipher } = await aes.encrypt(
        payload,
        password,
        salt,
        iterations,
      );

      const iterBuf = Buffer.alloc(4);
      iterBuf.writeUInt32BE(iterations);
      const fileToBuffer = Buffer.concat([
        SIGNATURE,
        iterBuf,
        Buffer.from(salt),
        Buffer.from(iv),
        Buffer.from(cipher),
      ]);

      const outDir = out.length > 0 ? `${out}/` : out;
      if (out.length > 0) {
        await mkdir(out, { recursive: true });
      }

      // Random opaque name, retry on the unlikely collision.
      let randomFileName;
      do {
        const randomId = webcrypto.getRandomValues(new Uint8Array(5));
        randomFileName = Buffer.from(randomId).toString('hex');
      } while (existsSync(`${outDir}${randomFileName}.tumba`));

      await writeFile(`${outDir}${randomFileName}.tumba`, fileToBuffer);

      console.log('File encrypted successfully');
      console.log(`${randomFileName}.tumba created`);
      return `${randomFileName}.tumba`;
    } catch (error) {
      console.log(`Error: ${error.message}`);
    }
  },

  async decrypt(ciphertext, password, iterations, out) {
    try {
      const file = await readFile(ciphertext);

      const outDir = out.length > 0 ? `${out}/` : out;
      if (out.length > 0) {
        await mkdir(out, { recursive: true });
      }

      let outName;
      let plaintext;

      if (
        file.length >= SIGNATURE.length &&
        file.subarray(0, SIGNATURE.length).equals(SIGNATURE)
      ) {
        // New format: read iterations from the header, everything else is
        // verified after decrypting.
        const storedIterations = file.readUInt32BE(4);
        const salt = new Uint8Array(file.subarray(8, 24));
        const combined = new Uint8Array(file.subarray(24)); // iv + cipher
        const payload = await aes.decrypt(
          combined,
          password,
          salt,
          storedIterations,
        );

        // Encrypted version marker: confirms format/version post-decrypt.
        if (!payload.subarray(0, MAGIC.length).equals(MAGIC)) {
          console.log('Error: file is corrupted or incorrect password');
          return;
        }

        const nameStart = MAGIC.length + 2;
        const nameLen = payload.readUInt16BE(MAGIC.length);
        outName = path.basename(
          payload.subarray(nameStart, nameStart + nameLen).toString('utf8'),
        );
        plaintext = payload.subarray(nameStart + nameLen);
      } else {
        // Legacy format: iterations come from the flag, name is guessed.
        const salt = new Uint8Array(file.subarray(0, 16));
        const combined = new Uint8Array(file.subarray(16)); // iv + cipher
        plaintext = await aes.decrypt(combined, password, salt, iterations);

        const baseName = path.basename(ciphertext).replace(/\.tumba$/, '');
        const fileType = await fileTypeFromBuffer(plaintext);
        const fileExt = fileType ? `.${fileType.ext}` : '';
        outName = `${baseName}${fileExt}`;
      }

      await writeFile(`${outDir}${outName}`, plaintext);
      console.log('File decrypted successfully');
      return `${outDir}${outName}`;
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
