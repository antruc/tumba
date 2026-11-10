import { readFile, writeFile, mkdir, rm } from 'node:fs/promises';
import path from 'node:path';
import { fileTypeFromBuffer } from 'file-type';
import aes from './aes.js';

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
const HEADER_LEN = SIGNATURE.length + 4 + 16;
const IV_AND_TAG_LEN = 12 + 16;

// Upper bound for the iteration count read from an untrusted header, so a
// tampered file cannot stall PBKDF2 for hours before failing.
export const MAX_ITERATIONS = 10_000_000;

const corrupted = () => new Error('file is corrupted or incorrect password');

// Write without overwriting: an existing file is never replaced. Owner-only
// permissions, and a failed write (disk full) leaves no partial file behind.
const writeNew = async (file, data) => {
  try {
    await writeFile(file, data, { flag: 'wx', mode: 0o600 });
  } catch (error) {
    if (error.code !== 'EEXIST')
      await rm(file, { force: true }).catch(() => {});
    throw error;
  }
};

// The embedded name is untrusted: keep only the base name, and on Windows
// replace the characters NTFS rejects or treats specially (':' opens an
// alternate data stream). Unusable names fall back to the container name.
const safeName = (name, fallback) => {
  let base = path.basename(name);
  if (process.platform === 'win32') {
    base = base.replace(/[<>:"|?*\p{Cc}]/gu, '_');
  }
  return base === '' || base === '.' || base === '..' ? fallback : base;
};

const decryptOrFail = async (combined, password, salt, iterations) => {
  try {
    return await aes.decrypt(combined, password, salt, iterations);
  } catch (error) {
    if (error.name === 'OperationError') throw corrupted();
    throw error;
  }
};

// The whole file is held in memory: WebCrypto AES-GCM has no streaming API,
// so files near 2 GB fail in readFile, and peak memory is several times the
// file size (data, payload, cipher and output buffers coexist). Chunked
// encryption with one IV per chunk would lift that limit.
const tumba = {
  // Returns the path of the created .tumba file.
  async encrypt(plaintext, password, iterations, out) {
    const data = await readFile(plaintext);

    // Encrypted payload: version magic + original name + data.
    const nameBuf = Buffer.from(path.basename(plaintext), 'utf8');
    const nameLenBuf = Buffer.alloc(2);
    nameLenBuf.writeUInt16BE(nameBuf.length);
    const payload = Buffer.concat([MAGIC, nameLenBuf, nameBuf, data]);

    const salt = crypto.getRandomValues(new Uint8Array(16));
    const { iv, cipher } = await aes.encrypt(
      payload,
      password,
      salt,
      iterations,
    );

    const iterBuf = Buffer.alloc(4);
    iterBuf.writeUInt32BE(iterations);
    const file = Buffer.concat([SIGNATURE, iterBuf, salt, iv, cipher]);

    if (out) await mkdir(out, { recursive: true });

    // Random opaque name, retry on the unlikely collision.
    for (;;) {
      const randomId = crypto.getRandomValues(new Uint8Array(5));
      const outPath = path.join(
        out,
        `${Buffer.from(randomId).toString('hex')}.tumba`,
      );
      try {
        await writeNew(outPath, file);
        return outPath;
      } catch (error) {
        if (error.code !== 'EEXIST') throw error;
      }
    }
  },

  // Returns the path of the restored file. Iterations only apply to legacy
  // files, new files carry their own.
  async decrypt(ciphertext, password, iterations, out) {
    const file = await readFile(ciphertext);

    let outName;
    let plaintext;

    if (file.subarray(0, SIGNATURE.length).equals(SIGNATURE)) {
      if (file.length < HEADER_LEN + IV_AND_TAG_LEN) throw corrupted();

      const storedIterations = file.readUInt32BE(SIGNATURE.length);
      if (storedIterations < 1 || storedIterations > MAX_ITERATIONS) {
        throw corrupted();
      }

      const payload = await decryptOrFail(
        file.subarray(HEADER_LEN), // iv + cipher
        password,
        file.subarray(8, HEADER_LEN),
        storedIterations,
      );

      // Encrypted version marker: confirms format/version post-decrypt.
      if (
        payload.length < MAGIC.length + 2 ||
        !payload.subarray(0, MAGIC.length).equals(MAGIC)
      ) {
        throw corrupted();
      }

      const nameStart = MAGIC.length + 2;
      const nameLen = payload.readUInt16BE(MAGIC.length);
      outName = safeName(
        payload.subarray(nameStart, nameStart + nameLen).toString('utf8'),
        path.basename(ciphertext, '.tumba'),
      );
      plaintext = payload.subarray(nameStart + nameLen);
    } else {
      // Legacy format: iterations come from the flag, name is guessed.
      if (file.length < 16 + IV_AND_TAG_LEN) throw corrupted();

      plaintext = await decryptOrFail(
        file.subarray(16), // iv + cipher
        password,
        file.subarray(0, 16),
        iterations,
      );

      const baseName = path.basename(ciphertext, '.tumba');
      const fileType = await fileTypeFromBuffer(plaintext);
      outName = fileType ? `${baseName}.${fileType.ext}` : baseName;
    }

    if (out) await mkdir(out, { recursive: true });

    const outPath = path.join(out, outName);
    try {
      await writeNew(outPath, plaintext);
    } catch (error) {
      if (error.code === 'EEXIST') throw new Error(`${outPath} already exists`);
      throw error;
    }
    return outPath;
  },
};

export default tumba;
