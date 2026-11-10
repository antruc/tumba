import { describe, it, expect, beforeEach } from 'vitest';
import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import tumba from '../lib/tumba.js';
import aes from '../lib/aes.js';

const password = 'test-password';
const iterations = 1000;
let dir;

beforeEach(async () => {
  dir = await mkdtemp(path.join(tmpdir(), 'tumba-'));
});

const encryptSample = async (content = 'hello') => {
  const src = path.join(dir, 'note.txt');
  await writeFile(src, content);
  return tumba.encrypt(src, password, iterations, dir);
};

describe('tumba file format', () => {
  it('restores original name and content', async () => {
    const enc = await encryptSample('hello');
    const out = await tumba.decrypt(enc, password, 0, path.join(dir, 'out'));

    expect(path.basename(out)).toBe('note.txt');
    expect(await readFile(out, 'utf8')).toBe('hello');
  });

  it('never overwrites an existing file', async () => {
    const enc = await encryptSample('old');
    await writeFile(path.join(dir, 'note.txt'), 'newer edits');

    await expect(tumba.decrypt(enc, password, 0, dir)).rejects.toThrow(
      'already exists',
    );
    expect(await readFile(path.join(dir, 'note.txt'), 'utf8')).toBe(
      'newer edits',
    );
  });

  it('rejects a wrong password', async () => {
    const enc = await encryptSample();
    await expect(tumba.decrypt(enc, 'wrong', 0, dir)).rejects.toThrow(
      'corrupted',
    );
  });

  it('rejects truncated files and tampered iterations', async () => {
    const truncated = path.join(dir, 'short.tumba');
    await writeFile(truncated, Buffer.from([0x7f, 0x54, 0x4d, 0x42, 0, 0]));
    await expect(tumba.decrypt(truncated, password, 0, dir)).rejects.toThrow(
      'corrupted',
    );

    const enc = await encryptSample();
    const file = await readFile(enc);
    file.writeUInt32BE(0xffffffff, 4);
    await writeFile(enc, file);
    await expect(tumba.decrypt(enc, password, 0, dir)).rejects.toThrow(
      'corrupted',
    );
  });

  it('rejects a file with a changed cipher byte', async () => {
    const enc = await encryptSample();
    const file = await readFile(enc);
    file[file.length - 20] ^= 1;
    await writeFile(enc, file);
    await expect(tumba.decrypt(enc, password, 0, dir)).rejects.toThrow(
      'corrupted',
    );
  });

  it('keeps crafted embedded names inside the output folder', async () => {
    // Build a valid container whose embedded name is hostile.
    const craft = async (name, id) => {
      const nameBuf = Buffer.from(name);
      const nameLen = Buffer.alloc(2);
      nameLen.writeUInt16BE(nameBuf.length);
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const { iv, cipher } = await aes.encrypt(
        Buffer.concat([
          Buffer.from('TMB1'),
          nameLen,
          nameBuf,
          Buffer.from('x'),
        ]),
        password,
        salt,
        iterations,
      );
      const iterBuf = Buffer.alloc(4);
      iterBuf.writeUInt32BE(iterations);
      const file = path.join(dir, `${id}.tumba`);
      await writeFile(
        file,
        Buffer.concat([
          Buffer.from([0x7f, 0x54, 0x4d, 0x42]),
          iterBuf,
          salt,
          iv,
          cipher,
        ]),
      );
      return file;
    };
    const out = path.join(dir, 'out');
    const restore = async (name, id) =>
      path.relative(
        out,
        await tumba.decrypt(await craft(name, id), password, 0, out),
      );

    expect(await restore('../../evil.txt', 'a')).toBe('evil.txt');
    // Unusable names fall back to the container name.
    expect(await restore('..', 'b')).toBe('b');
    expect(await restore('', 'c')).toBe('c');
    if (process.platform === 'win32') {
      expect(await restore('note.txt:ads', 'd')).toBe('note.txt_ads');
      expect(await restore('a?b.txt', 'e')).toBe('a_b.txt');
    }
  });

  it('decrypts legacy files with the given iterations', async () => {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const { iv, cipher } = await aes.encrypt(
      Buffer.from('legacy data'),
      password,
      salt,
      iterations,
    );
    const legacy = path.join(dir, 'abc.tumba');
    await writeFile(legacy, Buffer.concat([salt, iv, cipher]));

    const out = await tumba.decrypt(legacy, password, iterations, dir);
    expect(path.basename(out)).toBe('abc');
    expect(await readFile(out, 'utf8')).toBe('legacy data');
  });
});
