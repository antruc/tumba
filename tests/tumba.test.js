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
