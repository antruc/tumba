#!/usr/bin/env node
import meow from 'meow';
import { statSync } from 'node:fs';
import path from 'node:path';
import passwordPrompt from '@inquirer/password';
import tumba, { MAX_ITERATIONS } from '../lib/tumba.js';

// New files store their iteration count. Legacy files (no header) fall back to
// this when decrypting without an explicit -i.
const LEGACY_ITERATIONS = 100000;
const DEFAULT_ITERATIONS = 600000;
const MIN_ENCRYPT_ITERATIONS = 100000;

const cli = meow(
  `
  Usage
    $ tumba -option <input>

  Options
    --encrypt, -e     Encrypt a file from disk
    --decrypt, -d     Decrypt a file to disk
    --iterations, -i  PBKDF2 iterations (default: 600000,
                      stored in the encrypted file)
    --outDir, -o      Output directory (optional)

  Examples
    $ tumba -e file1.png
    $ tumba -e 'file 2.png'
    $ tumba -e file3.png -o test
`,
  {
    importMeta: import.meta,
    flags: {
      encrypt: { type: 'string', shortFlag: 'e' },
      decrypt: { type: 'string', shortFlag: 'd' },
      iterations: { type: 'number', shortFlag: 'i' },
      outDir: { type: 'string', shortFlag: 'o', default: '' },
    },
  },
);

const { encrypt, decrypt, iterations, outDir } = cli.flags;

const askPassword = (message) => passwordPrompt({ message, mask: true });

const checkFile = (file) => {
  const stat = statSync(file, { throwIfNoEntry: false });
  if (!stat) throw new Error('File does not exist');
  if (!stat.isFile()) throw new Error('Path must be a file');
};

const checkIterations = (min) => {
  if (
    iterations !== undefined &&
    !(
      Number.isInteger(iterations) &&
      iterations >= min &&
      iterations <= MAX_ITERATIONS
    )
  ) {
    throw new Error(
      `Iterations must be an integer from ${min} to ${MAX_ITERATIONS}`,
    );
  }
};

const run = async () => {
  if (encrypt && decrypt) {
    throw new Error('Use either --encrypt or --decrypt, not both');
  }
  if (encrypt) {
    checkFile(encrypt);
    checkIterations(MIN_ENCRYPT_ITERATIONS);
    const password = await askPassword('Password:');
    const confirm = await askPassword('Confirm password:');
    if (password.length === 0) {
      throw new Error('Password length must be greater than zero');
    }
    if (password !== confirm) throw new Error('Passwords do not match');

    const outPath = await tumba.encrypt(
      encrypt,
      password,
      iterations ?? DEFAULT_ITERATIONS,
      outDir,
    );
    console.log('File encrypted successfully');
    console.log(`${outPath} created`);
  } else if (decrypt) {
    checkFile(decrypt);
    if (path.extname(decrypt) !== '.tumba') {
      throw new Error('File must be encrypted');
    }
    checkIterations(1);
    const password = await askPassword('Password:');

    const outPath = await tumba.decrypt(
      decrypt,
      password,
      iterations ?? LEGACY_ITERATIONS,
      outDir,
    );
    console.log('File decrypted successfully');
    console.log(`${outPath} created`);
  } else {
    console.log(cli.help);
  }
};

run().catch((error) => {
  if (error.name === 'ExitPromptError') {
    console.log('Process cancelled');
    process.exitCode = 130;
  } else {
    console.error(`Error: ${error.message}`);
    process.exitCode = 1;
  }
});
