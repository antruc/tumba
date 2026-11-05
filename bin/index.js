#!/usr/bin/env node
import meow from 'meow';
import { existsSync, lstatSync } from 'node:fs';
import path from 'node:path';
import inquirer from 'inquirer';
import tumba from '../lib/tumba.js';

// New files store their iteration count. Legacy files (no header) fall back to
// this when decrypting without an explicit -i.
const LEGACY_ITERATIONS = 100000;
const DEFAULT_ITERATIONS = 600000;

const cli = meow(
  `
  Usage
    $ tumba -option <input>

  Options
    --encrypt, -e  Encrypt a file from disk
    --decrypt, -d  Decrypt a file to disk
    --iterations, -i  PBKDF2 iterations (encrypt default: 600000, stored in file)
    --outDir, -o  Output directory (Optional)

  Examples
    $ tumba -e file1.png
    $ tumba -e 'file 2.png'
    $ tumba -e file3.png -o test
`,
  {
    importMeta: import.meta,
    flags: {
      encrypt: {
        type: 'string',
        shortFlag: 'e',
      },
      decrypt: {
        type: 'string',
        shortFlag: 'd',
      },
      iterations: {
        type: 'number',
        shortFlag: 'i',
      },
      outDir: {
        type: 'string',
        shortFlag: 'o',
        default: '',
      },
    },
  },
);

// Check if the necessary flags are set and if there is a valid input
if (Object.hasOwn(cli.flags, 'encrypt') && cli.flags.encrypt.length > 0) {
  // Check if path exist
  const pathExist = existsSync(cli.flags.encrypt);
  if (pathExist) {
    // Check if path is a file
    const isFile = lstatSync(cli.flags.encrypt).isFile();
    if (isFile) {
      inquirer
        .prompt([
          {
            message: 'Password:',
            name: 'password',
            type: 'password',
            mask: true,
          },
          {
            message: 'Confirm password:',
            name: 'confirm',
            type: 'password',
            mask: true,
          },
        ])
        .then((answer) => {
          if (answer.password.length === 0) {
            console.log('Error: Password length must be greater than zero');
          } else if (answer.password !== answer.confirm) {
            console.log('Error: Passwords do not match');
          } else {
            tumba.encrypt(
              cli.flags.encrypt,
              answer.password,
              cli.flags.iterations ?? DEFAULT_ITERATIONS,
              cli.flags.outDir,
            );
          }
        });
    } else {
      console.log('Error: Path must be a file');
    }
  } else {
    console.log('Error: File does not exist');
  }
} else if (
  Object.hasOwn(cli.flags, 'decrypt') &&
  cli.flags.decrypt.length > 0
) {
  const pathExist = existsSync(cli.flags.decrypt);
  if (pathExist) {
    const isFile = lstatSync(cli.flags.decrypt).isFile();
    if (isFile) {
      // Check the real extension is '.tumba'
      if (path.extname(cli.flags.decrypt) === '.tumba') {
        inquirer
          .prompt([
            {
              message: 'Password:',
              name: 'password',
              type: 'password',
              mask: true,
            },
          ])
          .then((answer) => {
            // Decrypt file. Iterations only used for legacy files.
            tumba.decrypt(
              cli.flags.decrypt,
              answer.password,
              cli.flags.iterations ?? LEGACY_ITERATIONS,
              cli.flags.outDir,
            );
          });
      } else {
        console.log('Error: File must be encrypted');
      }
    } else {
      console.log('Error: Path must be a file');
    }
  } else {
    console.log('Error: File does not exist');
  }
} else {
  // Else show help message
  console.log(cli.help);
}

// Show message if process is terminated
process.on('uncaughtException', (error) => {
  if (error instanceof Error && error.name === 'ExitPromptError') {
    console.log('Process cancelled');
  } else {
    throw error;
  }
});
