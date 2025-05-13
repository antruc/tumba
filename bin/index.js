#! /usr/bin/env node
import meow from 'meow';
import { lstatSync } from 'node:fs';
import inquirer from 'inquirer';
import tumba from '../lib/tumba.js';

const cli = meow(
  `
  Usage
    $ tumba -option <input>

  Options
    --encrypt, -e  Encrypt a file from disk
    --decrypt, -d  Decrypt a file to disk
    --iterations, -i  Number of iterations (Default: 100000)
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
        default: 100000,
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
  const isFile = lstatSync(cli.flags.encrypt).isFile();
  // Check if path is a file
  if (isFile) {
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
        // Check if password string is not empty
        if (answer.password.length > 0) {
          // Encrypt file
          tumba.encrypt(
            cli.flags.encrypt,
            answer.password,
            cli.flags.iterations,
            cli.flags.outDir,
          );
        } else {
          console.log('Error: Password length must be greater than zero');
        }
      });
  } else {
    console.log('Error: Path must be a file');
  }
} else if (
  Object.hasOwn(cli.flags, 'decrypt') &&
  cli.flags.decrypt.length > 0
) {
  const isFile = lstatSync(cli.flags.decrypt).isFile();
  if (isFile) {
    // Check if file includes '.tumba'
    if (cli.flags.decrypt.includes('.tumba')) {
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
          // Decrypt file
          tumba.decrypt(
            cli.flags.decrypt,
            answer.password,
            cli.flags.iterations,
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
  // Else show help message
  console.log(cli.help);
}

// Exit if process is terminated
process.on('uncaughtException', (error) => {
  if (error instanceof Error && error.name === 'ExitPromptError') {
    console.log('Process cancelled');
  } else {
    // Else rethrow unknown errors
    throw error;
  }
});
