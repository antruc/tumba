#! /usr/bin/env node
import meow from 'meow'
import inquirer from 'inquirer'
import tumba from '../lib/tumba.js'

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
        shortFlag: 'e'
      },
      decrypt: {
        type: 'string',
        shortFlag: 'd'
      },
      iterations: {
        type: 'number',
        shortFlag: 'i',
        default: 100000
      },
      outDir: {
        type: 'string',
        shortFlag: 'o',
        default: ''
      }
    }
  }
)

if (Object.hasOwn(cli.flags, 'encrypt') && cli.flags.encrypt.length > 0) {
  inquirer
    .prompt([
      {
        message: 'Password:',
        name: 'password',
        type: 'password',
        mask: true
      }
    ])
    .then((answer) => {
      if (answer.password.length > 0) {
        tumba.encrypt(
          cli.flags.encrypt,
          answer.password,
          cli.flags.iterations,
          cli.flags.outDir
        )
      } else {
        console.log('Password length must be greater than zero')
      }
    })
} else if (
  Object.hasOwn(cli.flags, 'decrypt') &&
  cli.flags.decrypt.length > 0
) {
  inquirer
    .prompt([
      {
        message: 'Password:',
        name: 'password',
        type: 'password',
        mask: true
      }
    ])
    .then((answer) => {
      if (answer.password.length > 0) {
        tumba.decrypt(
          cli.flags.decrypt,
          answer.password,
          cli.flags.iterations,
          cli.flags.outDir
        )
      } else {
        console.log('Password length must be greater than zero')
      }
    })
} else {
  console.log(cli.help)
}
