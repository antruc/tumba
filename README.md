# tumba

**Encrypt any file with a password from the terminal. AES-GCM 256 with a
PBKDF2 key, the original file name hidden inside the ciphertext, and nothing
ever overwritten**

[![npm](https://img.shields.io/npm/v/tumba)](https://www.npmjs.com/package/tumba)
![Node 22+](https://img.shields.io/badge/node-22%2B-339933?logo=nodedotjs&logoColor=white)
![WebCrypto](https://img.shields.io/badge/crypto-WebCrypto-orange)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![code style: prettier](https://img.shields.io/badge/code_style-prettier-ff69b4.svg)](https://github.com/prettier/prettier)

> Tomb *(noun)*: A vault or chamber for burial of the dead

tumba is a small Node.js CLI that encrypts any file with a password and
decrypts it back. You type the password at a prompt, and the original file
stays untouched:

```
$ tumba -e tax-return-2026.pdf
? Password: ********
? Confirm password: ********
File encrypted successfully
3f9a1c07be.tumba created

$ tumba -d 3f9a1c07be.tumba
? Password: ********
File decrypted successfully
tax-return-2026.pdf created
```

**What is a `.tumba` file?** The encrypted file tumba produces. It gets a
random name, so neither its name nor its type gives away what is inside; the
original name travels encrypted and comes back on decrypt. To open one,
install tumba (`npm install -g tumba`) and run `tumba -d <file>.tumba` with the
password used to create it

## Contents

- [Features](#features)
- [Installing](#installing)
- [Usage](#usage)
- [How it works](#how-it-works)
- [Known limitations](#known-limitations)
- [Development](#development)
- [License](#license)

## Features

- **Authenticated encryption:** AES-GCM 256. A wrong password or a single
  changed byte fails the decrypt instead of producing garbage
- **Password-derived key:** PBKDF2-SHA256 with a random 16-byte salt and
  600,000 iterations by default, the
  [OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2)
  recommendation. The count is stored in the file, so you never have to
  remember it
- **Hidden metadata:** the output name is 10 random hex characters, and the
  format version is encrypted too, so nothing about the file leaks in clear
- **Never overwrites:** decrypting next to a file with the same name stops
  with an error instead of replacing it
- **Careful writes:** output files are created readable by their owner only
  (mode `600` on Linux and macOS), and a write that fails midway (disk full)
  leaves no partial file behind
- **No third-party crypto:** encryption runs on Node's built-in WebCrypto
  (`crypto.subtle`, backed by Node's own OpenSSL). The three runtime
  dependencies (flags, password prompt, file type detection for legacy files)
  are plain JavaScript with no native addons, so nothing compiles on install
- **Hardened parsing:** an iteration count read from a tampered header is
  capped at 10,000,000, so a forged file cannot stall PBKDF2 for hours

## Installing

Requires [Node.js](https://nodejs.org) 22 or later

```bash
npm install -g tumba
```

Or run it once without installing:

```bash
npx tumba -e file.png
```

## Usage

```
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
```

| Task | Command |
|---|---|
| Encrypt into another folder (created if missing) | `tumba -e photo.jpg -o vault` |
| Encrypt with a stronger key | `tumba -e photo.jpg -i 2000000` |
| Decrypt | `tumba -d 3f9a1c07be.tumba` |
| Decrypt into another folder | `tumba -d 3f9a1c07be.tumba -o restored` |

- The password is asked twice when encrypting and once when decrypting. It
  is never taken as a flag, so it does not end up in your shell history
- Decrypt only accepts files ending in `.tumba`. If one was renamed, give it
  the extension back
- `-i` accepts 100,000 to 10,000,000 when encrypting. When decrypting it is
  only needed for files made by tumba 1.0.x, which did not store the count
  (they used 100,000)
- `-e` and `-d` cannot be combined in one run
- `Ctrl+C` at the prompt cancels with exit code 130. Any error exits with 1

## How it works

```
file ──► MAGIC + name + data ──► AES-GCM 256 ──► SIGNATURE + iterations + salt + iv + cipher ──► <random>.tumba
                                    ▲
             password ──► PBKDF2-SHA256 (salt, iterations)
```

### File format

| Bytes | Field | In clear? |
|---|---|---|
| 4 | `SIGNATURE`: `7F 54 4D 42` (`\x7FTMB`) | Yes |
| 4 | PBKDF2 iterations, big-endian | Yes |
| 16 | Salt | Yes |
| 12 | AES-GCM IV | Yes |
| rest | Ciphertext + 16-byte GCM tag | No |

Inside the ciphertext:

| Bytes | Field |
|---|---|
| 4 | `MAGIC`: `TMB1`, the format version |
| 2 | Name length, big-endian |
| n | Original file name, UTF-8 |
| rest | File contents |

The version marker lives inside the ciphertext and is checked only after a
successful decrypt, so nothing about the version or the contents leaks in
clear. The decrypted name is reduced to its base name, so a crafted file
cannot write outside the output folder. On Windows, characters the file
system rejects or treats specially (`< > : " | ? *` and control characters)
are replaced with `_`, so a file encrypted on Linux as `a:b.txt` comes back
as `a_b.txt`. An empty or unusable name falls back to the `.tumba` file's
own name

Files without `SIGNATURE` are read as the 1.0.x format (`salt + iv + cipher`,
no stored name). Their extension is guessed from the content with
[file-type](https://github.com/sindresorhus/file-type)

## Known limitations

- **Memory:** the whole file is held in memory, because WebCrypto AES-GCM has
  no streaming API. Files near 2 GB fail to read, and peak memory use is
  several times the file size, so expect to need about 4 GB of free RAM for
  a 1 GB file
- **One file at a time:** to encrypt a folder, zip it first
- **No password recovery:** a forgotten password means the file is gone. That
  is the point

## Development

```bash
git clone https://github.com/antruc/tumba.git
cd tumba && npm install
npm test             # vitest
npm run lint         # eslint
npm run prettier     # format check
npm run format       # fix lint and format
```

| Path | What it does |
|---|---|
| [bin/index.js](bin/index.js) | CLI: flags, password prompts, input checks, exit codes |
| [lib/tumba.js](lib/tumba.js) | File format: header, embedded name, legacy files, safe writes |
| [lib/aes.js](lib/aes.js) | PBKDF2 key derivation and AES-GCM encrypt/decrypt |
| [tests/](tests/) | Round trips, tampering, wrong password, no-overwrite, crafted names, legacy format |

## License

[MIT](LICENSE) © Antruc
