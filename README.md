# tumba

![npm](https://img.shields.io/npm/v/tumba)
[![code style: prettier](https://img.shields.io/badge/code_style-prettier-ff69b4.svg?style=flat-square)](https://github.com/prettier/prettier)

> Tomb *(noun)*: A vault or chamber for burial of the dead

Encrypt and Decrypt files using AES-GCM 256 with PBKDF2 derived keys

# Install
```
npm install -g tumba
```

# Usage
```
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
```
