>[!CAUTION]
>There is a bug, if you encrypt a file larger than ~1.5G it won't be decryptable.<br>
>Use the [aes-gcm branch](https://github.com/D4MI4NX/go-dencrypt/tree/aes-gcm) for now if you need.
>(Incompatible with main)

# go-dencrypt

go-dencrypt is a tool for file encryption and decryption. It uses AES encryption with CFB mode and Argon2 key derivation function for secure encryption.



# Usage

The tool is interactive and all arguments are optional. Run it with the following command:

```shell
./dencrypt_<os>_<arch>(.exe) [options] [files]
```

# 

# Options

Following command line options are supported:

    -H    Include hidden files (.*)
    -L    Print license information and exit
    -P string
        Specify password
    -V    Print version and exit
    -b    Include backup files (*~,*.bak)
    -e string
          Exclude one or more multiple files (comma seperated) or with shell patterns
    -ed
          Use the directory the executable is stored in (reversed on windows)
    -f    Dont ask for confirmation
    -fn
          En/Decrypt the filename
    -gr int
          Specify the number of concurrent files to en/decrypt
    -gz
          Use gzip compression for files
    -k    Keep input file(s)
    -m string
          Select mode (Encrypt: e  Decrypt: d)
    -nc
          Disable color output
    -nt
          Disable file tree view
    -p string
          Specify path to use (default ".")
    -rd int
          Specify the depth of the recursive traversal
    -si
          Shred the input file(s) before deletion
    -v    Print more information



# Encrypting files

![](https://github.com/D4MI4NX/go-dencrypt/blob/main/dencrypt_demo_encrypt.gif)

By default, the tool will select all unencrypted files in the current 
directory. You can also specify a single file, multiple files or shell patterns to 
encrypt by providing them as command-line arguments.

Then you will see the selected files in a tree-like format.

You will then be prompted for a password, which will be used to generate a key using Argon2 for encryption. After entering and confirming the password, you will see the password's ID (first 8 characters of the password's SHA512 hash). This helps to ensure you use the correct password if you remember its ID.



# Decrypting files

The process of decrypting files is almost the same as encrypting them.



# Config file

If you run the tool, a config file at `.dencrypt.config.yaml` will be created, unless one already exists.
It can be used to specify default values without having to use CLI flags. CLI flags are prioritized over the config file.
You can use the `CONFIG_FILE` environment variable to specify another config file at given path. This option is used both to specify a config file and create one at given path.
There also is a `IGNORE_CONFIG` environment variable to ignore values from the config file.

> [!NOTE]
> 
> Environment variables can be set like this:
> 
> Unix/Linux:
> 
> `VARIABLE=value ./program`
> 
> Windows:
> 
> `set VARIABLE=value && .\program.exe`



# Notes

- File list tree-like format inspired by https://gitlab.com/OldManProgrammer/unix-tree

- If encrypted files are found and files are going to be encrypted, salt from the already encrypted files will be used

- The encrypted files will have the extension .enc added to their original filenames and removed at decryption

- This tool was primarily developed on the latest version of Manjaro and occasionally on Android using Termux
  
  

# Compile yourself

Install go from your distro's package manager or the official website (https://go.dev/dl).

**Clone the repo**:

```shell
git clone https://github.com/D4MI4NX/go-dencrypt.git
```

...or download the zip.

**Change directory to the source code**:

```shell
cd go-dencrypt
```

**Install go dependencies**:

```shell
go mod tidy
```

**Build**:

```shell
make
```

  or

```shell
go build -ldflags "-s -w"
```

or recommended (linux only)

```shell
go build -ldflags "-s -w" -buildmode pie
```

**Install**:

If built with `make`, the binary will be stored as /path/to/go-dencrypt/bin/dencrypt(.exe). Else as /path/to/go-dencrypt/dencrypt(.exe).

    make install

  ...if compiled with make. This will copy the binary to /home/[user]/.local/bin, so make sure its in your path. Or...

    make install_termux

  ...for Termux. ($PREFIX/bin)



# License

This tool is released under the GPL-3.0 license.


