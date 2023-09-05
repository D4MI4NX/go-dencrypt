# go-dencrypt
go-dencrypt is a tool for file encryption and decryption. It uses AES encryption with CFB mode and Argon2 key derivation function for secure encryption.
It was originally written in python (https://github.com/D4MI4NX/python-dencrypt). But I decided to remake and improve it in Go.

# Usage

The tool is interactive and all arguments are optional. Run it with the following command:

    ./dencrypt_<os>_<arch>(.exe) [options]

# Options

The tool supports following command line options:

    -F string
        Specify one or multiple files (comma separated) or with wildcard (*)
    -L  Print license information and exit
    -bs
        Import/Export base64 encoded salt
    -e string
        Exclude one or multiple files (comma separated) or with wildcard (*)
    -ed
        Use the directory the executable is stored in (reversed on windows)
    -f  Dont ask about en/decrypting files
    -fn
        En/Decrypt the file name
    -gr int
        Specify the number of concurrent goroutines to run (default 1/4 of available cpu threads)
    -gz
        Use gzip compression for files
    -hcs
        Use hard-coded salt
    -hs
        Read or write salt from/to the home directory (~/.salt)
    -i	Increase iterations and memory usage in the key generation, making it take around 6x longer
    -k	Keep input file
    -m string
        Encrypt: e  Decrypt: d
    -nc
        Disable color output
    -nh
        Disable prompt for printing/saving the hashed password
    -p string
        Specify path to use
    -r	Selects all files in every subdirectory
    -rd int
        Specify the depth of the recursive traversal
    -s string
        Specify file containing salt
    -si
        Shred the input file before deletion
    -v	Print more information

# Encrypt files

By default, the tool will select all unencrypted files in the current directory and will ignore hidden ones (files that start with a "."). You can also specify a single file, multiple files or wildcard patterns to encrypt using the -F option. It will prompt for a password and generate a key using Argon2, which will be used for encryption. After entering and confirming the password, you will have the option to print (`y`) the SHA-256 hash of the password or save/append (`s`) it to a file ('.password.sha256' in the used directory). Saving the SHA-256 hash of the password can be useful when encrypting files again: If you entered a password, which's SHA-256 is stored in the file, you dont have to confirm the password. Saving the password's SHA-256 hash brings the risk of someone obtaining the file and cracking the password. To your advantage, you could use the passwords hash to crack it in case you forgot the password. If you dont want to be prompted for this, use the `-nh` option. Then you will see the selected files in a tree-like format and you will be prompted for a final confirmation.


# Decrypting files

The process of decrypting files is the same as encrypting them, except you won´t be prompted to confirm the password or print/save it's SHA-256.

# Selecting specific file with the `-F` option

If you want to encrypt or decrypt one file, use:

    ./dencrypt_<os>_<arch>(.exe) -F file
If you want to encrypt or decrypt multiple files, use:

    ./dencrypt_<os>_<arch>(.exe) -F file1,file2,...
If you want to encrypt or decrypt files using the wildcard pattern, use:

    ./dencrypt_<os>_<arch>(.exe) -F "*.txt"

It is recommended to use parentheses (" ") when specifying files with wildcard pattern.

You can also use a combination of them, for example:

    ./dencrypt_<os>_<arch>(.exe) -F "*.txt",file1.txt,file2.txt

The `-e` option works the same, except the files there will be excluded from en/decryption.

# Important

Don´t delete or move the .salt file while having encrypted files because it is used for key generation and wont decrypt your files without it. (except you specified another salt file using the `-s` option or used the `-hcs` option at encryption)

# Notes

• File list tree-like format inspired by http://mama.indstate.edu/users/ice/tree/

• Every time you encrypt file(s) and no encrypted files are in the current and all subdirectories, the script will generate new salt.

• The encrypted files will have the extension .enc added to their original filenames and removed at decryption.

• This tool was primarily developed on the latest version of Manjaro and occasionally on Android using Termux.

# Compile yourself

Install go from your distro's package manager or the official website (https://go.dev/doc/install).

**Clone the repo**:

    git clone https://github.com/D4MI4NX/go-dencrypt.git

...or download the zip.

**Change direcory to the source code**:

    cd go-dencrypt

**Install go dependencies**:

    go mod tidy

**Build**:

    make
  or

    go build

**Install**:

If built with `make`, the binary will be stored as /path/to/go-dencrypt/bin/dencrypt(.exe). Else as /path/to/go-dencrypt/dencrypt(.exe).


    make install
  ...if compiled with make. This will copy the binary to /home/[user]/.local/bin, so make sure its in your path. Or...

    make install_termux
  ...for Termux. ($PREFIX/bin)

# License

This tool is released under the GPL-3.0 license.
