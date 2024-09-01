/* go-dencrypt is a tool for file encryption and decryption. It uses AES encryption with CFB mode and Argon2 key derivation function for secure encryption.

Copyright (C) 2023-2024 D4MI4NX

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation version 3.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>*/

package main

import (
    "bytes"
    "compress/gzip"
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha512"
    "encoding/hex"
    "errors"
    "fmt"
    "github.com/AlecAivazis/survey/v2"
    "github.com/fatih/color"
    "github.com/lu4p/shred"
    "github.com/zenazn/pkcs7pad"
    "golang.org/x/crypto/argon2"
    "io"
    "io/ioutil"
    "os"
    "path/filepath"
    "strings"
    "time"
)

var (
    CiphertextBlockSizeTooShort = errors.New("Ciphertext block size is too short!")
)

// GetFilesFromPattern returns file paths by the
// specified shell pattern or directories.
func GetFilesFromPattern(pattern string) ([]string) {
    var files []string

    if info, err := os.Stat(pattern); err == nil && info.IsDir() {
        filepath.WalkDir(pattern, func(path string, e os.DirEntry, err error) error {
            if err != nil {
                return err
            }

            if !e.IsDir() {
                files = append(files, path)
            }

            return nil
        })
    } else {
        matches, _ := filepath.Glob(pattern)
        matches = Filter(matches, IsRegularFile)
        files = append(files, matches...)
    }

    return files
}

// ConfirmOverwrite will prompt for confirmation to overwrite a file.
// It also has arguments to enable prompting wether all files, or none should be overwritten.
// Then it returns wether the (file can be overwritten),
// (all files can be overwritten) and (no files can be overwritten).
func ConfirmOverwrite(file string, allOption, noneOption bool) (bool, bool, bool) {
    var inp string
    allText := ""
    if allOption {
        allText = "|[all]"
    }
    noneText := ""
    if noneOption {
        noneText = "|[none]"
    }

    if IsRegularFile(file) {
        fmt.Printf("File %s exists. Overwrite? ([y]es|[n]o%s%s)\n>", color.MagentaString(file), allText, noneText)
        fmt.Scan(&inp)
        inp = strings.ToLower(inp)
        if inp == "all" && allOption {
            return true, true, false
        } else if inp == "none" && noneOption {
            return false, false, true
        } else if (inp != "y") == (inp != "yes") {
            return false, false, false
        }
    }
    return true, false, false
}

type TreeNode struct {
        Name     string
        IsDir    bool
        Path   string
        Children []*TreeNode
}

// BuildTree returns a *TreeNode built from a slice of file paths.
func BuildTree(files []string) *TreeNode {
    var root *TreeNode

    root = &TreeNode{Name: ".", IsDir: true}

    for _, file := range files {
        path := strings.Split(file, string(filepath.Separator))
        currentNode := root

        for i := 0; i < len(path); i++ {
            dirName := path[i]

            var childNode *TreeNode
            for _, child := range currentNode.Children {
                if child.Name == dirName {
                    childNode = child
                    break
                }
            }

            if childNode == nil {
                isDir := i < len(path)-1
                childNode = &TreeNode{Name: dirName, Path: file, IsDir: isDir}
                currentNode.Children = append(currentNode.Children, childNode)
            }
            currentNode = childNode
        }
    }
    return root
}

// PrintTree prints a *TreeNode object.
func PrintTree(node *TreeNode, indent string, lastChild bool) {
    boldBlue := color.New(color.FgBlue, color.Bold)
    boldGreen := color.New(color.FgGreen, color.Bold)
    boldRed := color.New(color.FgRed, color.Bold)
    boldMagenta := color.New(color.FgMagenta, color.Bold)
    boldCyan := color.New(color.FgCyan, color.Bold)

    if lastChild {
        fmt.Print(indent + "`-- ")
        indent += "    "
    } else {
        fmt.Print(indent + "|-- ")
        indent += "|   "
    }

    if node.IsDir {
        boldBlue.Println(node.Name)
    } else {
        if fileInfo, err := os.Stat(node.Path); err == nil && (fileInfo.Mode().Perm()&0111 != 0 || HasAnySuffix(node.Name, ".exe", ".com", ".out", ".elf", ".jar", ".bat", ".cmd", ".sh", ".run", ".app", ".py", ".php", ".pl", ".rb", ".bin")) {
            boldGreen.Println(node.Name)
        } else if HasAnySuffix(node.Name, ".tar", ".gz", ".xz", ".zip", ".bz2", ".7z", ".lzma", ".z", ".tbz2", ".tgz", ".txz", ".lzw", ".zst") {
            boldRed.Println(node.Name)
        } else if HasAnySuffix(node.Name, ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".tif", ".webp", ".heic", ".heif", ".svg", ".mp4", ".avi", ".mkv", ".mov", ".wmv", ".flv", ".webm", ".3gp", ".wma") {
            boldMagenta.Println(node.Name)
        } else if HasAnySuffix(node.Name, ".mp3", ".aac", ".flac", ".m4a", ".ogg", ".wav") {
            boldCyan.Println(node.Name)
        } else {
            fmt.Println(node.Name)
        }
    }

    if node.IsDir {
        for i, child := range node.Children {
            last := i == len(node.Children)-1
            PrintTree(child, indent, last)
        }
    }
}

// ShredFile overwrites a file at given path multiple times
// to make it harder to recover its data.
func ShredFile(path string) {
    shredconf := shred.Conf{Times: 2, Zeros: true, Remove: false}
    shredconf.File(path)
}

// PromptPassword will prompt for a password and optionally ask for confirmation.
func PromptPassword(confirm bool) (string, error) {
    var password, passwordConfirm string
    var err error

    for {
        prompt := &survey.Password{Message: "Password:"}
        err = survey.AskOne(prompt, &password)
        if err != nil {
            return "", err
        }

        if confirm {
            prompt := &survey.Password{Message: " Confirm:"}
            err = survey.AskOne(prompt, &passwordConfirm)
            if err != nil {
                return "", err
            }

            if password == passwordConfirm {
                break
            } else if password != passwordConfirm {
                color.Yellow("Passwords didnt match!")
                continue
            }
        }

        break
    }

    return password, nil
}

// Contains checks wether a string is present in a []string.
func Contains(s []string, str string) bool {
    for _, i := range s {
        if i == str {
            return true
        }
    }
    return false
}

// HasAnySuffix checks wether a string has one of the specified suffixes.
func HasAnySuffix(s string, suffixes ...string) bool {
	for _, suffix := range suffixes {
		if strings.HasSuffix(strings.ToLower(s), suffix) {
			return true
		}
	}
	return false
}

// IsRegularFile checks wether a path is a regular file.
func IsRegularFile(path string) bool {
    info, err := os.Stat(path)
    if err != nil {
        return false
    }

    return !info.IsDir()
}

// Filter filters an []string conditionally.
func Filter(input []string, condition func(string) bool) []string {
	var result []string
	for _, item := range input {
		if condition(item) {
			result = append(result, item)
		}
	}
	return result
}

// GenerateKey generates an Argon2ID key with given password and salt.
func GenerateKey(password string, salt []byte) []byte {
    return argon2.IDKey([]byte(password), salt, 64, 128*1024, 4, 32)
}

// GenerateSalt generates random bytes of given length.
func GenerateSalt(length int) ([]byte, error) {
    salt := make([]byte, length)
    _, err := rand.Read(salt)
    if err != nil {
        return []byte{}, err
    }

    return salt, nil
}

// EncryptFilename encrypts a file name by given checksum.
func EncryptFilename(file string, sum []byte) (string, error) {
    path := strings.TrimSuffix(file, filepath.Base(file))
    ext := filepath.Ext(file)
    name := strings.TrimSuffix(filepath.Base(file), ext)

    iv := make([]byte, 4)
    if _, err := io.ReadFull(rand.Reader, iv); err != nil {
       return "", err
    }
    iv = append(iv, make([]byte, aes.BlockSize - len(iv))...)

    key := argon2.Key(sum, iv, 4, 32*1024, 4, 32)

    block, err := aes.NewCipher(key)
    if err != nil {
        return "", err
    }

    paddedPlaintext := pkcs7pad.Pad([]byte(name), aes.BlockSize)

    ciphertext := make([]byte, aes.BlockSize+len(paddedPlaintext))
    copy(ciphertext[:aes.BlockSize], iv)

    stream := cipher.NewCFBEncrypter(block, iv)
    stream.XORKeyStream(ciphertext[aes.BlockSize:], paddedPlaintext)

    encodedEncryptedFilename := hex.EncodeToString(append(ciphertext[:4], ciphertext[aes.BlockSize:]...))

    return filepath.Join(path, encodedEncryptedFilename) + ext, nil
}

// DecryptFilename decrypts a file name by given checksum.
func DecryptFilename(file string, sum []byte) (string, error) {
    path := strings.TrimSuffix(file, filepath.Base(file))
    name := strings.Split(filepath.Base(file), ".")[0]

    decodedFilename, err := hex.DecodeString(name)
    if err != nil {
        return "", err
    }

    if len(decodedFilename) < 6 {
        return "", errors.New("Name too short!")
    }

    iv := make([]byte, 4, 16)
    copy(iv, decodedFilename[:4])
    iv = append(iv, make([]byte, 12)...)
    ciphertext := decodedFilename[4:]

    key := argon2.Key(sum, iv, 4, 32*1024, 4, 32)

    block, err := aes.NewCipher(key)
    if err != nil {
        return "", err
    }

    if len(ciphertext) < aes.BlockSize {
        return "", errors.New("Ciphertext block size is too short!")
    }

    stream := cipher.NewCFBDecrypter(block, iv)
    stream.XORKeyStream(ciphertext, ciphertext)

    plaintext, err := pkcs7pad.Unpad(ciphertext)
    if err != nil {
        return "", err
    }

    decryptedFilename := string(plaintext)

    decryptedFilename += strings.Join(strings.Split(filepath.Base(file), name)[1:], "")

    return filepath.Join(path, decryptedFilename), nil
}

// GetFileModTime returns the file modification date.
func GetFileModTime(file string) (time.Time, error) {
    fileData, err := os.Stat(file)
    if err != nil {
        return time.Time{}, err
    }

    return fileData.ModTime(), nil
}

// ModifyFileModTime modifys a files modificatiom date.
func ModifyFileModTime(file string, newTime time.Time) error {
    return os.Chtimes(file, time.Now(), newTime)
}

// Encrypt encrypts a given []byte with given key and returns it.
func Encrypt(key, plaintext []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return []byte{}, err
    }

    nonce := make([]byte, 12)
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        return []byte{}, err
    }

    aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return []byte{}, err
	}

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)

    return append(nonce, ciphertext...), nil
}

// Decrypt decrypts a []byte with given key and returns it.
func Decrypt(key, ciphertext []byte) ([]byte, error) {
    if len(ciphertext) < 12 {
        return []byte{}, errors.New("ciphertext too short!")
    }

    nonce := ciphertext[:12]
    ciphertext = ciphertext[12:]

    block, err := aes.NewCipher(key)
    if err != nil {
        return []byte{}, err
    }

    aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return []byte{}, err
	}

    plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)

    return plaintext, err
}

// GzipCompress compresses a given []byte and returns it.
func GzipCompress(data []byte) []byte {
    var cf bytes.Buffer
    gw := gzip.NewWriter(&cf)
    gw.Write(data)
    gw.Close()

    return cf.Bytes()
}

// GzipDecompress decompresses a given []byte and returns it.
func GzipDecompress(data []byte) ([]byte, error) {
    gr, err := gzip.NewReader(bytes.NewReader(data))
    if err != nil {
        return []byte{}, err
    }
    defer gr.Close()

    decompressedData, err := ioutil.ReadAll(gr)

    return decompressedData, nil
}

// IsEncrypted checks wether a file contains the .enc extension.
func IsEncrypted(file string) bool {
    file = filepath.Base(file)

    if strings.Contains(file, ".enc.") || strings.HasSuffix(file, ".enc") {
        return true
    }

    return false
}

// ReadFirstXByte returns the first x byte of a file.
func ReadFirstXByte(file string, x int) ([]byte, error) {
    f, err := os.Open(file)
    if err != nil {
        return []byte{}, err
    }
    defer f.Close()

    buffer := make([]byte, x)
    _, err = f.Read(buffer)
    if err != nil {
        return []byte{}, err
    }

    return buffer, nil
}

// GetID returns a unique identifier
// made by the first 8 characters of its SHA512 checksum.
func GetID(input []byte) string {
    sha512Hash := sha512.Sum512(input)
    id := hex.EncodeToString(append([]byte{}, sha512Hash[:]...))

    return id[:8]
}

// FilterFilesByDepth filters out files
// that are not in the specified recursion depth.
func FilterFilesByDepth(files []string, depth int) []string {
    files = Filter(files, func(path string) bool {
        return (depth < 0 || strings.Count(path, string(filepath.Separator)) <= depth)
    })

    return files
}

// FilenameIsHex returns wether a file name is HEX encoded.
func FilenameIsHex(filename string) bool {
    filename = filepath.Base(filename)
    filename = strings.Split(filename, ".")[0]

    if _, err := hex.DecodeString(filename); err != nil {
        return false
    }

    return true
}

// IsLink returns wether a file is a link
func IsLink(path string) bool {
    _, err := os.Readlink(path)
    return err == nil
}
