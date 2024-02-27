/* go-dencrypt is a tool for file encryption and decryption. It uses AES encryption with CFB mode and Argon2 key derivation function for secure encryption.

Copyright (C) 2023  D4MI4NX

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
    "bufio"
    "bytes"
    "compress/gzip"
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "encoding/base64"
    "encoding/hex"
    "errors"
    "fmt"
    "flag"
    "github.com/AlecAivazis/survey/v2"
    "github.com/fatih/color"
    "github.com/lu4p/shred"
    "github.com/schollz/progressbar/v3"
    "github.com/zenazn/pkcs7pad"
    "golang.org/x/crypto/argon2"
    "gopkg.in/yaml.v2"
    "io"
    "io/ioutil"
    "log"
    "math"
    "os"
    "path/filepath"
    "runtime"
    "strings"
    "sync"
    "time"
)

var encFiles []string
var shaPassFile bool
var shaFileHash string
var useHcs bool
var path string
var rootPath string
var err error
var homeSalt bool
var saltArg string
var verbose bool
var useGzip bool
var cpuThreads int = int(math.Round(float64(runtime.NumCPU()) / 2))
var b64salt bool
var keepIF bool
var us bool
var shredIF bool
var encFn bool
var noHash bool
var separator string
var recursive bool
var recDepth int
var bsSalt string

type TreeNode struct {
        Name     string
        IsDir    bool
        OgName   string
        Children []*TreeNode
}

type Config struct {
    B64Salt      bool   `yaml:"b64salt"`
    CpuThreads   int    `yaml:"cpuThreads"`
    EncFn        bool   `yaml:"encFilename"`
    Exclude      string `yaml:"exclude"`
    ExecDir      bool   `yaml:"executableDir"`
    File         string `yaml:"file"`
    Force        bool   `yaml:"force"`
    HomeSalt     bool   `yaml:"homeSalt"`
    KeepIF       bool   `yaml:"keepInputFiles"`
    Mode         string `yaml:"mode"`
    NoColor      bool   `yaml:"noColor"`
    NoHash       bool   `yaml:"noHash"`
    NoTree       bool   `yaml:"noTree"`
    Password     string `yaml:"password"`
    Path         string `yaml:"path"`
    RecDepth     int    `yaml:"recursiveDepth"`
    Recursive    bool   `yaml:"recursive"`
    Salt         string `yaml:"saltFile"`
    ShowLicense  bool   `yaml:"showLicense"`
    ShowVersion  bool   `yaml:"showVersion"`
    ShredIF      bool   `yaml:"shredInputFiles"`
    Us           bool   `yaml:"us"`
    UseGzip      bool   `yaml:"useGzip"`
    UseHcs       bool   `yaml:"useHcs"`
    Verbose      bool   `yaml:"verbose"`
}

func main() {
    var file string
    var mode string
    var force bool
    var noColor bool
    var exclude string
    var password string
    var genSalt bool
    var execDir bool
    var files []string
    var showLicense bool
    var inp string
    var showVersion bool
    var noTree bool
    var filteredFiles []string

    var ignoreConfig bool
    var configFile string

    // ----- ClI flags -----
    flag.StringVar(&file, "F", file, "Specify one or multiple files (comma separated) or with wildcard (*)")
    flag.StringVar(&mode, "m", mode, "Encrypt: e  Decrypt: d")
    flag.BoolVar(&force, "f", force, "Dont ask about en/decrypting files")
    flag.BoolVar(&useHcs, "hcs", useHcs, "Use hard-coded salt")
    flag.BoolVar(&execDir, "ed", execDir, "Use the directory the executable is stored in (reversed on windows)")
    flag.BoolVar(&homeSalt, "hs", homeSalt, "Read or write salt from/to the home directory (~/.salt)")
    flag.StringVar(&saltArg, "s", saltArg, "Specify file containing salt")
    flag.BoolVar(&verbose, "v", verbose, "Print more information")
    flag.BoolVar(&useGzip, "gz", useGzip, "Use gzip compression for files")
    flag.IntVar(&cpuThreads, "gr", cpuThreads, "Specify the number of concurrent goroutines to run")
    flag.BoolVar(&b64salt, "bs", b64salt, "Import/Export base64 encoded salt")
    flag.BoolVar(&noColor, "nc", noColor, "Disable color output")
    flag.BoolVar(&keepIF, "k", keepIF, "Keep input file(s)")
    flag.BoolVar(&us, "i", us, "Increase iterations and memory usage in the key generation, making it take around 6x longer")
    flag.BoolVar(&shredIF, "si", shredIF, "Shred the input file(s) before deletion")
    flag.BoolVar(&encFn, "fn", encFn, "En/Decrypt the file name")
    flag.BoolVar(&noHash, "nh", noHash, "Disable prompt for printing/saving the hashed password")
    flag.BoolVar(&recursive, "r", recursive, "Selects all files in every subdirectory")
    flag.StringVar(&exclude, "e", exclude, "Exclude one or multiple files (comma separated) or with wildcard (*)")
    flag.BoolVar(&showLicense, "L", showLicense, "Print license information and exit")
    flag.IntVar(&recDepth, "rd", recDepth, "Specify the depth of the recursive traversal")
    flag.StringVar(&path, "p", path, "Specify path to use")
    flag.StringVar(&password, "P", password, "Specify password")
    flag.BoolVar(&showVersion, "V", showVersion, "Print version and exit")
    flag.BoolVar(&noTree, "nt", noTree, "Disable file tree view")
    flag.BoolVar(&ignoreConfig, "ic", false, "Ignore config file")
    flag.StringVar(&configFile, "c", ".dencrypt.config.yaml", "Specify config file to use or create new one on given path")
    flag.StringVar(&bsSalt, "bss", "", "Specify the base64-encoded salt for decryption with the -bs option")
    flag.Parse()
    // ------------------------------

    defaultConfig := `b64salt: false           # Display base64 encoded salt at key generation (Write it down!). (default false)
cpuThreads: 0            # CPU threads to use for concurrent en/decryption (-1: all, -2: half...). (default 0 (half available threads))
encFilename: false       # En/Decrypt file name. (default false)
exclude: ""              # Specify file(s) to exclude. Example: "text.txt,image.png,*.zip". (default "")
executableDir: false     # Use path the executable is stored in. (default false)
file: ""                 # Specify file(s) to use exclusively. (default "")
force: false             # Skip display of file(s) and confirmation prompt. (default false)
homeSalt: false          # Store/Read salt from the home directory (~/.salt). (default false)
keepInputFiles: false    # Keep the input files. (default false)
mode: ""                 # Specify the mode to use. "e" for encrypt and "d" for decrypt. (default "")
noColor: false           # Disable color. (default false)
noHash: false            # Dont ask about printing/storing the salted hash of the entered pasword. (default false)
noTree: false            # Display the files under each over instead of a tree view. (default false)
password: ""             # Specify password to use. Not recommended. (default "")
path: ""                 # Specify path to use. (default "")
recursive: false         # Use all files in every subdirectory. (default false)
recursiveDepth: 0        # Specify the depth of recursive traversal. (default 0 (unlimited))
saltFile: ""             # Specify file to store/read the salt from. (default "")
showLicense: false       # Print license information and exit. (default false)
showVersion: false       # Print version and exit. (default false)
shredInputFiles: false   # Shred (overwrite the input file(s) multiple times) before deletion. (default false)
us: false                # Increase iterations and memory usage in the key generation, making it take around 6x longer. (default false)
useGzip: false           # (De)Compress input files using gzip. (default false)
useHcs: false            # Use hard-coded salt. (default false)
verbose: false           # Print more information. (default false)`

    log.SetFlags(0)

    // ----- Read config and decide what values to use -----
    if !ignoreConfig {
        if !IsRegularFile(configFile) {
            err = ioutil.WriteFile(configFile, []byte(defaultConfig), 0644)
            if err != nil {
                fmt.Println(err)
            } else {
                fmt.Printf("Config file written to %s\n", configFile)
            }
        } else {
            config, err := readConfig(configFile)
            if err != nil {
                fmt.Printf("Error reading config file: %v\n", err)
            } else {
                if file == "" {
                    file = config.File
                }
                if mode == "" {
                    mode = config.Mode
                }
                if !force {
                    force = config.Force
                }
                if !noColor {
                    noColor = config.NoColor
                }
                if exclude == "" {
                    exclude = config.Exclude
                }
                if password == "" {
                    password = config.Password
                }
                if !execDir {
                    execDir = config.ExecDir
                }
                if !recursive {
                    recursive = config.Recursive
                }
                if !showLicense {
                    showLicense = config.ShowLicense
                }
                if !showVersion {
                    showVersion = config.ShowVersion
                }
                if !noTree {
                    noTree = config.NoTree
                }

                // Global variables
                if !useHcs {
                    useHcs = config.UseHcs
                }
                if path == "" {
                    path = config.Path
                }
                if !homeSalt {
                    homeSalt = config.HomeSalt
                }
                if saltArg == "" {
                    saltArg = config.Salt
                }
                if !verbose {
                    verbose = config.Verbose
                }
                if !useGzip {
                    useGzip = config.UseGzip
                }
                if cpuThreads == int(math.Round(float64(runtime.NumCPU()) / 2)) && config.CpuThreads != 0 {
                    cpuThreads = config.CpuThreads
                }
                if !b64salt {
                    b64salt = config.B64Salt
                }
                if !keepIF {
                    keepIF = config.KeepIF
                }
                if !us {
                    us = config.Us
                }
                if recDepth == 0 {
                    recDepth = config.RecDepth
                }
                if !shredIF {
                    shredIF = config.ShredIF
                }
                if !encFn {
                    encFn = config.EncFn
                }
                if !noHash {
                    noHash = config.NoHash
                }
            }
        }
    }
    // ------------------------------

    // ----- Get path separator -----
    separator = string(filepath.Separator)
    // ------------------------------

    if showVersion {
        fmt.Println("go-dencrypt 1.3.14")
        os.Exit(0)
    }

    if showLicense {
        fmt.Println(`go-dencrypt is a tool for file encryption and decryption. It uses AES encryption with CFB mode and Argon2 key derivation function for secure encryption.

Copyright (C) 2023  D4MI4NX

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation version 3.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>`)
        os.Exit(0)
    }

    if noColor {color.NoColor = true}

    // ----- Decide how many CPU threads to use -----
    if verbose {fmt.Println("Amount of available cpu threads:", runtime.NumCPU())}

    if cpuThreads < 0 || runtime.NumCPU() < cpuThreads || cpuThreads == 0 {
        argCpuThreads := cpuThreads
        cpuThreads = int(math.Round(float64(runtime.NumCPU()) / 2))
        if argCpuThreads < 0 {
            cpuThreads = int(math.Round(float64(runtime.NumCPU()) / (float64(argCpuThreads) * -1)))
            if cpuThreads < 1 {
                cpuThreads = 1
            }
        } else if runtime.NumCPU() < argCpuThreads {
            color.Yellow(fmt.Sprintf("Cannot use more than %d concurrent goroutines. Using %d.", runtime.NumCPU(), cpuThreads))
        }
    }

    if verbose {fmt.Printf("Using %d threads.\n", cpuThreads)}
    // ------------------------------

    // ----- Exit on invalid mode -----
    if mode != "e" && mode != "d" && mode != "" {
        fmt.Printf("Mode %s not found!\n", mode)
    }
    // ------------------------------

    // ----- Change path -----
    if rootPath, err = os.Getwd(); err != nil {
        log.Fatal(err)
    }

    if path != "" {
        if err = os.Chdir(path); err != nil {
            log.Fatal(err)
        }
    } else if (!execDir && runtime.GOOS == "windows") || (execDir && runtime.GOOS != "windows") {
        if path, err = os.Executable(); err != nil {
            log.Fatal(err)
        }
        if path, err = filepath.Abs(filepath.Dir(path)); err != nil {
            log.Fatal(err)
        }
        os.Chdir(path)
    } else {
        if path, err = os.Getwd(); err != nil {
            log.Fatal(err)
        }
    }

    if verbose {fmt.Println("Using path:", path)}
    // ------------------------------

    // ----- Get ignored files -----
    ignoredFiles := []string{
        filepath.Base(os.Args[0]),
        "main.go",
        "go.mod",
        "go.sum",
        "Makefile",
        "README.md",
        "LICENSE",
        "dencrypt",
        "dencrypt.exe",
        "dencrypt_windows_amd64.exe",
        "dencrypt_windows_arm64.exe",
        "dencrypt_linux_amd64",
        "dencrypt_linux_arm64",
    }

    if exclude != "" {
        ignoredFiles = append(ignoredFiles, getFiles(exclude)...)
    }
    // ------------------------------

    // ----- Get files and check for encrypted files -----
    entries, err := os.ReadDir(".")
    if err != nil {
        log.Fatal(err)
    }

    modePrompt := true
    genSalt = true

    for _, _file := range entries {
        if !_file.IsDir() && !strings.HasPrefix(_file.Name(), ".") {
            if file == "" && !recursive {
                files = append(files, _file.Name())
            }
            if strings.Contains(_file.Name(), ".enc.") || strings.HasSuffix(_file.Name(), ".enc") {genSalt = false}
        }
    }

    err = filepath.WalkDir(".", func(path string, d os.DirEntry, err error) error {
        if err != nil && (verbose || recursive) {
            color.Yellow(fmt.Sprint(err))
        }

        if !d.IsDir() && !strings.HasPrefix(d.Name(), ".") {
            if file == "" && recursive && (recDepth <= 0 || strings.Count(path, separator) <= recDepth) {
                files = append(files, path)
            }
            if strings.Contains(d.Name(), ".enc.") || strings.HasSuffix(d.Name(), ".enc") {
                genSalt = false
            }
        }
        return nil
    })
    if err != nil {
        log.Fatal(err)
    }

    if file == "" {
        for _, file := range files {
            skip := false
            for _, part := range strings.Split(file, separator) {
                if strings.HasPrefix(part, ".") {
                    skip = true
                    break
                }
            }
            if !skip {
                filteredFiles = append(filteredFiles, file)
            }
        }
        files = filteredFiles
    }
    // ------------------------------

    // ----- Get files specified by flag -----
    if file != "" {
        files = getFiles(file)
    }
    // ------------------------------

    // ----- Look for .password.sha256 file -----
    if _, err := os.Stat(".password.sha256"); err == nil {
        shaPassFile = true
        if verbose {fmt.Println(".password.sha256 found.")}
    } else if os.IsNotExist(err) {
        shaPassFile = false
        if verbose {fmt.Println(".password.sha256 not found.")}
    } else {
        log.Fatal(err)
    }
    // ------------------------------

    // ----- Filter files -----
    filteredFiles = []string{}

    for _, file := range files {
        for strings.HasPrefix(file, fmt.Sprintf(".%s", separator)) {
           file = strings.TrimPrefix(file, fmt.Sprintf(".%s", separator))
        }
        filteredFiles = append(filteredFiles, file)
    }

    files = filteredFiles

    files = filter(files, func(s string) bool {
        return !Contains(ignoredFiles, s) && !(strings.HasSuffix(s, "~") && file == "")
    })
    // ------------------------------

    // ----- Split not encrypted and encrypted files -----
    for i := 0; i < len(files); i++ {
        if strings.Contains(files[i], ".enc.") || strings.HasSuffix(files[i], ".enc") {
            encFiles = append(encFiles, files[i])
            files = append(files[:i], files[i+1:]...)
            i--
        }
    }
    // ------------------------------

    // ----- Exit if no files found -----
    if len(files) == 0 && len(encFiles) == 0 {
        color.Red("No files found!")
        os.Exit(0)
    }
    // ------------------------------

    // ----- Prompt for mode if necessary -----
    if modePrompt {
        if 0 < len(files) && len(encFiles) == 0 {
            mode = "e"
        } else if len(files) == 0 && 0 < len(encFiles) {
            mode = "d"
        } else {
            if mode == "" {
                for {
                    fmt.Print("[E]ncrypt or [D]ecrypt?\n>")
                    fmt.Scan(&mode)
                    mode = strings.ToLower(mode)
                    if mode == "e" || mode == "d" {
                        break
                    }
                    color.Yellow(fmt.Sprintf("Mode %s not found!", mode))
                }
            }
        }
    }
    // ------------------------------

    // ----- Select encrypted files for decryption mode -----
    if mode == "d" {
        files = encFiles
    }
    // ------------------------------

    // ----- Prompt for password if necessary -----
    if password == "" {password = PromptPassword(mode == "e")}
    // ------------------------------

    // ----- Show files and prompt for confirmation -----
    if !force {
        if !noTree {
            root := buildTree(files)
            printTree(root, "", true)
        } else {
            fmt.Println(strings.Join(files, "\n"))
        }
        if mode == "e" {
            fmt.Printf("\nEncrypt these files? ([y]es|[n]o)\n>")
        } else if mode == "d" {
            fmt.Printf("\nDecrypt these files? ([y]es|[n]o)\n>")
        }
        fmt.Scan(&inp)
        if strings.ToLower(inp) != "y" && strings.ToLower(inp) != "yes" {
            fmt.Println("[cancelled]")
            os.Exit(0)
        }
    }
    // ------------------------------

    // ----- Start en/decryption -----
    FileLoop(files, mode, password, genSalt)
    // ------------------------------
}

func getFiles(file string) ([]string) {
    var fn []string
    var files []string

    fileArg := strings.Split(file, ",")
    for i := len(fileArg) - 1; 0 <= i; i-- {
        if strings.Contains(fileArg[i], "*") {
            fn, _ = filepath.Glob(fileArg[i])
            fn = filter(fn, func(s string) bool {
                return !strings.HasPrefix(s, ".") && IsRegularFile(s)
            })
            files = append(files, fn...)
        } else if !IsRegularFile(fileArg[i]) {
            if recursive {
                err = filepath.WalkDir(fileArg[i], func(path string, d os.DirEntry, err error) error {
                    if err != nil {
                        return err
                    }

                    if !d.IsDir() && !strings.HasPrefix(d.Name(), ".") && (recDepth <= 0 || strings.Count(path, separator) <= recDepth) {
                        files = append(files, path)
                    }
                    return nil
                })
                if err != nil {
                    color.Red(fmt.Sprint(err))
                    continue
                }
            } else {
                entries, err := os.ReadDir(fileArg[i])
                if err != nil {
                    fmt.Println(err)
                }
                for _, _file := range entries {
                    if !_file.IsDir() && !strings.HasPrefix(_file.Name(), ".") {
                        files = append(files, filepath.Join(fileArg[i], _file.Name()))
                    }
                }
            }
        } else {
            if IsRegularFile(fileArg[i]) {
                files = append(files, fileArg[i])
            }
        }
    }
    return files
}

func confirmOverwrite(file string) bool {
    var inp string
    if IsRegularFile(file) {
        fmt.Printf("File %s exists. Overwrite? ([y]es|[n]o)\n>", file)
        fmt.Scan(&inp)
        if strings.ToLower(inp) != "y" || strings.ToLower(inp) != "yes" {
            return false
        }
    }
    return true
}

func readConfig(filename string) (Config, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return Config{}, err
	}

	var config Config
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return Config{}, err
	}

	return config, nil
}

func buildTree(files []string) *TreeNode {
    var root *TreeNode
    if rootPath == path {
        root = &TreeNode{Name: ".", IsDir: true}
    } else {
        root = &TreeNode{Name: path, IsDir: true}
    }
    for _, file_ := range files {
        path_ := strings.Split(file_, separator)
        currentNode := root

        for i := 0; i < len(path_); i++ {
            dirName := path_[i]

            var childNode *TreeNode
            for _, child := range currentNode.Children {
                if child.Name == dirName {
                    childNode = child
                    break
                }
            }

            if childNode == nil {
                isDir := i < len(path_)-1
                childNode = &TreeNode{Name: dirName, OgName: file_, IsDir: isDir}
                currentNode.Children = append(currentNode.Children, childNode)
            }
            currentNode = childNode
        }
    }
    return root
}

func printTree(node *TreeNode, indent string, lastChild bool) {
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
        if fileInfo, err := os.Stat(node.OgName); err == nil && (fileInfo.Mode().Perm()&0111 != 0 || hasAnySuffix(node.Name, ".exe", ".com", ".out", ".elf", ".jar", ".bat", ".cmd", ".sh", ".run", ".app", ".py", ".php", ".pl", ".rb", ".bin")) {
            boldGreen.Println(node.Name)
        } else if hasAnySuffix(node.Name, ".tar", ".gz", ".xz", ".zip", ".bz2", ".7z", ".lzma", ".z", ".tbz2", ".tgz", ".txz", ".lzw", ".zst") {
            boldRed.Println(node.Name)
        } else if hasAnySuffix(node.Name, ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".tif", ".webp", ".heic", ".heif", ".svg", ".mp4", ".avi", ".mkv", ".mov", ".wmv", ".flv", ".webm", ".3gp", ".wma") {
            boldMagenta.Println(node.Name)
        } else if hasAnySuffix(node.Name, ".mp3", ".aac", ".flac", ".m4a", ".ogg", ".wav") {
            boldCyan.Println(node.Name)
        } else {
            fmt.Println(node.Name)
        }
    }

    if node.IsDir {
        for i, child := range node.Children {
            last := i == len(node.Children)-1
            printTree(child, indent, last)
        }
    }
}

func EncryptFile(key []byte, file string) error {
    var newFile string
    var modifiedPlaintext []byte
    var fileModTime time.Time
    plaintext, err := ioutil.ReadFile(file)
    if err != nil {
        return err
    }

    fileModTime, err = getFileModTime(file)
    if err != nil && verbose {
        fmt.Println(err)
    }

    if useGzip {
        if verbose {fmt.Printf("Compressing %s...\n", file)}
        modifiedPlaintext = gzipCompress(plaintext)
        if verbose {fmt.Printf("Compressed %s.\n", file)}
    } else {
        modifiedPlaintext = plaintext
    }

    ciphertext, err := encrypt(key, modifiedPlaintext)
    if err != nil {
        return err
    }

    ext := filepath.Ext(file)
    fileName := strings.TrimSuffix(file, ext)

    if encFn {
        if _, err := hex.DecodeString(filepath.Base(fileName)); err != nil {
            fnIv := make([]byte, 4)
            if _, err := io.ReadFull(rand.Reader, fnIv); err != nil {
               return err
            }
            fnIv = append(fnIv, make([]byte, aes.BlockSize - len(fnIv))...)

            sha256Hash := sha256.Sum256(plaintext)
            fnKey := argon2.Key(append([]byte{}, sha256Hash[:]...), fnIv, 4, 32*1024, 4, 32)

            encryptedFN, err := EncryptFilename(fnKey, fnIv, strings.TrimSuffix(filepath.Base(file), ext))
            if err != nil {
                return err
            }

            encodedEncryptedFN := hex.EncodeToString(append(encryptedFN[:4], encryptedFN[aes.BlockSize:]...))

            fileName = strings.TrimSuffix(file, filepath.Base(file)) + encodedEncryptedFN
        }
    }

    if !useGzip {
        newFile = fileName + ".enc" + ext
    } else {
        newFile = fileName + ".gz" + ".enc" + ext
    }

    if verbose {fmt.Printf("Writing encrypted content to %s...\n", newFile)}
    err = ioutil.WriteFile(newFile, ciphertext, 0644)
    if err != nil {
        return err
    }
    if verbose {fmt.Printf("Wrote encrypted content to %s.\n", newFile)}

    if !fileModTime.IsZero() {
        err = modifyFileModTime(newFile, fileModTime)
        if verbose {
            if err != nil {
                fmt.Println(err)
            } else {
                fmt.Printf("Modified time on %s.\n", newFile)
            }
        }
    }

    if !keepIF {
        if shredIF {
            if verbose {fmt.Printf("Shredding %s...\n", file)}
            shredFile(file)
            if verbose {fmt.Printf("Shredded %s.\n", file)}
        }
        if verbose{fmt.Printf("Deleting %s...\n", file)}
        err = os.Remove(file)
        if err != nil {
            return err
        }
        if verbose {fmt.Printf("Deleted %s.\n", file)}
    }
    return nil
}


func DecryptFile(key []byte, file string) error {
    var decFullFname string
    var hasEncSuffix bool
    var hasGzSuffix bool
    var fileModTime time.Time
    ciphertext, err := ioutil.ReadFile(file)
    if err != nil {
        return err
    }

    fileData, err := os.Stat(file)
    if err != nil && verbose {
        fmt.Println(err)
    } else {
        fileModTime = fileData.ModTime()
    }

    plaintext, err := decrypt(key, ciphertext)
    if err != nil {
        return err
    }

    if useGzip && strings.Contains(file, ".gz.enc") {
        if verbose {fmt.Printf("Decompressing %s...\n", file)}
        gr, err := gzip.NewReader(bytes.NewReader(plaintext))
        if err != nil {
            return err
        }
        defer gr.Close()
        if verbose {fmt.Printf("Decompressed %s.\n", file)}
        plaintext, err = ioutil.ReadAll(gr)
    }

    ext := filepath.Ext(file)
    fileName := strings.TrimSuffix(file, ext)

    hasEncSuffix = false
    hasGzSuffix = false
    if encFn {
        if strings.HasSuffix(fileName, ".enc") {
            hasEncSuffix = true
            fileName = strings.TrimSuffix(fileName, ".enc")
        }
        if strings.HasSuffix(fileName, ".gz") {
            hasGzSuffix = true
            fileName = strings.TrimSuffix(fileName, ".gz")
        }

        decodedFN, err := hex.DecodeString(filepath.Base(fileName))
        if err != nil {
            fmt.Printf("%s: %v\n", filepath.Base(fileName), err)
        } else if err == nil {
            sha256Hash := sha256.Sum256(plaintext)

            fnIv := make([]byte, 4, 16)
            copy(fnIv, decodedFN[:4])
            fnIv = append(fnIv, make([]byte, 12)...)

            fnKey := argon2.Key(append([]byte{}, sha256Hash[:]...), fnIv, 4, 32*1024, 4, 32)

            decryptedFN, err := DecryptFilename(fnKey, decodedFN)
            if err != nil {
                color.Magenta(fmt.Sprintf("%s: Couldnt decrypt file name: %v\n", file, err))
                decFullFname = file
            } else {
                fileName = string(decryptedFN)
                if hasGzSuffix {
                    fileName += ".gz"
                }
                if hasEncSuffix {
                    fileName += ".enc"
                }
                decFullFname = strings.TrimSuffix(file, filepath.Base(file)) + fileName + ext
            }
        }
    } else {
        decFullFname = file
    }

    var newFile string

    if encFn {
        fileName = strings.TrimSuffix(file, filepath.Base(file)) + fileName
    }
    if useGzip && strings.Contains(fileName, ".gz") {
        if strings.Contains(file, ".") && !strings.HasPrefix(fileName, ".") && !strings.HasSuffix(file, ".enc") {
            newFile = strings.TrimSuffix(fileName, ".gz.enc") + ext
        } else {
            newFile = strings.TrimSuffix(decFullFname, ".gz.enc")
        }
    } else {
        if strings.Contains(file, ".") && !strings.HasPrefix(fileName, ".") && !strings.HasSuffix(file, ".enc") {
            newFile = strings.TrimSuffix(fileName, ".enc") + ext
        } else {
            newFile = strings.TrimSuffix(decFullFname, ".enc")
        }
    }

    if newFile == "" || newFile == file || strings.HasPrefix(newFile, ".") {
        return errors.New("Could not choose new file name")
    }

    if verbose {fmt.Printf("Writing decrypted content to %s...\n", newFile)}
    err = ioutil.WriteFile(newFile, plaintext, 0644)
    if err != nil {
        return err
    }
    if verbose {fmt.Printf("Wrote decrypted content to %s.\n", newFile)}

    if !fileModTime.IsZero() {
        err = os.Chtimes(newFile, fileModTime, fileModTime)
        if err != nil && verbose {
            fmt.Println(err)
        } else if verbose {
            fmt.Printf("Modified time on %s.\n", newFile)
        }
    }

    if !keepIF {
        if shredIF {
            if verbose {fmt.Printf("Shredding %s...\n", file)}
            shredFile(file)
            if verbose {fmt.Printf("Shredded %s.\n", file)}
        }
        if verbose {fmt.Printf("Deleting %s...\n", file)}
        err = os.Remove(file)
        if err != nil {
            return err
        }
        if verbose {fmt.Printf("Deleted %s.\n", file)}
    }
    return nil
}


func shredFile(fileName string) {
    shredconf := shred.Conf{Times: 2, Zeros: true, Remove: false}
    shredconf.File(fileName)
}


func PromptPassword(confirm bool) string {
    var password string
    var passConfirm string
    var passFile *os.File
    for true {
        prompt := &survey.Password{Message: "Password:"}
        err := survey.AskOne(prompt, &password)
        if err != nil {
            log.Fatal(err)
        }
        hashBytes := sha256.Sum256([]byte(password))
        passSha := hex.EncodeToString(hashBytes[:])

        salt := make([]byte, 16)
        _, err = rand.Read(salt)
        if err != nil {
            log.Fatal(err)
        }
        hashBytes = sha256.Sum256(append([]byte(password), salt...))
        saltedPassSha := hex.EncodeToString(hashBytes[:])

        if shaPassFile {
            passFile, err = os.Open(".password.sha256")
            if err != nil {
                log.Fatal(err)
            }
            defer passFile.Close()
            scanner := bufio.NewScanner(passFile)
            currentLine := 0
            for scanner.Scan() {
                line := strings.Split(strings.TrimSpace(scanner.Text()), " ")
                currentLine++
                if 1 < len(line) {
                    decodedSalt, err := hex.DecodeString(line[1])
                    if err != nil {
                        fmt.Printf(".password.sha256 line %d: %v\n", currentLine, err)
                    }
                    hashBytes = sha256.Sum256(append([]byte(password), decodedSalt...))
                }
                if passSha == line[0] || hex.EncodeToString(hashBytes[:]) == line[0] {
                    confirm = false
                    break
                }
            }
        }

        if confirm {
            prompt := &survey.Password{Message: " Confirm:"}
            err := survey.AskOne(prompt, &passConfirm)
            if err != nil {
                log.Fatal(err)
            }
            if password == passConfirm {
                var inp string
                if !noHash {
                    fmt.Printf("Print SHA-256 of password or save with salt to file? ([y]es|[s]ave|[n]o)\n>")
                    fmt.Scan(&inp)
                    inp = strings.ToLower(inp)
                    if inp == "y" || inp == "yes" || inp == "ys" || inp == "sy" {
                        fmt.Println(passSha)
                    }
                    if inp == "s" || inp == "save" || inp == "ys" || inp == "sy" {
                        passFile, err = os.OpenFile(".password.sha256", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
                        if err != nil {
                            log.Fatal(err)
                        }
                        defer passFile.Close()
                        if _, err = passFile.WriteString(saltedPassSha + " " + hex.EncodeToString(salt) + "\n"); err != nil {
                            log.Fatal(err)
                        } else {
                            color.Green(fmt.Sprintf("SHA-256 of password with salt saved to %s", filepath.Join(path, ".password.sha256!")))
                        }
                    }
                }
                break
            } else {
                color.Yellow("Passwords didnt match!")
                continue
            }
        }
        break
    }
    return password
}


func FileLoop(files []string, mode string, password string, genSalt bool) {
    var key []byte
    var errors []string
    var errorsMutex sync.Mutex
    var wg sync.WaitGroup
    key = GenKey(password, genSalt, mode)
    bar := progressbar.Default(int64(len(files)))
    fmt.Printf("\n")
    semaphore := make(chan struct{}, cpuThreads)
    if mode == "e" {
        for _, file := range files {
            wg.Add(1)
            semaphore <- struct{}{}
            go func(file string) {
                defer func() {
                    <-semaphore
                    wg.Done()
                }()

                color.Yellow("Encrypting %s...\n", file)
                err := EncryptFile(key, file)
                if err != nil {
                    errorsMutex.Lock()
                    color.Red(fmt.Sprintf("%s: %v\n", file, err))
                    errors = append(errors, fmt.Sprintf("%s: %v", file, err))
                    errorsMutex.Unlock()
                } else {
                    color.Green("Encrypted %s!\n", file)
                }
                bar.Add(1)
                fmt.Printf("\n")
            }(file)
        }
    }

    if mode == "d" {
        for _, file := range files {
            wg.Add(1)
            semaphore <- struct{}{}
            go func(file string) {
                defer func() {
                    <-semaphore
                    wg.Done()
                }()

                color.Yellow("Decrypting %s...\n", file)
                err := DecryptFile(key, file)
                if err != nil {
                    errorsMutex.Lock()
                    color.Red(fmt.Sprintf("%s: %v\n", file, err))
                    errors = append(errors, fmt.Sprintf("%s: %v", file, err))
                    errorsMutex.Unlock()
                } else {
                    color.Green("Decrypted %s!\n", file)
                }
                bar.Add(1)
                fmt.Printf("\n")
            }(file)
        }
    }
    wg.Wait()

    if 0 < len(errors) {
        if verbose {fmt.Println("Writing errors to .dencrypt.errors...")}
        file, _ := os.Create(".dencrypt.errors")
        defer file.Close()

        writer := bufio.NewWriter(file)
        for _, item := range errors {
            _, _ = writer.WriteString(item + "\n")
        }
        err = writer.Flush()
        if verbose {
            if err != nil {
                fmt.Println("Couldnt write errors to .dencrypt.errors: ", err)
            } else {
                fmt.Println("Wrote errors to .dencrypt.errors !")
            }
        }
    } else if _, err = os.Stat(".dencrypt.errors"); err == nil {
        os.Remove(".dencrypt.errors")
        if verbose {fmt.Println("Deleted .dencrypt.errors !")}
    }

    modeMsg := "encrypted"
    if mode == "d" {
        modeMsg = "decrypted"
    }

    fmt.Printf("%s %d out of %d files.\n", strings.Title(modeMsg), len(files) - len(errors), len(files))
}


func Contains(s []string, str string) bool {
    for _, i := range s {
        if i == str {
            return true
        }
    }
    return false
}

func hasAnySuffix(s string, suffixes ...string) bool {
	for _, suffix := range suffixes {
		if strings.HasSuffix(strings.ToLower(s), suffix) {
			return true
		}
	}
	return false
}

func IsRegularFile(path string) bool {
    info, err := os.Stat(path)
    if err != nil {
        return false
    }
    return !info.IsDir()
}

func filter(input []string, condition func(string) bool) []string {
	var result []string
	for _, item := range input {
		if condition(item) {
			result = append(result, item)
		}
	}
	return result
}

func GenKey(password string, gensalt bool, mode string) []byte {
    var saltFile string
    var err error
    var inp string

    if homeSalt {
        saltFile, err = os.UserHomeDir()
        if err != nil {
            log.Fatal(err)
        }
        saltFile = filepath.Join(saltFile, ".salt")
    } else if saltArg != "" {
        saltFile = saltArg
    } else {
        saltFile = ".salt"
    }
    if verbose && !useHcs {fmt.Println("Using salt from", saltFile)} else if verbose && useHcs {fmt.Println("Using hard-coded salt.")}
    var salt []byte
    if useHcs {
        salt = []byte("1234567890123456")
    } else {
        if gensalt || b64salt {
            if verbose {fmt.Println("Generating new salt.")}
            salt = make([]byte, 16)
            _, err = rand.Read(salt)
            if err != nil {
                log.Fatal(err)
            }
            if !b64salt {
                err = ioutil.WriteFile(saltFile, salt, 0644)
                if err != nil {
                    log.Fatal(err)
                }
            }
        } else if !b64salt {
            salt, err = ioutil.ReadFile(saltFile)
            if err != nil {
                log.Fatal(err)
            }
        }
    }
    if b64salt {
        if mode == "e" {
            fmt.Printf("\nBase64 encoded salt: ")
            color.Cyan(fmt.Sprintf("%s\n\n", base64.URLEncoding.EncodeToString(salt)))
            fmt.Print("To continue, enter ")
            color.Cyan("base64 encoded salt")
            fmt.Print(">")
            for {
                fmt.Scan(&inp)
                if inp == base64.URLEncoding.EncodeToString(salt) {
                    break
                }
                fmt.Printf("Incorrect salt! Try again.\n>")
            }
        } else if mode == "d" {
            if bsSalt == "" {
                fmt.Print("\nEnter ")
                color.Cyan("base64 encoded salt")
                fmt.Print(">")
                fmt.Scan(&inp)
                bsSalt = inp
            }
            salt, err = base64.URLEncoding.DecodeString(bsSalt)
            if err != nil {
                log.Fatal(err)
            }
        }
    }
    var its int
    if us {its = 96} else {its = 64}
    var mem int
    if us {mem = 512*1024} else {mem = 128*1024}
    color.Yellow("Generating key...")
    kst := time.Now()
    key := argon2.Key([]byte(password), salt, uint32(its), uint32(mem), 4, 32)
    color.Green("Key generated in %.2fs.", math.Round(time.Since(kst).Seconds()*1000) / 1000)
    return key
}

func EncryptFilename(key []byte, iv []byte, str string) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    paddedPlaintext := pkcs7pad.Pad([]byte(str), aes.BlockSize)

    ciphertext := make([]byte, aes.BlockSize+len(paddedPlaintext))
    copy(ciphertext[:aes.BlockSize], iv)

    stream := cipher.NewCFBEncrypter(block, iv)
    stream.XORKeyStream(ciphertext[aes.BlockSize:], paddedPlaintext)

    return ciphertext, nil
}

func DecryptFilename(key []byte, ciphertext []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil,err
    }

    if len(ciphertext) < aes.BlockSize {
        if verbose {fmt.Println("Ciphertext block size is too short!")}
        return nil, err
    }

    iv := make([]byte, 4, 16)
    copy(iv, ciphertext[:4])
    iv = append(iv, make([]byte, 12)...)
    ciphertext = ciphertext[4:]

    stream := cipher.NewCFBDecrypter(block, iv)
    stream.XORKeyStream(ciphertext, ciphertext)

    ciphertext, err = pkcs7pad.Unpad(ciphertext)
    if err != nil {
        return nil, err
    }
    return ciphertext, nil
}

func getFileModTime(file string) (time.Time, error) {
    fileData, err := os.Stat(file)
    if err != nil {
        return time.Time{}, err
    }

    return fileData.ModTime(), nil
}

func modifyFileModTime(file string, newTime time.Time) error {
    err = os.Chtimes(file, newTime, newTime)
    if err != nil {
        return err
    }

    return nil
}

func encrypt(key, plaintext []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return []byte{}, err
    }

    paddedPlaintext := pkcs7pad.Pad(plaintext, aes.BlockSize)

    ciphertext := make([]byte, aes.BlockSize+len(paddedPlaintext))

    iv := ciphertext[:aes.BlockSize]
    if _, err := io.ReadFull(rand.Reader, iv); err != nil {
        return []byte{}, err
    }

    stream := cipher.NewCFBEncrypter(block, iv)
    stream.XORKeyStream(ciphertext[aes.BlockSize:], paddedPlaintext)

    return ciphertext, nil
}

func decrypt(key, ciphertext []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return []byte{}, err
    }

    if len(ciphertext) < aes.BlockSize {
        return []byte{}, errors.New("Ciphertext block size is too short!")
    }

    iv := ciphertext[:aes.BlockSize]
    ciphertext = ciphertext[aes.BlockSize:]

    stream := cipher.NewCFBDecrypter(block, iv)
    stream.XORKeyStream(ciphertext, ciphertext)

    plaintext, err := pkcs7pad.Unpad(ciphertext)
    if err != nil {
        return []byte{}, errors.New(fmt.Sprintf("Wrong encryption key: %v", err))
    }

    return plaintext, nil
}

func gzipCompress(data []byte) []byte {
    var cf bytes.Buffer
    gw := gzip.NewWriter(&cf)
    gw.Write(data)
    gw.Close()

    return cf.Bytes()
}
