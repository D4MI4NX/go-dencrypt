/* go-dencrypt is a tool for file encryption and decryption. It uses AES encryption with CFB mode and Argon2 key derivation function for secure encryption.

Copyright (C) 2023-2024  D4MI4NX

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
    "crypto/sha512"
    "encoding/hex"
    "errors"
    "fmt"
    "flag"
    "github.com/fatih/color"
    "github.com/schollz/progressbar/v3"
    "gopkg.in/yaml.v3"
    "io/ioutil"
    "math"
    "os"
    "path/filepath"
    "runtime"
    "strings"
    "sync"
    "time"
)

var (
    IgnoredFiles = []string{
        filepath.Base(os.Args[0]),
        "main.go",
        "dencrypt.go",
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
        ".dencrypt.config.yaml",
        ".dencrypt.errors.txt",
    }
)

const (
    Version = "go-dencrypt 2.0.10"

    License = `go-dencrypt is a tool for file encryption and decryption. It uses AES encryption with CFB mode and Argon2 key derivation function for secure encryption.

Copyright (C) 2023-2024  D4MI4NX

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation version 3.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>`

    defaultConfig = `maxConcurrency: 0           # CPU threads to use for concurrent en/decryption (-1: all, -2: half...). (default 0 (half available threads))
encryptFilename: false      # En/Decrypt filename. (default false)
exclude: ""                 # Specify file(s) to exclude. Example: "text.txt,image.png,*.zip". (default "")
executableDir: false        # Use path the executable is stored in. (default false)
selectedFiles: []           # Specify file(s) to use exclusively. (default [])
force: false                # Dont ask for confirmation. (default false)
includeBackupFiles: false   # Make backup files (*~,*.bak) selectable. (default false)
includeHiddenFiles: false   # Make hidden files (.*) selectable (default false)
keepInputFiles: false       # Keep the input files. (default false)
mode: ""                    # Specify the mode to use. "e" for encrypt and "d" for decrypt. (default "")
noColor: false              # Disable color. (default false)
noFileTree: false           # Display the files under each over instead of a tree view. (default false)
password: ""                # Specify password to use. Not recommended. (default "")
path: ""                    # Specify path to use. (default "")
recursiveDepth: 0           # Specify the depth of recursive traversal. (default 0 (unlimited))
shredInputFiles: false      # Shred (overwrite the input files multiple times) before deletion. (default false)
useGzip: false              # (De)Compress input files using gzip. (default false)
verbose: false              # Print more information. (default false)`
)

type Options struct {
    Files struct {
        Found                   []string
        Selected                []string
        Plaintext               []string
        Encrypted               []string
    }
    Force                   bool        `yaml:"force"`
    Mode                    string      `yaml:"mode"`
    RecursiveDepth          int         `yaml:"recursiveDepth"`
    SelectedPaths           []string    `yaml:"selectedFiles"`
    ExecutableDir           bool        `yaml:"executableDir"`
    Verbose                 bool        `yaml:"verbose"`
    MaxConcurrency          int         `yaml:"maxConcurrency"`
    ExcludedPaths           string      `yaml:"exclude"`
    ShowLicenseAndExit      bool
    ShowVersionAndExit      bool
    Path                    string      `yaml:"path"`
    Password                string      `yaml:"password"`
    NoFileTree              bool        `yaml:"noFileTree"`
    IncludeHiddenFiles      bool        `yaml:"includeHiddenFiles"`
    IncludeBackupFiles      bool        `yaml:"includeBackupFiles"`
    NoColor                 bool        `yaml:"noColor"`

    EncryptFilename         bool        `yaml:"encryptFilename"`
    KeepInputFiles          bool        `yaml:"keepInputFiles"`
    ShredInputFiles         bool        `yaml:"shredInputFiles"`
    UseGzip                 bool        `yaml:"useGzip"`
}


func main() {
    options := parseConfig()
    options = parseFlags(options)

    if options.ShowVersionAndExit {
        fmt.Println(Version)
        return
    }

    if options.ShowLicenseAndExit {
        fmt.Println(License)
        return
    }

    vprintln(options.Verbose, "Amount of available cpu threads:", runtime.NumCPU())

    options.MaxConcurrency = decideMaxConcurrency(options.MaxConcurrency)

    vprintf(options.Verbose, "Using %d threads.\n", options.MaxConcurrency)

    options.Mode = strings.ToLower(options.Mode)

    err := decidePath(&options)
    if err != nil {
        fmt.Println(err)
    }

    vprintln(options.Verbose, "Using path:", options.Path)

    if options.ExcludedPaths != "" {
        IgnoredFiles = append(IgnoredFiles, GetFilesFromDirectory(options.ExcludedPaths)...)
    }

    vprintln(options.Verbose, "Excluded files:", IgnoredFiles)

    for _, path := range options.SelectedPaths {
        options.Files.Found = append(options.Files.Found, GetFilesFromDirectory(filepath.Clean(path))...)
    }

    options.Files.Found = filterFiles(options.Files.Found, options)

    options.Files.Found = FilterFilesByDepth(options.Files.Found, options.RecursiveDepth)

    splitPlaintextAndEncryptedFiles(&options)

    if len(append(options.Files.Plaintext, options.Files.Encrypted...)) == 0 {
        color.Red("No files found!")
        return
    }

    decideMode(&options)

    if options.Mode == "e" {
        options.Files.Selected = options.Files.Plaintext
    } else if options.Mode == "d" {
        options.Files.Selected = options.Files.Encrypted
    }

    if !options.Force {
        options.Files.Selected = checkFileConflicts(options.Files.Selected, options)
    }

    if options.NoFileTree {
        fmt.Println(strings.Join(options.Files.Selected, "\n"))
    } else {
        PrintTree(BuildTree(options.Files.Selected), "", true)
    }

    fmt.Printf("\n")

    if options.Password == "" {
        password, err := PromptPassword(true)
        if err != nil {
            color.Red(err.Error())
            return
        } else {
            options.Password = password
        }
    }

    passwordID := GetID([]byte(options.Password))
    fmt.Printf("Password ID: %s\n", color.CyanString(passwordID))

    if value := promptConfirmation(options); !value {
        return
    }

    if err := processSelectedFiles(options); err != nil {
        color.Red(err.Error())
        return
    }
}

func processSelectedFiles(options Options) error {
    var fileErrors []string
    var wg sync.WaitGroup
    keyStore := make(map[string][]byte)
    var keyGenerationMutex sync.Mutex
    var saltInProgress []byte
    var encSalt []byte
    var err error

    semaphore := make(chan struct{}, options.MaxConcurrency)

    statusPending := "Decrypting"
    statusFinished := "Decrypted"

    if options.Mode == "e" {
        statusPending = "Encrypting"
        statusFinished = "Encrypted"

        if 0 < len(options.Files.Encrypted) {
            encSalt, err = ReadFirstXByte(options.Files.Encrypted[0], 16)
        }

        if encSalt == nil {
            encSalt, err = GenerateSalt(16)
            if err != nil {
                return err
            }
        }
    }

    bar := progressbar.Default(int64(len(options.Files.Selected)))
    fmt.Printf("\n")

    for _, file := range options.Files.Selected {
        wg.Add(1)
        semaphore <- struct{}{}
        go func(file string) {
            defer func() {
                <-semaphore
                bar.Add(1)
                wg.Done()
                fmt.Printf("\n")
            }()

            var salt []byte
            var fileErr error
            var pendingSalt []byte

            if options.Mode == "e" {
                salt = encSalt
            } else if options.Mode == "d" {
                salt, fileErr = ReadFirstXByte(file, 16)
                if fileErr != nil {
                    color.Red(fileErr.Error())
                    return
                }
            }

            id := GetID(salt)

            if  _, exists := keyStore[string(salt)]; !exists {
                color.Yellow(fmt.Sprintf("%s waiting for key %s...\n", file, id))
                pendingSalt = saltInProgress
                keyGenerationMutex.Lock()

                if string(saltInProgress) != string(salt) && string(salt) != string(pendingSalt) {
                    saltInProgress = salt

                    color.Yellow(fmt.Sprintf("Generating key %s...\n", id))
                    t0 := time.Now()
                    keyStore[string(salt)] = GenerateKey(options.Password, salt)
                    color.Green("Key %s generated in %.2fs.", id, math.Round(time.Since(t0).Seconds()*1000) / 1000)
                }

                keyGenerationMutex.Unlock()
            }

            color.Yellow("%s %s...\n", statusPending, file)
            fileErr = processFile(file, options, keyStore[string(salt)], salt)
            if fileErr != nil {
                fileErr = errors.New(fmt.Sprintf("%s: %v\n", file, fileErr))
                color.Red(fileErr.Error())
                fileErrors = append(fileErrors, fileErr.Error())
            } else {
                color.Green("%s %s!\n", statusFinished, file)
            }
        }(file)
    }

    wg.Wait()

    errorFile := ".dencrypt.errors.txt"

    if 0 < len(fileErrors) {
        err := ioutil.WriteFile(errorFile, []byte(strings.Join(fileErrors, "")), 0644)
        if err != nil {
            fmt.Println(err)
        }

        vprintf(options.Verbose, "Wrote errors to %s\n", errorFile)
    } else if _, err = os.Stat(errorFile); err == nil {
        os.Remove(errorFile)
        vprintf(options.Verbose, "Removed %s\n", errorFile)
    }

    fmt.Printf("%s %d / %d files ",
      statusFinished,
      len(options.Files.Selected) - len(fileErrors),
      len(options.Files.Selected),
    )

    percentage := "(" + fmt.Sprint(
      (len(options.Files.Selected) - len(fileErrors)) * 100 / len(options.Files.Selected),
    ) + "%)"

    if len(fileErrors) == 0 {
        color.Green(percentage)
    } else if len(fileErrors) == len(options.Files.Selected) {
        color.Red(percentage)
    } else {
        color.Yellow(percentage)
    }

    return nil
}

func processFile(file string, options Options, key, salt []byte) error {
    var newFilename string
    var filename string
    var newContent []byte
    var ciphertext []byte

    content, err := ioutil.ReadFile(file)
    if err != nil {
        return err
    }

    fileModTime, err := GetFileModTime(file)
    if err != nil && options.Verbose {
        fmt.Println(err)
    }

    ext := filepath.Ext(file)
    name := strings.TrimSuffix(file, ext)
    filename = file

    if options.Mode == "e" {
        var modifiedContent []byte

        if options.UseGzip && !strings.HasSuffix(file, ".gz") {
            vprintf(options.Verbose, "Compressing %s...\n", file)
            modifiedContent = GzipCompress(content)
            vprintf(options.Verbose, "Compressed %s.\n", file)
        } else {
            modifiedContent = content
        }

        ciphertext, err := Encrypt(key, modifiedContent)
        if err != nil {
            return err
        }

        if options.EncryptFilename {
            if _, err := hex.DecodeString(name); err != nil {
                sha512Hash := sha512.Sum512(content)

                filename, err = EncryptFilename(file, append([]byte{}, sha512Hash[:]...))
                if err != nil {
                    filename = name

                    vprintln(options.Verbose, err)
                }
            }
        }

        newFilename = encNewFilename(filename, options)

        newContent = append(salt, ciphertext...)
    } else if options.Mode == "d" {
        ciphertext = content[16:]

        plaintext, err := Decrypt(key, ciphertext)
        if err != nil {
            return err
        }

        if options.UseGzip && strings.HasSuffix(file, ".gz") ||
          (FilenameIsHex(file) && options.EncryptFilename && strings.HasSuffix(file, ".gz")) {
            options.UseGzip = true

            vprintf(options.Verbose, "Decompressing %s...\n", file)

            plaintext, err = GzipDecompress(plaintext)
            if err != nil {
                return err
            }

            vprintf(options.Verbose, "Decompressed %s.\n", file)
        }

        if options.EncryptFilename {
            sha512Hash := sha512.Sum512(plaintext)

            filename, err = DecryptFilename(file, append([]byte{}, sha512Hash[:]...))
            if err != nil {
                color.Magenta(fmt.Sprintf("%s: Couldnt decrypt filename: %v\n", file, err))
                filename = file
            }
        }

        newFilename, err = decRestoreFilename(filename, options)
        if err != nil {
            return err
        }

        newContent = plaintext
    }

    vprintf(options.Verbose, "Writing new content to %s...\n", newFilename)

    err = ioutil.WriteFile(newFilename, newContent, 0644)
    if err != nil {
        return err
    }

    vprintf(options.Verbose, "Wrote new content to %s.\n", newFilename)

    if !fileModTime.IsZero() {
        err = ModifyFileModTime(newFilename, fileModTime)
        if options.Verbose {
            if err != nil {
                fmt.Println(err)
            } else {
                fmt.Printf("Modified time on %s.\n", newFilename)
            }
        }
    }

    if !options.KeepInputFiles {
        if options.ShredInputFiles {
            vprintf(options.Verbose, "Shredding %s...\n", file)
            ShredFile(file)
            vprintf(options.Verbose, "Shredded %s.\n", file)
        }

        vprintf(options.Verbose, "Deleting %s...\n", file)

        err = os.Remove(file)
        if err != nil {
            return err
        }

        vprintf(options.Verbose, "Deleted %s.\n", file)
    }

    return nil
}

func promptConfirmation(options Options) bool {
    var inp string

    if options.Force {
        return true
    }

    mode := "Encrypt"
    if options.Mode == "d" {
        mode = "Decrypt"
    }

    fmt.Printf("%s %d files? ([y]es|[n]o)\n>", mode, len(options.Files.Selected))

    fmt.Scan(&inp)

    if strings.ToLower(inp) != "y" && strings.ToLower(inp) != "yes" {
        fmt.Println("[cancelled]")
        return false
    }

    return true
}

func decideMode(options *Options) {
    if 0 < len(options.Files.Plaintext) && len(options.Files.Encrypted) == 0 {
        options.Mode = "e"
    } else if len(options.Files.Plaintext) == 0 && 0 < len(options.Files.Encrypted) {
        options.Mode = "d"
    } else {
        if isModeInvalid(options.Mode) || options.Mode == "" {
            for {
                fmt.Print("[E]ncrypt or [D]ecrypt?\n>")
                fmt.Scan(&options.Mode)
                options.Mode = strings.ToLower(options.Mode)

                if isModeInvalid(options.Mode) {
                    color.Yellow(fmt.Sprintf("Mode %s not found!", options.Mode))
                    continue
                }

                break
            }
        }
    }
}

func splitPlaintextAndEncryptedFiles(options *Options) {
    for _, file := range options.Files.Found {
        if IsEncrypted(file) {
            options.Files.Encrypted = append(options.Files.Encrypted, file)
        } else {
            options.Files.Plaintext = append(options.Files.Plaintext, file)
        }
    }
}


func filterFiles(files []string, options Options) []string {
    files = Filter(files, func(file string) bool {
        return !Contains(IgnoredFiles, file) &&
          !Contains(IgnoredFiles, filepath.Base(file)) &&
          !(!options.IncludeHiddenFiles && strings.HasPrefix(filepath.Base(file), ".")) &&
          !(!options.IncludeBackupFiles && HasAnySuffix(file, "~", ".bak"))
    })

    return files
}

func decidePath(options *Options) error {
    var err error
    var executable string

    if options.Path != "." {
        if err = os.Chdir(options.Path); err != nil {
            return err
        }
    } else if (!options.ExecutableDir && runtime.GOOS == "windows") || (options.ExecutableDir && runtime.GOOS != "windows") {
        if executable, err = os.Executable(); err != nil {
            return err
        }
        if options.Path, err = filepath.Abs(filepath.Dir(executable)); err != nil {
            return err
        }

        os.Chdir(options.Path)
    } else {
        if options.Path, err = os.Getwd(); err != nil {
            return err
        }
    }

    return nil
}

func isModeInvalid(mode string) bool {
    return mode != "e" && mode != "d" && mode != ""
}

func decideMaxConcurrency(preferred int) int {
    var concurrency int
    availableThreads := runtime.NumCPU()

    if preferred < 0 || availableThreads < preferred || preferred == 0 {
        concurrency = int(math.Round(float64(availableThreads) / 2))
        if preferred < 0 {
            concurrency = int(math.Round(float64(availableThreads) / (float64(preferred) * -1)))
            if concurrency < 1 {
                concurrency = 1
            }
        } else if availableThreads < preferred {
            color.Yellow(fmt.Sprintf("Cannot use more than %d concurrent goroutines. Using %d.", availableThreads, concurrency))
        }
    } else {
        concurrency = preferred
    }

    return concurrency
}

func parseFlags(options Options) Options {
    if options.Path == "" {
        options.Path = "."
    }

    flag.StringVar(&options.Mode, "m", options.Mode,
      "Select mode (Encrypt: e  Decrypt: d)")
    flag.BoolVar(&options.Force, "f", options.Force,
      "Dont ask for confirmation")
    flag.BoolVar(&options.ExecutableDir, "ed", options.ExecutableDir,
      "Use the directory the executable is stored in (reversed on windows)")
    flag.BoolVar(&options.Verbose, "v", options.Verbose,
      "Print more information")
    flag.BoolVar(&options.UseGzip, "gz", options.UseGzip,
      "Use gzip compression for files")
    flag.IntVar(&options.MaxConcurrency, "gr", options.MaxConcurrency,
      "Specify the number of concurrent files to en/decrypt")
    flag.BoolVar(&color.NoColor, "nc", options.NoColor,
      "Disable color output")
    flag.BoolVar(&options.KeepInputFiles, "k", options.KeepInputFiles,
      "Keep input file(s)")
    flag.BoolVar(&options.ShredInputFiles, "si", options.ShredInputFiles,
      "Shred the input file(s) before deletion")
    flag.BoolVar(&options.EncryptFilename, "fn", options.EncryptFilename,
      "En/Decrypt the filename")
    flag.StringVar(&options.ExcludedPaths, "e", options.ExcludedPaths,
      "Exclude one or multiple files (comma separated) or with wildcard pattern (*)")
    flag.BoolVar(&options.ShowLicenseAndExit, "L", options.ShowLicenseAndExit,
      "Print license information and exit")
    flag.IntVar(&options.RecursiveDepth, "rd", options.RecursiveDepth,
      "Specify the depth of the recursive traversal")
    flag.StringVar(&options.Path, "p", options.Path,
      "Specify path to use")
    flag.StringVar(&options.Password, "P", options.Password,
      "Specify password")
    flag.BoolVar(&options.ShowVersionAndExit, "V", options.ShowVersionAndExit,
      "Print version and exit")
    flag.BoolVar(&options.NoFileTree, "nt", options.NoFileTree,
      "Disable file tree view")
    flag.BoolVar(&options.IncludeHiddenFiles, "H", options.IncludeHiddenFiles,
      "Include hidden files (.*)")
    flag.BoolVar(&options.IncludeBackupFiles, "b", options.IncludeBackupFiles,
      "Include backup files (*~,*.bak)")
    flag.Parse()

    options.SelectedPaths = append(options.SelectedPaths, flag.Args()...)

    if len(options.SelectedPaths) == 0 {
        options.SelectedPaths = []string{"."}
    }

	return options
}

func parseConfig() Options {
    var err error

    configFile := os.Getenv("CONFIG_FILE")

    if configFile == "" {
        configFile = ".dencrypt.config.yaml"
    } else {
        IgnoredFiles = append(IgnoredFiles, configFile)
    }

    if !IsTrue(os.Getenv("IGNORE_CONFIG")) {
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
                return Options{}
            } else {
                return config
            }
        }
    }

    return Options{}
}

func readConfig(path string) (Options, error) {
    data, err := ioutil.ReadFile(path)
    if err != nil {
        return Options{}, err
    }

    var config Options
    err = yaml.Unmarshal(data, &config)
    if err != nil {
        return Options{}, err
    }

    return config, nil
}

func encNewFilename(filename string, options Options) string {
    base := filepath.Base(filename)
    path := strings.TrimSuffix(filename, base)

    var newFilename string

    if strings.Count(base, ".") == 1 && strings.HasPrefix(base, ".") {
        newFilename = base + ".enc"
    } else {
        ext := filepath.Ext(base)
        newFilename = strings.TrimSuffix(base, ext) + ".enc" + ext
    }

    if options.UseGzip && !strings.HasSuffix(filename, ".gz") {
        newFilename += ".gz"
    }

    return filepath.Join(path, newFilename)
}

func decRestoreFilename(filename string, options Options) (string, error) {
    base := filepath.Base(filename)
    path := strings.TrimSuffix(filename, base)

    if options.UseGzip {
        base = strings.TrimSuffix(base, ".gz")
    }

    base = strings.Replace(base, ".enc", "", 1)

    restoredFilename := filepath.Join(path, base)

    if restoredFilename == filename || IsInvalidFilename(restoredFilename) {
        return restoredFilename, errors.New("Could not choose new filename")
    }

    return restoredFilename, nil
}

func IsInvalidFilename(filename string) bool {
    return filename == ""
}

func checkFileConflicts(files []string, options Options) []string {
    var newFilename string
    var confirmation, all, none bool
    var newFiles []string

    for _, file := range files {
        if options.Mode == "e" {
            newFilename = encNewFilename(file, options)
        } else if options.Mode == "d" {
            newFilename, _ = decRestoreFilename(file, options)
        }

        if options.Force || all {
            confirmation = true
        } else if !all && !none {
            confirmation, all, none = ConfirmOverwrite(newFilename, true, true)
        } else if none {
            confirmation = false
        }

        if confirmation {
            newFiles = append(newFiles, file)
        }
    }

    if len(newFiles) == 0 {
        color.Red("No files left!")
        os.Exit(0)
    }

    return newFiles
}

func vprintf(verbose bool, format string, a ...any) {
    if verbose {
        fmt.Printf(format, a...)
    }
}

func vprintln(verbose bool, a ...any) {
    if verbose {
        fmt.Println(a...)
    }
}
