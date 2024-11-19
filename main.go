/* go-dencrypt is a tool for file encryption and decryption. It uses AES encryption with CGM mode and Argon2 key derivation function for secure encryption.

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
	"bytes"
	"crypto/sha512"
	_ "embed"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/schollz/progressbar/v3"
	"gopkg.in/yaml.v3"
)

const (
	ToolName     = "go-dencrypt"
	MajorVersion = 3
	MinorVersion = 3
	PatchVersion = 0
)

var (
	VersionNumber = strconv.Itoa(MajorVersion) + "." + strconv.Itoa(MinorVersion) + "." + strconv.Itoa(PatchVersion)
	Version       = ToolName + " " + VersionNumber
	IgnoredFiles  = []string{
		filepath.Base(os.Args[0]),
		"dencrypt.go",
		"go.mod",
		"go.sum",
		"magic.go",
		"main.go",

		"dencrypt_test.go",

		"Makefile",

		"LICENSE",
		"README.md",

		"default-config.yaml",
		"license-info.txt",

		".dencrypt.config.yaml",
		".dencrypt.errors.txt",

		"dencrypt",
		"dencrypt.exe",
		"dencrypt_linux_amd64",
		"dencrypt_linux_arm64",
		"dencrypt_windows_amd64.exe",
		"dencrypt_windows_arm64.exe",
	}

	//go:embed license-info.txt
	License string

	//go:embed default-config.yaml
	defaultConfig string
)

type Options struct {
	Files struct {
		Found     []string
		Selected  []string
		Plaintext []string
		Encrypted []string
	}
	Force              bool     `yaml:"force"`
	Mode               string   `yaml:"mode"`
	RecursiveDepth     int      `yaml:"recursiveDepth"`
	SelectedPaths      []string `yaml:"selectedFiles"`
	ExecutableDir      bool     `yaml:"executableDir"`
	Verbose            bool     `yaml:"verbose"`
	ExcludedPaths      string   `yaml:"exclude"`
	ShowLicenseAndExit bool
	ShowVersionAndExit bool
	Path               string `yaml:"path"`
	Password           string `yaml:"password"`
	NoFileTree         bool   `yaml:"noFileTree"`
	IncludeHiddenFiles bool   `yaml:"includeHiddenFiles"`
	IncludeBackupFiles bool   `yaml:"includeBackupFiles"`
	FollowLinks        bool   `yaml:"followLinks"`
	NoColor            bool   `yaml:"noColor"`

	EncryptFilename bool   `yaml:"encryptFilename"`
	KeepInputFiles  bool   `yaml:"keepInputFiles"`
	ShredInputFiles bool   `yaml:"shredInputFiles"`
	UseGzip         bool   `yaml:"useGzip"`
	SaltFile        string `yaml:"saltFile"`
}

func main() {
	options := parseConfig()
	options = parseFlags(options)

	var err error

	if options.SaltFile != "" {
		IgnoredFiles = append(IgnoredFiles, options.SaltFile)
		if _, err = os.Stat(options.SaltFile); err != nil {
			color.Red("Coudlnt find salt file: " + err.Error())
			os.Exit(1)
		}
	}

	if options.ShowVersionAndExit {
		fmt.Println(Version)
		return
	}

	if options.ShowLicenseAndExit {
		fmt.Println(License)
		return
	}

	options.Mode = strings.ToLower(options.Mode)

	err = decidePath(&options)
	if err != nil {
		fmt.Println(err)
	}

	vprintln(options.Verbose, "Using path:", options.Path)

	if options.ExcludedPaths != "" {
		IgnoredFiles = append(IgnoredFiles, GetFilesFromPattern(options.ExcludedPaths)...)
	}

	vprintln(options.Verbose, "Excluded files:", IgnoredFiles)

	for _, path := range options.SelectedPaths {
		options.Files.Found = append(options.Files.Found, GetFilesFromPattern(filepath.Clean(path))...)
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
	keyStore := make(map[string][]byte)
	var encSalt []byte
	var err error

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
		func() {
			defer bar.Add(1)

			var salt []byte
			var fileErr error
			var properties FileProperties

			readSaltFile := func(f string) ([]byte, error) {
				saltFileContent, err := ioutil.ReadFile(f)
				if err != nil {
					return []byte{}, errors.New("Couldnt read salt file: " + err.Error())
				}

				sha512Hash := sha512.Sum512(saltFileContent)

				return append([]byte{}, sha512Hash[:]...), nil
			}

			if options.Mode == "e" {
				properties.MajorVersion = MajorVersion
				properties.MinorVersion = MinorVersion
				properties.PatchVersion = PatchVersion
				properties.VersionNumber = VersionNumber
				if options.SaltFile != "" {
					salt, err = readSaltFile(options.SaltFile)
					if err != nil {
						color.Red(err.Error())
						return
					}

					properties.Salt = options.SaltFile
					properties.SaltType = "file"
				} else {
					salt = encSalt
					properties.Salt = base64.URLEncoding.EncodeToString(salt)
					properties.SaltType = "b64"
				}
			} else if options.Mode == "d" {
				fileErr = func() error {
					properties, err = ParseEncryptedFile(file)
					if err != nil {
						return err
					}

					switch properties.SaltType {
					case "file":
						salt, err = readSaltFile(properties.Salt)
					default:
						salt, err = base64.URLEncoding.DecodeString(properties.Salt)
					}

					return err
				}()
				if fileErr != nil {
					color.Red(fileErr.Error())
					return
				}
			}

			id := GetID(salt)

			if _, exists := keyStore[string(salt)]; !exists {
				color.Yellow(fmt.Sprintf("Generating key %s...\n", id))
				t0 := time.Now()
				keyStore[string(salt)] = GenerateKey(options.Password, salt)
				color.Green("Key %s generated in %.2fs.", id, math.Round(time.Since(t0).Seconds()*1000)/1000)
			}

			color.Yellow("%s %s...\n", statusPending, file)
			fileErr = processFile(file, options, properties, keyStore[string(salt)])
			if fileErr != nil {
				fileErr = fmt.Errorf("%s: %v", file, fileErr)
				color.Red(fileErr.Error())
				fileErrors = append(fileErrors, fileErr.Error())
			} else {
				color.Green("%s %s!\n", statusFinished, file)
			}
		}()
	}

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

	total := len(options.Files.Selected)
	amntErrors := len(fileErrors)
	amntSuccessful := total - amntErrors

	fmt.Printf("%s %d / %d files ",
		statusFinished,
		amntSuccessful,
		total,
	)

	percentage := amntSuccessful * 100 / total

	percentageMsg := fmt.Sprint("(" + strconv.Itoa(percentage) + "%)")

	if len(fileErrors) == 0 {
		color.Green(percentageMsg)
	} else if amntErrors == total {
		color.Red(percentageMsg)
	} else {
		color.Yellow(percentageMsg)
	}

	return nil
}

func processFile(file string, options Options, properties FileProperties, key []byte) error {
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
			properties.GzipCompressed = true
			vprintf(options.Verbose, "Compressed %s.\n", file)
		} else {
			modifiedContent = content
		}

		ciphertext, err := Encrypt(key, modifiedContent)
		if err != nil {
			return err
		}

		if options.EncryptFilename {
			filename, err = EncryptFilename(file, key)
			if err != nil {
				filename = name
				vprintln(options.Verbose, err)
			} else {
				properties.EncryptedFilename = true
			}
		}

		newFilename = NewFilename(filename)

		encodedProperties, err := EncodeFileProperties(properties)
		if err != nil {
			return err
		}

		encodedProperties = append([]byte(ToolName+";"), encodedProperties...)
		ciphertext = append([]byte("\n"), ciphertext...)
		newContent = append([]byte(encodedProperties), ciphertext...)
	} else if options.Mode == "d" {
		if properties.MajorVersion != MajorVersion {
			return fmt.Errorf("version missmatch: Tool is %s, file is %s", VersionNumber, properties.VersionNumber)
		}

		ciphertext = bytes.SplitN(content, []byte("\n"), 2)[1]

		plaintext, err := Decrypt(key, ciphertext)
		if err != nil {
			return err
		}

		if properties.GzipCompressed {
			options.UseGzip = true

			vprintf(options.Verbose, "Decompressing %s...\n", file)

			plaintext, err = GzipDecompress(plaintext)
			if err != nil {
				return err
			}

			vprintf(options.Verbose, "Decompressed %s.\n", file)
		}

		if properties.EncryptedFilename {
			filename, err = DecryptFilename(file, key)
			if err != nil {
				color.Magenta(fmt.Sprintf("%s: Couldnt decrypt filename: %v\n", file, err))
				filename = file
			}
		}

		newFilename, err = RestoreFilename(filename)
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
		if IsEncryptedWithMagic(file) {
			options.Files.Encrypted = append(options.Files.Encrypted, file)
		} else {
			options.Files.Plaintext = append(options.Files.Plaintext, file)
		}
	}
}

func filterFiles(files []string, options Options) []string {
	var newFiles []string

	for _, file := range files {
		linkTarget, err := os.Readlink(file)
		if err == nil && options.FollowLinks && IsRegularFile(linkTarget) {
			newFiles = append(newFiles, linkTarget)
		} else {
			newFiles = append(newFiles, file)
		}
	}

	newFiles = Filter(newFiles, func(file string) bool {
		return !Contains(IgnoredFiles, file) &&
			!Contains(IgnoredFiles, filepath.Base(file)) &&
			!(!options.IncludeHiddenFiles && strings.HasPrefix(filepath.Base(file), ".")) &&
			!(!options.IncludeBackupFiles && HasAnySuffix(file, "~", ".bak")) &&
			!IsLink(file)
	})

	slices.Sort(newFiles)

	return slices.Compact(newFiles)
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
	flag.BoolVar(&color.NoColor, "nc", options.NoColor,
		"Disable color output")
	flag.BoolVar(&options.KeepInputFiles, "k", options.KeepInputFiles,
		"Keep input file(s)")
	flag.BoolVar(&options.ShredInputFiles, "si", options.ShredInputFiles,
		"Shred the input file(s) before deletion")
	flag.BoolVar(&options.EncryptFilename, "fn", options.EncryptFilename,
		"En/Decrypt the filename")
	flag.StringVar(&options.ExcludedPaths, "e", options.ExcludedPaths,
		"Exclude one or multiple files (comma separated) or with shell patterns")
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
	flag.BoolVar(&options.FollowLinks, "l", options.FollowLinks,
		"Follow links")
	flag.StringVar(&options.SaltFile, "sf", options.SaltFile,
		"Specify file to generate salt from")
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

	if value, _ := strconv.ParseBool(os.Getenv("IGNORE_CONFIG")); !value {
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

func IsInvalidFilename(filename string) bool {
	return filename == ""
}

func IsEncryptedWithMagic(file string) bool {
	if !IsEncrypted(filepath.Base(file)) {
		return false
	}

	data, _ := ReadFirstXByte(file, len(ToolName))

	return string(data) == ToolName
}

func checkFileConflicts(files []string, options Options) []string {
	var newFilename string
	var confirmation, all, none bool
	var newFiles []string

	for _, file := range files {
		if options.Mode == "e" {
			newFilename = NewFilename(file)
		} else if options.Mode == "d" {
			newFilename, _ = RestoreFilename(file)
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
