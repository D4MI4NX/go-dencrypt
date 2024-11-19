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
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"os"
)

type FileProperties struct {
	MajorVersion      int    `json:"version_major"`
	MinorVersion      int    `json:"version_minor"`
	PatchVersion      int    `json:"version_patch"`
	VersionNumber     string `json:"version_number"`
	Salt              string `json:"salt"`
	SaltType          string `json:"salt_type"`
	EncryptedFilename bool   `json:"filename_encrypted"`
	GzipCompressed    bool   `json:"gzip_compressed"`
}

func ParseEncryptedFile(path string) (FileProperties, error) {
	var properties FileProperties

	file, err := os.Open(path)
	if err != nil {
		return properties, err
	}

	reader := bufio.NewReader(file)

	firstLine, err := reader.ReadBytes('\n')
	if err != nil {
		return properties, err
	}

	splitFirstLine := bytes.SplitN(firstLine, []byte(";"), 2)
	if len(splitFirstLine) != 2 {
		return properties, errors.New("wrong format")
	}

	jsonData := splitFirstLine[1]

	err = json.Unmarshal(jsonData, &properties)
	return properties, err
}

func EncodeFileProperties(properties FileProperties) ([]byte, error) {
	return json.Marshal(properties)
}
