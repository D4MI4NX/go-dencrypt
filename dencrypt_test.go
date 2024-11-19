package main

import (
	"slices"
	"strings"
	"testing"
)

var (
	plaintextFilenames = []string{
		"test",
		"test.txt",
		"test.png.txt",
		".test",
		".test.txt",
		".test.png.txt",
	}
	encryptedFilenames = []string{
		"test.enc",
		"test.enc.txt",
		"test.png.enc.txt",
		".test.enc",
		".test.enc.txt",
		".test.png.enc.txt",
	}
)

func TestContains(t *testing.T) {
	value1 := "apple"
	value2 := "dragonfruit"

	slice := []string{value1, "banana", "cherry"}

	if !Contains(slice, value1) {
		t.Fatalf("%v contains %s", slice, value1)
	}

	if Contains(slice, value2) {
		t.Fatalf("%v does not contain %s", slice, value2)
	}
}

func TestHasAnySuffix(t *testing.T) {
	suffix := ".enc"
	value := "test" + suffix

	if !HasAnySuffix(value, suffix) {
		t.Fatalf("%s has suffix %s", value, suffix)
	}

	wrongSuffix := ".plt"

	if HasAnySuffix(value, wrongSuffix) {
		t.Fatalf("%s does not have suffix %s", value, wrongSuffix)
	}
}

func TestFilter(t *testing.T) {
	slice := []string{"apple", "banana", "cherry"}

	filteredSlice := Filter(slice, func(s string) bool {
		return !strings.Contains(s, "a")
	})

	if !slices.Equal(filteredSlice, []string{"cherry"}) {
		t.Fatalf("%s should only contain cherry", filteredSlice)
	}
}

func TestIsEncrypted(t *testing.T) {
	for _, filename := range encryptedFilenames {
		if !IsEncrypted(filename) {
			t.Fatalf("%s is encrypted", filename)
		}
	}

	for _, filename := range plaintextFilenames {
		if IsEncrypted(filename) {
			t.Fatalf("%s is not encrypted", filename)
		}
	}
}

func TestNewFilename(t *testing.T) {
	for i, filename := range plaintextFilenames {
		expectedFilename := encryptedFilenames[i]
		fn := NewFilename(filename)
		if fn != expectedFilename {
			t.Fatalf("%s should be %s, got %s", filename, expectedFilename, fn)
		}
	}
}

func TestRestoreFilename(t *testing.T) {
	for i, filename := range encryptedFilenames {
		expectedFilename := plaintextFilenames[i]
		fn, err := RestoreFilename(filename)
		if fn != expectedFilename {
			t.Fatalf("%s should be %s, got %s: %s", filename, expectedFilename, fn, err.Error())
		}
	}
}
