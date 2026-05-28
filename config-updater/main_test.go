package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCopyConfigCopiesNestedFiles(t *testing.T) {
	sourceRoot := filepath.Join(t.TempDir(), "source")
	targetRoot := filepath.Join(t.TempDir(), "target")

	sourceFile := filepath.Join(sourceRoot, "nested", "config.yml")
	if err := os.MkdirAll(filepath.Dir(sourceFile), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sourceFile, []byte("key: value\n"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := copyConfig(sourceRoot, targetRoot); err != nil {
		t.Fatal(err)
	}

	targetFile := filepath.Join(targetRoot, "nested", "config.yml")
	data, err := os.ReadFile(targetFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "key: value\n" {
		t.Fatalf("unexpected copied content: %q", data)
	}
}

func TestCopyConfigReturnsTargetErrors(t *testing.T) {
	sourceRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(sourceRoot, "config.yml"), []byte("key: value\n"), 0644); err != nil {
		t.Fatal(err)
	}

	targetRoot := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(targetRoot, []byte("not a directory\n"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := copyConfig(sourceRoot, targetRoot); err == nil {
		t.Fatal("expected copyConfig to return an error")
	}
}
