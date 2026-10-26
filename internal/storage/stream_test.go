package storage

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAtomicWriteSuccess(t *testing.T) {
	dir := t.TempDir()
	finalPath := filepath.Join(dir, "test.blob")

	err := AtomicWrite(finalPath, func(tmpPath string) error {
		return os.WriteFile(tmpPath, []byte("hello atomic"), 0600)
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, err := os.ReadFile(finalPath)
	if err != nil {
		t.Fatalf("failed to read final file: %v", err)
	}
	if string(data) != "hello atomic" {
		t.Errorf("expected 'hello atomic', got %q", string(data))
	}
}

func TestAtomicWriteErrorCleanup(t *testing.T) {
	dir := t.TempDir()
	finalPath := filepath.Join(dir, "test.blob")

	err := AtomicWrite(finalPath, func(tmpPath string) error {
		_ = os.WriteFile(tmpPath, []byte("partial"), 0600)
		return os.ErrClosed
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if _, err := os.Stat(finalPath); !os.IsNotExist(err) {
		t.Errorf("expected final path not to exist, got err: %v", err)
	}

	// Verify no temp files remain in dir
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("failed to read dir: %v", err)
	}
	if len(entries) > 0 {
		t.Errorf("expected 0 files in dir, found %d", len(entries))
	}
}
