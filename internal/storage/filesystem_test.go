package storage

import (
	"io"
	"os"
	"strings"
	"testing"
)

func TestFSWriteOpenDelete(t *testing.T) {
	root := t.TempDir()
	fs, err := NewFS(root)
	if err != nil {
		t.Fatalf("failed to create FS: %v", err)
	}

	key := "abcdef1234567890abcdef1234567890"
	content := "encrypted blob content"

	err = fs.Write(key, strings.NewReader(content))
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	rc, err := fs.Open(key)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() {
		_ = rc.Close()
	}()

	data, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}
	if string(data) != content {
		t.Errorf("expected %q, got %q", content, string(data))
	}

	// Test Delete (idempotent)
	if err := fs.Delete(key); err != nil {
		t.Errorf("Delete failed: %v", err)
	}
	if err := fs.Delete(key); err != nil {
		t.Errorf("Delete missing file failed (should be idempotent): %v", err)
	}

	_, err = fs.Open(key)
	if !os.IsNotExist(err) {
		t.Errorf("expected ErrNotExist after delete, got %v", err)
	}
}

func TestFSPathTraversalDefense(t *testing.T) {
	root := t.TempDir()
	fs, err := NewFS(root)
	if err != nil {
		t.Fatalf("failed to create FS: %v", err)
	}

	badKeys := []string{
		"../escape",
		"foo/bar",
		"foo\\bar",
		".hidden",
		"",
	}

	for _, k := range badKeys {
		if err := fs.Write(k, strings.NewReader("data")); err == nil {
			t.Errorf("expected error for bad key %q, got nil", k)
		}
		if _, err := fs.Open(k); err == nil {
			t.Errorf("expected error for bad key %q, got nil", k)
		}
		if err := fs.Delete(k); err == nil {
			t.Errorf("expected error for bad key %q, got nil", k)
		}
	}
}
