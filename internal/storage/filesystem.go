package storage

import (
	"io"
	"os"
	"path/filepath"
	"strings"
)

type FS struct {
	root string
}

func NewFS(root string) (*FS, error) {
	if root == "" {
		root = "data/storage"
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return nil, err
	}
	return &FS{root: root}, nil
}

func validateKey(key string) error {
	if key == "" || strings.Contains(key, "/") || strings.Contains(key, "\\") || strings.Contains(key, "..") || strings.HasPrefix(key, ".") {
		return os.ErrPermission
	}
	return nil
}

// Write streams r into a temp file under root, fsyncs, atomically renames to key.
func (f *FS) Write(key string, r io.Reader) error {
	if err := validateKey(key); err != nil {
		return err
	}
	finalPath := filepath.Join(f.root, key)
	return AtomicWrite(finalPath, func(tmpPath string) error {
		out, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, r); err != nil {
			_ = out.Close()
			return err
		}
		if err := out.Sync(); err != nil {
			_ = out.Close()
			return err
		}
		return out.Close()
	})
}

// Open returns a reader over the stored blob at key.
func (f *FS) Open(key string) (io.ReadCloser, error) {
	if err := validateKey(key); err != nil {
		return nil, err
	}
	finalPath := filepath.Join(f.root, key)
	return os.Open(finalPath)
}

// Delete removes the blob at key. Idempotent (returns nil if missing).
func (f *FS) Delete(key string) error {
	if err := validateKey(key); err != nil {
		return err
	}
	finalPath := filepath.Join(f.root, key)
	err := os.Remove(finalPath)
	if err != nil && os.IsNotExist(err) {
		return nil
	}
	return err
}
