package storage

import (
	"os"
	"path/filepath"
)

// AtomicWrite calls write(tmpPath) with the path of a temp file in the same
// directory as finalPath, then fsyncs and renames atomically. On error, the
// temp file is removed.
func AtomicWrite(finalPath string, write func(tmpPath string) error) error {
	dir := filepath.Dir(finalPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	tmpFile, err := os.CreateTemp(dir, "atomic-*")
	if err != nil {
		return err
	}
	tmpPath := tmpFile.Name()

	success := false
	defer func() {
		_ = tmpFile.Close()
		if !success {
			_ = os.Remove(tmpPath)
		}
	}()

	if err := write(tmpPath); err != nil {
		return err
	}

	if err := tmpFile.Sync(); err != nil {
		return err
	}

	if err := tmpFile.Close(); err != nil {
		return err
	}

	if err := os.Rename(tmpPath, finalPath); err != nil {
		return err
	}

	success = true
	return nil
}
