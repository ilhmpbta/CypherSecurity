package config

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func TestLoadConfig(t *testing.T) {
	valid32Bytes := make([]byte, 32)
	validKEK := base64.StdEncoding.EncodeToString(valid32Bytes)

	t.Run("valid baseline config with env", func(t *testing.T) {
		t.Setenv("CYPHER_KEK", validKEK)
		t.Setenv("DATABASE_URL", "postgres://user:pass@localhost:5432/db?sslmode=disable")
		t.Setenv("SESSION_IDLE_TIMEOUT", "30m")
		t.Setenv("SESSION_ABS_TIMEOUT", "8h")
		t.Setenv("MAX_UPLOAD_BYTES", "1048576")

		cfg, err := Load()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.KEKBase64 != validKEK {
			t.Errorf("expected KEK %s, got %s", validKEK, cfg.KEKBase64)
		}
		if len(cfg.KEKBytes) != 32 {
			t.Errorf("expected KEKBytes length 32, got %d", len(cfg.KEKBytes))
		}
		if cfg.SessionIdleTimeout != 30*time.Minute {
			t.Errorf("expected idle timeout 30m, got %v", cfg.SessionIdleTimeout)
		}
		if cfg.SessionAbsTimeout != 8*time.Hour {
			t.Errorf("expected abs timeout 8h, got %v", cfg.SessionAbsTimeout)
		}
		if cfg.MaxUploadBytes != 1048576 {
			t.Errorf("expected max upload bytes 1048576, got %d", cfg.MaxUploadBytes)
		}
	})

	t.Run("missing CYPHER_KEK", func(t *testing.T) {
		t.Setenv("CYPHER_KEK", "")
		t.Setenv("DATABASE_URL", "postgres://user:pass@localhost:5432/db?sslmode=disable")

		_, err := Load()
		if err == nil || err.Error() != "CYPHER_KEK: missing" {
			t.Fatalf("expected missing KEK error, got: %v", err)
		}
	})

	t.Run("invalid base64 KEK", func(t *testing.T) {
		t.Setenv("CYPHER_KEK", "not-base64!@@#")
		t.Setenv("DATABASE_URL", "postgres://user:pass@localhost:5432/db?sslmode=disable")

		_, err := Load()
		if err == nil || !strings.Contains(err.Error(), "CYPHER_KEK: not valid base64") {
			t.Fatalf("expected bad base64 error, got: %v", err)
		}
	})

	t.Run("wrong KEK byte length", func(t *testing.T) {
		shortKEK := base64.StdEncoding.EncodeToString([]byte("too-short"))
		t.Setenv("CYPHER_KEK", shortKEK)
		t.Setenv("DATABASE_URL", "postgres://user:pass@localhost:5432/db?sslmode=disable")

		_, err := Load()
		if err == nil || !strings.Contains(err.Error(), "CYPHER_KEK: must be exactly 32 bytes") {
			t.Fatalf("expected wrong length error, got: %v", err)
		}
	})

	t.Run("negative timeout", func(t *testing.T) {
		t.Setenv("CYPHER_KEK", validKEK)
		t.Setenv("DATABASE_URL", "postgres://user:pass@localhost:5432/db?sslmode=disable")
		t.Setenv("SESSION_IDLE_TIMEOUT", "-10m")

		_, err := Load()
		if err == nil || !strings.Contains(err.Error(), "SESSION_IDLE_TIMEOUT") {
			t.Fatalf("expected negative timeout error, got: %v", err)
		}
	})

	t.Run("zero max upload bytes", func(t *testing.T) {
		t.Setenv("CYPHER_KEK", validKEK)
		t.Setenv("DATABASE_URL", "postgres://user:pass@localhost:5432/db?sslmode=disable")
		t.Setenv("MAX_UPLOAD_BYTES", "0")

		_, err := Load()
		if err == nil || !strings.Contains(err.Error(), "MAX_UPLOAD_BYTES") {
			t.Fatalf("expected invalid upload bytes error, got: %v", err)
		}
	})

	t.Run("fallback aliases PORT and STORAGE_DIR", func(t *testing.T) {
		t.Setenv("HTTP_ADDR", "")
		t.Setenv("CYPHER_STORAGE_ROOT", "")
		t.Setenv("CYPHER_KEK", validKEK)
		t.Setenv("DATABASE_URL", "postgres://user:pass@localhost:5432/db?sslmode=disable")
		t.Setenv("PORT", "9000")
		t.Setenv("STORAGE_DIR", "/custom/storage")

		cfg, err := Load()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.HTTPAddr != ":9000" {
			t.Errorf("expected HTTPAddr :9000, got %s", cfg.HTTPAddr)
		}
		if cfg.StorageRoot != "/custom/storage" {
			t.Errorf("expected StorageRoot /custom/storage, got %s", cfg.StorageRoot)
		}
	})
}
