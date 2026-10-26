package config

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"
)

type Config struct {
	DatabaseURL        string
	HTTPAddr           string
	KEKBase64          string
	KEKBytes           []byte
	MaxJSONBodyBytes   int64
	MaxUploadBytes     int64
	SecureCookies      bool
	StorageRoot        string
	SessionIdleTimeout time.Duration
	SessionAbsTimeout  time.Duration
}

// Load reads configuration from the environment and validates it eagerly.
func Load() (*Config, error) {
	httpAddr := os.Getenv("HTTP_ADDR")
	if httpAddr == "" {
		if port := os.Getenv("PORT"); port != "" {
			if strings.HasPrefix(port, ":") {
				httpAddr = port
			} else {
				httpAddr = ":" + port
			}
		} else {
			httpAddr = ":8080"
		}
	}

	storageRoot := os.Getenv("CYPHER_STORAGE_ROOT")
	if storageRoot == "" {
		storageRoot = os.Getenv("STORAGE_DIR")
	}
	if storageRoot == "" {
		storageRoot = "data/storage"
	}

	kekBase64 := os.Getenv("CYPHER_KEK")
	if kekBase64 == "" {
		return nil, fmt.Errorf("CYPHER_KEK: missing")
	}

	// Decode KEK: accept both standard and raw std encoding
	kekBytes, err := base64.StdEncoding.DecodeString(kekBase64)
	if err != nil {
		kekBytes, err = base64.RawStdEncoding.DecodeString(kekBase64)
		if err != nil {
			return nil, fmt.Errorf("CYPHER_KEK: not valid base64: %w", err)
		}
	}
	if len(kekBytes) != 32 {
		return nil, fmt.Errorf("CYPHER_KEK: must be exactly 32 bytes after base64 decode, got %d", len(kekBytes))
	}

	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		u, err := buildDatabaseURL()
		if err != nil {
			return nil, err
		}
		databaseURL = u
	}
	if databaseURL == "" {
		return nil, fmt.Errorf("DATABASE_URL: missing")
	}

	maxUploadBytes := int64(32 << 20) // 32 MB default
	if val := os.Getenv("MAX_UPLOAD_BYTES"); val != "" {
		var b int64
		if _, err := fmt.Sscanf(val, "%d", &b); err != nil || b <= 0 {
			return nil, fmt.Errorf("MAX_UPLOAD_BYTES: invalid value: %s", val)
		}
		maxUploadBytes = b
	}
	if maxUploadBytes <= 0 {
		return nil, fmt.Errorf("MAX_UPLOAD_BYTES: must be greater than zero")
	}

	// Parse optional session timeouts (deferred wiring pending 003_session_idle.sql)
	var sessionIdleTimeout, sessionAbsTimeout time.Duration
	if val := os.Getenv("SESSION_IDLE_TIMEOUT"); val != "" {
		d, err := time.ParseDuration(val)
		if err != nil || d <= 0 {
			return nil, fmt.Errorf("SESSION_IDLE_TIMEOUT: invalid duration %q: %w", val, err)
		}
		sessionIdleTimeout = d
	}
	if val := os.Getenv("SESSION_ABS_TIMEOUT"); val != "" {
		d, err := time.ParseDuration(val)
		if err != nil || d <= 0 {
			return nil, fmt.Errorf("SESSION_ABS_TIMEOUT: invalid duration %q: %w", val, err)
		}
		sessionAbsTimeout = d
	}

	secureCookies := os.Getenv("CYPHER_SECURE_COOKIES") != "false"

	return &Config{
		DatabaseURL:        databaseURL,
		HTTPAddr:           httpAddr,
		KEKBase64:          kekBase64,
		KEKBytes:           kekBytes,
		MaxJSONBodyBytes:   1 << 20, // 1 MB default
		MaxUploadBytes:     maxUploadBytes,
		SecureCookies:      secureCookies,
		StorageRoot:        storageRoot,
		SessionIdleTimeout: sessionIdleTimeout,
		SessionAbsTimeout:  sessionAbsTimeout,
	}, nil
}

func buildDatabaseURL() (string, error) {
	user := os.Getenv("POSTGRES_USER")
	pass := os.Getenv("POSTGRES_PASSWORD")
	db := os.Getenv("POSTGRES_DB")
	host := os.Getenv("POSTGRES_HOST")
	port := os.Getenv("POSTGRES_PORT")

	if user == "" || db == "" {
		return "", fmt.Errorf(
			"DATABASE_URL not set, and POSTGRES_USER / POSTGRES_DB are missing too")
	}

	u := &url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(user, pass),
		Host:   host + ":" + port,
		Path:   "/" + db,
	}
	q := u.Query()
	q.Set("sslmode", "disable")
	u.RawQuery = q.Encode()
	return u.String(), nil
}
