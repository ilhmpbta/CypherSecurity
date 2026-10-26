package config

import (
	"fmt"
	"net/url"
	"os"
)

type Config struct {
	DatabaseURL      string
	HTTPAddr         string
	KEKBase64        string
	SessionSecret    string
	MaxJSONBodyBytes int64
	MaxUploadBytes   int64
	SecureCookies    bool
}

// Load reads configuration from the environment.
func Load() (*Config, error) {
	cfg := &Config{
		DatabaseURL:      os.Getenv("DATABASE_URL"),
		HTTPAddr:         os.Getenv("HTTP_ADDR"),
		KEKBase64:        os.Getenv("CYPHER_KEK"),
		SessionSecret:    os.Getenv("SESSION_SECRET"),
		MaxJSONBodyBytes: 1 << 20,  // 1 MB default
		MaxUploadBytes:   32 << 20, // 32 MB default
		SecureCookies:    os.Getenv("CYPHER_SECURE_COOKIES") != "false",
	}

	if cfg.HTTPAddr == "" {
		cfg.HTTPAddr = ":8080"
	}

	if cfg.DatabaseURL == "" {
		u, err := buildDatabaseURL()
		if err != nil {
			return nil, err
		}
		cfg.DatabaseURL = u
	}

	return cfg, nil
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
