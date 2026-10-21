package config

// Config holds runtime configuration loaded from the environment.
type Config struct{}

// Load reads configuration from the environment.
func Load() (*Config, error) {
	return &Config{}, nil
}
