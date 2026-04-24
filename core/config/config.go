package config

import (
	"os"

	"github.com/begonia599/myplatform/core/auth"
	"github.com/begonia599/myplatform/core/database"
	"github.com/begonia599/myplatform/core/imagebed"
	"github.com/begonia599/myplatform/core/permission"
	"github.com/begonia599/myplatform/core/storage"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Server     ServerConfig                `yaml:"server"`
	Database   database.DatabaseConfig     `yaml:"database"`
	Auth       auth.AuthConfig             `yaml:"auth"`
	Permission permission.PermissionConfig `yaml:"permission"`
	Storage    storage.StorageConfig       `yaml:"storage"`
	ImageBed   imagebed.ImageBedConfig     `yaml:"imagebed"`
}

type ServerConfig struct {
	Port int    `yaml:"port"`
	Mode string `yaml:"mode"`
}

// Load reads a YAML config file and returns the parsed Config with defaults applied.
// Environment variables override sensitive config values.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	// Server defaults
	if cfg.Server.Port == 0 {
		cfg.Server.Port = 8080
	}
	if cfg.Server.Mode == "" {
		cfg.Server.Mode = "debug"
	}

	// Database defaults
	cfg.Database.ApplyDefaults()

	// Auth defaults
	cfg.Auth.ApplyDefaults()

	// Permission defaults
	cfg.Permission.ApplyDefaults()

	// Storage defaults
	cfg.Storage.ApplyDefaults()

	// ImageBed defaults
	cfg.ImageBed.ApplyDefaults()

	// Environment variable overrides (for sensitive fields)
	applyEnvOverrides(&cfg)

	return &cfg, nil
}

// applyEnvOverrides overrides config values with environment variables when set.
func applyEnvOverrides(cfg *Config) {
	if v := os.Getenv("MYPLATFORM_AUTH_JWT_SECRET"); v != "" {
		cfg.Auth.JWTSecret = v
	}
	if v := os.Getenv("MYPLATFORM_AUTH_OAUTH_GITHUB_CLIENT_ID"); v != "" {
		cfg.Auth.OAuth.GitHub.ClientID = v
	}
	if v := os.Getenv("MYPLATFORM_AUTH_OAUTH_GITHUB_CLIENT_SECRET"); v != "" {
		cfg.Auth.OAuth.GitHub.ClientSecret = v
	}
	if v := os.Getenv("MYPLATFORM_AUTH_OAUTH_GITHUB_REDIRECT_URL"); v != "" {
		cfg.Auth.OAuth.GitHub.RedirectURL = v
	}
	if v := os.Getenv("MYPLATFORM_AUTH_OAUTH_DISCORD_CLIENT_ID"); v != "" {
		cfg.Auth.OAuth.Discord.ClientID = v
	}
	if v := os.Getenv("MYPLATFORM_AUTH_OAUTH_DISCORD_CLIENT_SECRET"); v != "" {
		cfg.Auth.OAuth.Discord.ClientSecret = v
	}
	if v := os.Getenv("MYPLATFORM_AUTH_OAUTH_DISCORD_REDIRECT_URL"); v != "" {
		cfg.Auth.OAuth.Discord.RedirectURL = v
	}
	if v := os.Getenv("MYPLATFORM_DB_HOST"); v != "" {
		cfg.Database.Host = v
	}
	if v := os.Getenv("MYPLATFORM_DB_PASSWORD"); v != "" {
		cfg.Database.Password = v
	}
}
