package config

import (
	"os"

	"github.com/begonia599/myplatform/core/auth"
	"github.com/begonia599/myplatform/core/database"
	"github.com/begonia599/myplatform/core/permission"
	"github.com/begonia599/myplatform/core/storage"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Server   ServerConfig            `yaml:"server"`
	Database database.DatabaseConfig `yaml:"database"`
	Auth       auth.AuthConfig             `yaml:"auth"`
	Permission permission.PermissionConfig `yaml:"permission"`
	Storage    storage.StorageConfig          `yaml:"storage"`
}

type ServerConfig struct {
	Port int    `yaml:"port"`
	Mode string `yaml:"mode"`
}

// Load reads a YAML config file and returns the parsed Config with defaults applied.
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

	return &cfg, nil
}
