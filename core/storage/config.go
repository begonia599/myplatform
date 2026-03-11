package storage

// StorageConfig holds configuration for the file storage subsystem.
type StorageConfig struct {
	Type        string      `yaml:"type"`          // "local" or "s3"
	MaxFileSize int64       `yaml:"max_file_size"` // bytes
	Local       LocalConfig `yaml:"local"`
	S3          S3Config    `yaml:"s3"`
}

// LocalConfig configures the local filesystem backend.
type LocalConfig struct {
	BasePath string `yaml:"base_path"`
}

// S3Config configures an S3-compatible object storage backend.
type S3Config struct {
	Bucket    string `yaml:"bucket"`
	Region    string `yaml:"region"`
	Endpoint  string `yaml:"endpoint"`   // for MinIO or other S3-compatible services
	AccessKey string `yaml:"access_key"`
	SecretKey string `yaml:"secret_key"`
	UseSSL    bool   `yaml:"use_ssl"`
}

// ApplyDefaults sets sensible defaults for unset fields.
func (c *StorageConfig) ApplyDefaults() {
	if c.Type == "" {
		c.Type = "local"
	}
	if c.MaxFileSize == 0 {
		c.MaxFileSize = 50 * 1024 * 1024 // 50 MB
	}
	if c.Local.BasePath == "" {
		c.Local.BasePath = "./uploads"
	}
}
