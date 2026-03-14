package imagebed

// ImageBedConfig holds configuration for the image hosting subsystem.
type ImageBedConfig struct {
	MaxFileSize int64  `yaml:"max_file_size"` // bytes, default 10MB
	BasePath    string `yaml:"base_path"`     // sub-path within storage backend
}

// ApplyDefaults sets sensible defaults for unset fields.
func (c *ImageBedConfig) ApplyDefaults() {
	if c.MaxFileSize == 0 {
		c.MaxFileSize = 10 * 1024 * 1024 // 10 MB
	}
	if c.BasePath == "" {
		c.BasePath = "imagebed"
	}
}
