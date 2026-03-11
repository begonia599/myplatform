package permission

// PermissionConfig holds configuration for the permission module.
type PermissionConfig struct {
	SeedDefaults bool `yaml:"seed_defaults"`
}

// ApplyDefaults fills in zero-value fields with sensible defaults.
func (cfg *PermissionConfig) ApplyDefaults() {
	// No additional defaults needed at this time.
}
