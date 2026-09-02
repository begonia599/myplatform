package permission

// PermissionConfig holds configuration for the permission module.
type PermissionConfig struct {
	SeedDefaults bool `yaml:"seed_defaults"`

	// ServiceToken, when non-empty, must be presented as X-Service-Token on
	// the service-to-service endpoints (POST /api/permissions/registry and
	// POST /api/permissions/check). Empty disables the check.
	ServiceToken string `yaml:"service_token"`
}

// ApplyDefaults fills in zero-value fields with sensible defaults.
func (cfg *PermissionConfig) ApplyDefaults() {
	// No additional defaults needed at this time.
}
