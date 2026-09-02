package permission

import (
	"fmt"
	"time"

	"gorm.io/gorm"
)

// PermissionDefinition stores a registered permission entry from a business module.
// Uses a {module}.{resource} namespace to avoid conflicts across modules.
type PermissionDefinition struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	Module      string    `gorm:"size:64;not null;uniqueIndex:idx_perm_def" json:"module"`
	Resource    string    `gorm:"size:64;not null;uniqueIndex:idx_perm_def" json:"resource"`
	Action      string    `gorm:"size:64;not null;uniqueIndex:idx_perm_def" json:"action"`
	Description string    `gorm:"size:255" json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// ResourceDef is the input format for registering permissions.
type ResourceDef struct {
	Resource    string   `json:"resource" binding:"required"`
	Actions     []string `json:"actions" binding:"required"`
	Description string   `json:"description"`
}

// RoleGrant declares a default role→permission policy a module wants seeded at
// registration. The object is namespaced to {module}.{resource} so it matches
// how business modules check permissions (e.g. "blog.comment"). Idempotent.
type RoleGrant struct {
	Role     string `json:"role"`
	Resource string `json:"resource"`
	Action   string `json:"action"`
}

// RegisterPermissions idempotently registers permission definitions for a module.
// Existing entries are not duplicated; new ones are inserted.
//
// Registration itself grants nothing. Admins are superusers (see
// CheckPermission) and need no policies; every other role only receives what
// the module declares in grants. This used to auto-seed "{resource}/{action}"
// policies for admin AND user for every registered action — which meant any
// caller of the (service-to-service) registry endpoint could hand the user
// role arbitrary platform permissions such as storage/delete just by naming
// the resource. That behaviour was removed.
//
// grants optionally declare default role→permission policies for this module,
// seeded with a {module}.{resource} object (matching how business modules
// check), so non-admin roles work on a fresh database without manual
// assignment. Idempotent.
func (s *PermissionService) RegisterPermissions(db *gorm.DB, module string, defs []ResourceDef, grants []RoleGrant) (int, error) {
	created := 0
	for _, def := range defs {
		for _, action := range def.Actions {
			pd := PermissionDefinition{
				Module:      module,
				Resource:    def.Resource,
				Action:      action,
				Description: def.Description,
			}
			result := db.Where("module = ? AND resource = ? AND action = ?",
				module, def.Resource, action).FirstOrCreate(&pd)
			if result.Error != nil {
				return created, fmt.Errorf("permission: register %s.%s/%s: %w",
					module, def.Resource, action, result.Error)
			}
			if result.RowsAffected > 0 {
				created++
			}
		}
	}

	s.seedGrants(module, grants)
	return created, nil
}

// seedGrants writes the declared default role grants using the namespaced
// object so they match how business modules check (e.g. "blog.comment").
// Idempotent — AddPolicy is a no-op if the rule already exists. Grants can
// only ever touch objects under "{module}." so a module cannot reach into the
// platform's own objects (storage, imagebed, …) or another module's.
func (s *PermissionService) seedGrants(module string, grants []RoleGrant) {
	for _, g := range grants {
		if g.Role == "" || g.Resource == "" || g.Action == "" {
			continue
		}
		s.enforcer.AddPolicy(g.Role, module+"."+g.Resource, g.Action)
	}
}

// ListRegisteredModules returns a deduplicated list of all registered module names.
func (s *PermissionService) ListRegisteredModules(db *gorm.DB) ([]string, error) {
	var modules []string
	err := db.Model(&PermissionDefinition{}).Distinct("module").Pluck("module", &modules).Error
	if err != nil {
		return nil, fmt.Errorf("permission: list modules: %w", err)
	}
	return modules, nil
}

// ListModulePermissions returns all permission definitions for a given module.
func (s *PermissionService) ListModulePermissions(db *gorm.DB, module string) ([]PermissionDefinition, error) {
	var defs []PermissionDefinition
	err := db.Where("module = ?", module).Order("resource, action").Find(&defs).Error
	if err != nil {
		return nil, fmt.Errorf("permission: list module permissions: %w", err)
	}
	return defs, nil
}

// ListAllPermissions returns all registered permission definitions across all modules.
func (s *PermissionService) ListAllPermissions(db *gorm.DB) ([]PermissionDefinition, error) {
	var defs []PermissionDefinition
	err := db.Order("module, resource, action").Find(&defs).Error
	if err != nil {
		return nil, fmt.Errorf("permission: list all permissions: %w", err)
	}
	return defs, nil
}
