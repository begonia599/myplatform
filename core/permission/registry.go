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

// RegisterPermissions idempotently registers permission definitions for a module.
// Existing entries are not duplicated; new ones are inserted.
// Automatically creates Casbin policies for admin and user roles.
func (s *PermissionService) RegisterPermissions(db *gorm.DB, module string, defs []ResourceDef) (int, error) {
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

			// Auto-seed Casbin policies: admin and user get all permissions by default
			s.enforcer.AddPolicy("admin", def.Resource, action)
			s.enforcer.AddPolicy("user", def.Resource, action)
		}
	}
	return created, nil
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
