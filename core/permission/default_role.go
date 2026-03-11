package permission

import (
	"fmt"

	"gorm.io/gorm"
)

// DefaultRolePolicy defines a permission policy that is automatically applied
// to new users upon registration. Managed by admins to control what
// permissions newly registered users receive by default.
type DefaultRolePolicy struct {
	ID     uint   `gorm:"primaryKey" json:"id"`
	Role   string `gorm:"size:32;not null;uniqueIndex:idx_default_policy" json:"role"`
	Object string `gorm:"size:128;not null;uniqueIndex:idx_default_policy" json:"object"` // e.g. "blog.comment"
	Action string `gorm:"size:64;not null;uniqueIndex:idx_default_policy" json:"action"`
}

// SetDefaultRolePolicies replaces all default policies for a given role.
// This is a full replacement — old defaults for this role are deleted first.
func (s *PermissionService) SetDefaultRolePolicies(db *gorm.DB, role string, policies []DefaultRolePolicy) error {
	return db.Transaction(func(tx *gorm.DB) error {
		// Remove existing defaults for this role
		if err := tx.Where("role = ?", role).Delete(&DefaultRolePolicy{}).Error; err != nil {
			return fmt.Errorf("permission: clear default policies for %s: %w", role, err)
		}

		// Insert new defaults
		for i := range policies {
			policies[i].ID = 0 // ensure auto-increment
			policies[i].Role = role
		}
		if len(policies) > 0 {
			if err := tx.Create(&policies).Error; err != nil {
				return fmt.Errorf("permission: set default policies for %s: %w", role, err)
			}
		}
		return nil
	})
}

// GetDefaultRolePolicies returns the default policies configured for a role.
func (s *PermissionService) GetDefaultRolePolicies(db *gorm.DB, role string) ([]DefaultRolePolicy, error) {
	var policies []DefaultRolePolicy
	err := db.Where("role = ?", role).Find(&policies).Error
	if err != nil {
		return nil, fmt.Errorf("permission: get default policies: %w", err)
	}
	return policies, nil
}

// ApplyDefaultPolicies applies the default policies for a role to a specific user.
// Called during user registration to automatically grant initial permissions.
func (s *PermissionService) ApplyDefaultPolicies(db *gorm.DB, userID uint, role string) error {
	defaults, err := s.GetDefaultRolePolicies(db, role)
	if err != nil {
		return err
	}

	for _, d := range defaults {
		// Add Casbin policy: the user's role grants access to object/action
		if _, err := s.enforcer.AddPolicy(d.Role, d.Object, d.Action); err != nil {
			return fmt.Errorf("permission: apply default policy %s/%s/%s: %w",
				d.Role, d.Object, d.Action, err)
		}
	}

	// Ensure the user is assigned to this role in Casbin
	if _, err := s.AssignUserRole(userID, role); err != nil {
		return fmt.Errorf("permission: assign role %s to user %d: %w", role, userID, err)
	}

	return nil
}
