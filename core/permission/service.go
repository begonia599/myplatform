package permission

import (
	"fmt"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	gormadapter "github.com/casbin/gorm-adapter/v3"
	"gorm.io/gorm"
)

// PermissionService wraps a Casbin SyncedEnforcer for thread-safe permission checks.
type PermissionService struct {
	enforcer *casbin.SyncedEnforcer
	cfg      *PermissionConfig
}

// New creates a PermissionService backed by the given GORM database.
func New(cfg *PermissionConfig, db *gorm.DB) (*PermissionService, error) {
	adapter, err := gormadapter.NewAdapterByDB(db)
	if err != nil {
		return nil, fmt.Errorf("permission: failed to create adapter: %w", err)
	}

	m, err := model.NewModelFromString(casbinModel)
	if err != nil {
		return nil, fmt.Errorf("permission: failed to parse model: %w", err)
	}

	enforcer, err := casbin.NewSyncedEnforcer(m, adapter)
	if err != nil {
		return nil, fmt.Errorf("permission: failed to create enforcer: %w", err)
	}

	if err := enforcer.LoadPolicy(); err != nil {
		return nil, fmt.Errorf("permission: failed to load policy: %w", err)
	}

	svc := &PermissionService{enforcer: enforcer, cfg: cfg}

	if cfg.SeedDefaults {
		svc.seedDefaults(db)
	}

	return svc, nil
}

// UserSubject returns the Casbin subject string for a given user ID.
func UserSubject(userID uint) string {
	return fmt.Sprintf("user:%d", userID)
}

// CheckPermission checks whether a user has the given permission.
func (s *PermissionService) CheckPermission(userID uint, obj, act string) (bool, error) {
	return s.enforcer.Enforce(UserSubject(userID), obj, act)
}

// --- Policy CRUD (role → permission) ---

// AddRolePolicy adds a policy rule granting a role permission on an object/action.
func (s *PermissionService) AddRolePolicy(role, obj, act string) (bool, error) {
	return s.enforcer.AddPolicy(role, obj, act)
}

// RemoveRolePolicy removes a policy rule for a role.
func (s *PermissionService) RemoveRolePolicy(role, obj, act string) (bool, error) {
	return s.enforcer.RemovePolicy(role, obj, act)
}

// GetRolePolicies returns all policy rules for a specific role.
func (s *PermissionService) GetRolePolicies(role string) [][]string {
	res, _ := s.enforcer.GetFilteredPolicy(0, role)
	return res
}

// GetAllPolicies returns all policy rules.
func (s *PermissionService) GetAllPolicies() [][]string {
	res, _ := s.enforcer.GetPolicy()
	return res
}

// --- User-role assignment ---

// AssignUserRole assigns a role to a user.
func (s *PermissionService) AssignUserRole(userID uint, role string) (bool, error) {
	return s.enforcer.AddGroupingPolicy(UserSubject(userID), role)
}

// RemoveUserRole removes a role from a user.
func (s *PermissionService) RemoveUserRole(userID uint, role string) (bool, error) {
	return s.enforcer.RemoveGroupingPolicy(UserSubject(userID), role)
}

// GetUserRoles returns all roles assigned to a user.
func (s *PermissionService) GetUserRoles(userID uint) ([]string, error) {
	return s.enforcer.GetRolesForUser(UserSubject(userID))
}

// SyncUserRole ensures a user has the given role (idempotent).
func (s *PermissionService) SyncUserRole(userID uint, role string) error {
	_, err := s.enforcer.AddGroupingPolicy(UserSubject(userID), role)
	return err
}

// seedDefaults inserts default policies if they don't already exist,
// and registers platform permissions into the registry.
func (s *PermissionService) seedDefaults(db *gorm.DB) {
	defaults := [][]string{
		// admin
		{"admin", "user", "create"},
		{"admin", "user", "read"},
		{"admin", "user", "update"},
		{"admin", "user", "delete"},
		{"admin", "article", "create"},
		{"admin", "article", "read"},
		{"admin", "article", "update"},
		{"admin", "article", "delete"},
		{"admin", "permission", "manage"},
		// user
		{"user", "article", "read"},
		{"user", "article", "create"},
		// editor
		{"editor", "article", "read"},
		{"editor", "article", "create"},
		{"editor", "article", "update"},
		// storage permissions
		{"admin", "storage", "upload"},
		{"admin", "storage", "read"},
		{"admin", "storage", "delete"},
		{"user", "storage", "upload"},
		{"user", "storage", "read"},
		{"editor", "storage", "upload"},
		{"editor", "storage", "read"},
	}

	for _, p := range defaults {
		// AddPolicy is idempotent — returns false if rule already exists.
		_, _ = s.enforcer.AddPolicy(p[0], p[1], p[2])
	}

	// Self-register platform permissions into the registry
	platformDefs := []ResourceDef{
		{Resource: "user", Actions: []string{"create", "read", "update", "delete", "ban"}, Description: "User management"},
		{Resource: "role", Actions: []string{"read", "assign", "remove"}, Description: "Role assignment"},
		{Resource: "policy", Actions: []string{"read", "create", "delete"}, Description: "Permission policies"},
		{Resource: "defaults", Actions: []string{"read", "update"}, Description: "Default role templates"},
		{Resource: "registry", Actions: []string{"read"}, Description: "Permission registry"},
	}
	if db != nil {
		s.RegisterPermissions(db, "platform", platformDefs)
	}
}
