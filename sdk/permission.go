package sdk

import (
	"fmt"
	"net/http"
)

// PermissionService wraps all /api/permissions endpoints.
type PermissionService struct {
	c *Client
}

// ListPolicies returns all policies, optionally filtered by role.
func (p *PermissionService) ListPolicies(role string) ([]Policy, error) {
	path := "/api/permissions/policies"
	if role != "" {
		path += "?role=" + role
	}
	var resp PolicyListResponse
	if err := p.c.doJSON(http.MethodGet, path, nil, &resp, true); err != nil {
		return nil, err
	}
	return resp.Policies, nil
}

// AddPolicy adds a new permission policy.
func (p *PermissionService) AddPolicy(role, object, action string) error {
	return p.c.doJSON(http.MethodPost, "/api/permissions/policies", map[string]string{
		"role":   role,
		"object": object,
		"action": action,
	}, nil, true)
}

// RemovePolicy removes an existing permission policy.
func (p *PermissionService) RemovePolicy(role, object, action string) error {
	return p.c.doJSON(http.MethodDelete, "/api/permissions/policies", map[string]string{
		"role":   role,
		"object": object,
		"action": action,
	}, nil, true)
}

// ListUserRoles returns the roles assigned to a user.
func (p *PermissionService) ListUserRoles(userID uint) ([]string, error) {
	path := fmt.Sprintf("/api/permissions/roles/%d", userID)
	var resp UserRolesResponse
	if err := p.c.doJSON(http.MethodGet, path, nil, &resp, true); err != nil {
		return nil, err
	}
	return resp.Roles, nil
}

// AssignRole assigns a role to a user.
func (p *PermissionService) AssignRole(userID uint, role string) error {
	return p.c.doJSON(http.MethodPost, "/api/permissions/roles", map[string]any{
		"user_id": userID,
		"role":    role,
	}, nil, true)
}

// RemoveRole removes a role from a user.
func (p *PermissionService) RemoveRole(userID uint, role string) error {
	return p.c.doJSON(http.MethodDelete, "/api/permissions/roles", map[string]any{
		"user_id": userID,
		"role":    role,
	}, nil, true)
}

// ==================== Permission Registry ====================

// RegisterPermissions registers permission definitions for a business module.
// This is idempotent — existing definitions are not duplicated.
func (p *PermissionService) RegisterPermissions(module string, resources []ResourceDef) error {
	return p.c.doJSON(http.MethodPost, "/api/permissions/registry", map[string]any{
		"module":    module,
		"resources": resources,
	}, nil, false)
}

// ListModules returns all registered module names.
func (p *PermissionService) ListModules() ([]string, error) {
	var resp ModulesResponse
	if err := p.c.doJSON(http.MethodGet, "/api/permissions/registry", nil, &resp, true); err != nil {
		return nil, err
	}
	return resp.Modules, nil
}

// ListModulePermissions returns all permission definitions for a specific module.
func (p *PermissionService) ListModulePermissions(module string) ([]PermissionDef, error) {
	var resp ModulePermissionsResponse
	if err := p.c.doJSON(http.MethodGet, "/api/permissions/registry/"+module, nil, &resp, true); err != nil {
		return nil, err
	}
	return resp.Permissions, nil
}

// ==================== Default Role Policies ====================

// GetDefaultPolicies returns the default permission policies for a role.
func (p *PermissionService) GetDefaultPolicies(role string) ([]DefaultPolicy, error) {
	var resp DefaultPoliciesResponse
	if err := p.c.doJSON(http.MethodGet, "/api/permissions/defaults/"+role, nil, &resp, true); err != nil {
		return nil, err
	}
	return resp.Policies, nil
}

// SetDefaultPolicies replaces the default permission policies for a role.
// These policies are automatically applied to new users upon registration.
func (p *PermissionService) SetDefaultPolicies(role string, policies []Policy) error {
	return p.c.doJSON(http.MethodPut, "/api/permissions/defaults/"+role, map[string]any{
		"policies": policies,
	}, nil, true)
}
