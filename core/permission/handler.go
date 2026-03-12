package permission

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// Handler exposes HTTP endpoints for permission management.
type Handler struct {
	service *PermissionService
	db      *gorm.DB
}

// NewHandler creates a new permission Handler.
func NewHandler(service *PermissionService, db *gorm.DB) *Handler {
	return &Handler{service: service, db: db}
}

// PolicyRequest is the request body for adding/removing policies.
type PolicyRequest struct {
	Role   string `json:"role" binding:"required"`
	Object string `json:"object" binding:"required"`
	Action string `json:"action" binding:"required"`
}

// RoleAssignRequest is the request body for assigning/removing user roles.
type RoleAssignRequest struct {
	UserID uint   `json:"user_id" binding:"required"`
	Role   string `json:"role" binding:"required"`
}

// HandleListPolicies returns all policies, optionally filtered by role.
func (h *Handler) HandleListPolicies(c *gin.Context) {
	role := c.Query("role")

	var policies [][]string
	if role != "" {
		policies = h.service.GetRolePolicies(role)
	} else {
		policies = h.service.GetAllPolicies()
	}

	result := make([]gin.H, 0, len(policies))
	for _, p := range policies {
		result = append(result, gin.H{
			"role":   p[0],
			"object": p[1],
			"action": p[2],
		})
	}

	c.JSON(http.StatusOK, gin.H{"policies": result})
}

// HandleAddPolicy adds a new policy rule.
func (h *Handler) HandleAddPolicy(c *gin.Context) {
	var req PolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	added, err := h.service.AddRolePolicy(req.Role, req.Object, req.Action)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to add policy"})
		return
	}

	if added {
		c.JSON(http.StatusCreated, gin.H{"message": "policy added"})
	} else {
		c.JSON(http.StatusOK, gin.H{"message": "policy already exists"})
	}
}

// HandleRemovePolicy removes an existing policy rule.
func (h *Handler) HandleRemovePolicy(c *gin.Context) {
	var req PolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	removed, err := h.service.RemoveRolePolicy(req.Role, req.Object, req.Action)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to remove policy"})
		return
	}

	if removed {
		c.JSON(http.StatusOK, gin.H{"message": "policy removed"})
	} else {
		c.JSON(http.StatusNotFound, gin.H{"error": "policy not found"})
	}
}

// HandleListUserRoles returns the roles assigned to a user.
func (h *Handler) HandleListUserRoles(c *gin.Context) {
	userIDStr := c.Param("user_id")
	userID, err := strconv.ParseUint(userIDStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user_id"})
		return
	}

	roles, err := h.service.GetUserRoles(uint(userID))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get user roles"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"user_id": userID, "roles": roles})
}

// HandleAssignRole assigns a role to a user.
func (h *Handler) HandleAssignRole(c *gin.Context) {
	var req RoleAssignRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	added, err := h.service.AssignUserRole(req.UserID, req.Role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to assign role"})
		return
	}

	if added {
		c.JSON(http.StatusCreated, gin.H{"message": "role assigned"})
	} else {
		c.JSON(http.StatusOK, gin.H{"message": "role already assigned"})
	}
}

// HandleRemoveRole removes a role from a user.
func (h *Handler) HandleRemoveRole(c *gin.Context) {
	var req RoleAssignRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	removed, err := h.service.RemoveUserRole(req.UserID, req.Role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to remove role"})
		return
	}

	if removed {
		c.JSON(http.StatusOK, gin.H{"message": "role removed"})
	} else {
		c.JSON(http.StatusNotFound, gin.H{"error": "role assignment not found"})
	}
}

// ==================== Permission Registry ====================

// RegisterPermissionsRequest is the request body for registering module permissions.
type RegisterPermissionsRequest struct {
	Module    string        `json:"module" binding:"required"`
	Resources []ResourceDef `json:"resources" binding:"required"`
}

// HandleRegisterPermissions registers permission definitions for a business module.
func (h *Handler) HandleRegisterPermissions(c *gin.Context) {
	var req RegisterPermissionsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	created, err := h.service.RegisterPermissions(h.db, req.Module, req.Resources)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to register permissions"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "permissions registered",
		"module":  req.Module,
		"created": created,
	})
}

// HandleListModules returns all registered module names.
func (h *Handler) HandleListModules(c *gin.Context) {
	modules, err := h.service.ListRegisteredModules(h.db)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list modules"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"modules": modules})
}

// HandleListModulePermissions returns all permission definitions for a specific module.
func (h *Handler) HandleListModulePermissions(c *gin.Context) {
	module := c.Param("module")

	defs, err := h.service.ListModulePermissions(h.db, module)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list permissions"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"module":      module,
		"permissions": defs,
	})
}

// ==================== Default Role Policies ====================

// SetDefaultPoliciesRequest is the request body for setting default role policies.
type SetDefaultPoliciesRequest struct {
	Policies []DefaultRolePolicy `json:"policies" binding:"required"`
}

// HandleGetDefaultPolicies returns the default policies for a role.
func (h *Handler) HandleGetDefaultPolicies(c *gin.Context) {
	role := c.Param("role")

	policies, err := h.service.GetDefaultRolePolicies(h.db, role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get default policies"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"role":     role,
		"policies": policies,
	})
}

// HandleSetDefaultPolicies replaces the default policies for a role.
func (h *Handler) HandleSetDefaultPolicies(c *gin.Context) {
	role := c.Param("role")

	var req SetDefaultPoliciesRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	if err := h.service.SetDefaultRolePolicies(h.db, role, req.Policies); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to set default policies"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "default policies updated",
		"role":    role,
	})
}

// ==================== Permission Check ====================

// CheckPermissionRequest is the request body for checking a user's permission.
type CheckPermissionRequest struct {
	UserID uint   `json:"user_id" binding:"required"`
	Object string `json:"object" binding:"required"`
	Action string `json:"action" binding:"required"`
}

// HandleCheckPermission checks if a user has a specific permission.
// This is used by business modules for service-to-service permission verification.
func (h *Handler) HandleCheckPermission(c *gin.Context) {
	var req CheckPermissionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	// Look up user to get role
	var user struct {
		Role   string
		IsRoot bool
	}
	if err := h.db.Table("users").Select("role, is_root").Where("id = ?", req.UserID).First(&user).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	// Admin and root bypass all permission checks
	if user.IsRoot || user.Role == "admin" {
		c.JSON(http.StatusOK, gin.H{"allowed": true})
		return
	}

	// Check user-specific policy
	allowed, err := h.service.CheckPermission(req.UserID, req.Object, req.Action)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "permission check failed"})
		return
	}

	// Also check role-based policy if user-specific not found
	if !allowed {
		allowed, _ = h.service.enforcer.Enforce(user.Role, req.Object, req.Action)
	}

	c.JSON(http.StatusOK, gin.H{"allowed": allowed})
}
