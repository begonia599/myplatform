package permission

import (
	"github.com/begonia599/myplatform/core/auth"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// RegisterRoutes registers all permission management endpoints.
func RegisterRoutes(router *gin.Engine, authService *auth.AuthService, permService *PermissionService, db *gorm.DB) {
	h := NewHandler(permService, db)

	g := router.Group("/api/permissions")
	g.Use(auth.AuthMiddleware(authService))

	// --- Admin-only: Policy CRUD ---
	admin := g.Group("")
	admin.Use(auth.RequireRole("admin"))
	{
		admin.GET("/policies", h.HandleListPolicies)
		admin.POST("/policies", h.HandleAddPolicy)
		admin.DELETE("/policies", h.HandleRemovePolicy)

		// User-role assignment
		admin.GET("/roles/:user_id", h.HandleListUserRoles)
		admin.POST("/roles", h.HandleAssignRole)
		admin.DELETE("/roles", h.HandleRemoveRole)

		// Default role policy management (admin only)
		admin.GET("/defaults/:role", h.HandleGetDefaultPolicies)
		admin.PUT("/defaults/:role", h.HandleSetDefaultPolicies)
	}

	// --- Authenticated: Permission Registry read (any authenticated user) ---
	g.GET("/registry", h.HandleListModules)
	g.GET("/registry/:module", h.HandleListModulePermissions)

	// --- Service-to-service: no auth required (used by business modules at startup) ---
	router.POST("/api/permissions/registry", h.HandleRegisterPermissions)
	router.POST("/api/permissions/check", h.HandleCheckPermission)
}
