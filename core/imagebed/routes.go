package imagebed

import (
	"github.com/begonia599/myplatform/core/auth"
	"github.com/begonia599/myplatform/core/permission"
	"github.com/gin-gonic/gin"
)

// RegisterRoutes mounts all imagebed endpoints.
// Authenticated endpoints under /api/imagebed with auth middleware.
// Public serve endpoint /api/imagebed/:id without auth (handler checks internally).
func RegisterRoutes(router *gin.Engine, authService *auth.AuthService,
	imagebedService *ImageBedService, permService *permission.PermissionService) {

	handler := NewHandler(imagebedService, authService)

	// Public endpoint: serve image (conditional auth handled in handler)
	router.GET("/api/imagebed/:id", handler.HandleServe)

	// Authenticated endpoints
	api := router.Group("/api/imagebed")
	api.Use(auth.AuthMiddleware(authService))
	{
		api.POST("/upload", permission.RequirePermission(permService, "imagebed", "upload"), handler.HandleUpload)
		api.GET("/images", permission.RequirePermission(permService, "imagebed", "read"), handler.HandleList)
		api.DELETE("/images/:id", permission.RequirePermission(permService, "imagebed", "delete"), handler.HandleDelete)
		api.PATCH("/images/:id/visibility", permission.RequirePermission(permService, "imagebed", "update"), handler.HandleToggleVisibility)
	}
}
