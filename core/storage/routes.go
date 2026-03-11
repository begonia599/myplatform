package storage

import (
	"github.com/begonia599/myplatform/core/auth"
	"github.com/begonia599/myplatform/core/permission"
	"github.com/gin-gonic/gin"
)

// RegisterRoutes mounts all storage endpoints under /api/storage, protected by auth middleware.
func RegisterRoutes(router *gin.Engine, authService *auth.AuthService,
	storageService *StorageService, permService *permission.PermissionService) {

	handler := NewHandler(storageService, permService)

	api := router.Group("/api/storage")
	api.Use(auth.AuthMiddleware(authService))
	{
		api.POST("/upload", handler.HandleUpload)
		api.GET("/files", handler.HandleList)
		api.GET("/files/:id", handler.HandleGetMeta)
		api.GET("/files/:id/download", handler.HandleDownload)
		api.DELETE("/files/:id", handler.HandleDelete)
	}
}
