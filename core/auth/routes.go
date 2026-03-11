package auth

import (
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func RegisterRoutes(router *gin.Engine, service *AuthService, rootService *RootService, permApply PermissionApplier, db *gorm.DB) {
	h := NewHandler(service, rootService, permApply, db)
	g := router.Group("/auth")
	g.POST("/register", h.HandleRegister)
	g.POST("/login", h.HandleLogin)
	g.POST("/refresh", h.HandleRefresh)
	g.POST("/verify", h.HandleVerify)
	g.POST("/logout", AuthMiddleware(service), h.HandleLogout)
	g.GET("/me", AuthMiddleware(service), h.HandleMe)
	g.GET("/profile", AuthMiddleware(service), h.HandleGetProfile)
	g.PUT("/profile", AuthMiddleware(service), h.HandleUpdateProfile)

	// Root endpoints
	g.POST("/root/otp", h.HandleRootOTP)
	g.POST("/root/setup", AuthMiddleware(service), h.HandleRootSetup)

	// Admin: user management
	admin := g.Group("/admin")
	admin.Use(AuthMiddleware(service))
	admin.Use(RequireRole("admin"))
	{
		admin.GET("/users", h.HandleListUsers)
		admin.PUT("/users/status", h.HandleUpdateUserStatus)
	}
}
