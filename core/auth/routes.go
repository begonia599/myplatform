package auth

import (
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func RegisterRoutes(router *gin.Engine, service *AuthService, rootService *RootService, oauthService *OAuthService, permApply PermissionApplier, db *gorm.DB) {
	h := NewHandler(service, rootService, oauthService, permApply, db)
	g := router.Group("/auth")
	g.POST("/register", h.HandleRegister)
	g.POST("/login", h.HandleLogin)
	g.POST("/refresh", h.HandleRefresh)
	g.POST("/verify", h.HandleVerify)
	g.POST("/logout", AuthMiddleware(service), h.HandleLogout)
	g.GET("/me", AuthMiddleware(service), h.HandleMe)
	g.GET("/profile", AuthMiddleware(service), h.HandleGetProfile)
	g.PUT("/profile", AuthMiddleware(service), h.HandleUpdateProfile)

	// OAuth account management (static paths must be registered before wildcard)
	g.PUT("/password", AuthMiddleware(service), h.HandleChangePassword)
	g.GET("/oauth/accounts", AuthMiddleware(service), h.HandleGetOAuthAccounts)
	g.DELETE("/oauth/accounts/:provider", AuthMiddleware(service), h.HandleUnlinkOAuth)
	g.POST("/oauth/link-existing", AuthMiddleware(service), h.HandleLinkExisting)

	// Canonical user lookup (follows merged_into chain).
	// Used by external apps to resolve stale user IDs to the active user.
	g.GET("/users/:id/canonical", AuthMiddleware(service), h.HandleGetCanonicalUser)
	// Hard-delete a tombstone. Caller must be the merge target or admin.
	g.DELETE("/users/:id/purge", AuthMiddleware(service), h.HandlePurgeUser)

	// OAuth login flow (wildcard :provider)
	g.GET("/oauth/:provider", h.HandleOAuthAuthorize)
	g.GET("/oauth/:provider/bind", AuthMiddleware(service), h.HandleOAuthBindAuthorize)
	g.GET("/oauth/:provider/callback", h.HandleOAuthCallback)
	g.POST("/oauth/exchange", h.HandleOAuthExchange)

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
