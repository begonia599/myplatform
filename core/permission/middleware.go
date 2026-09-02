package permission

import (
	"crypto/subtle"
	"net/http"

	"github.com/begonia599/myplatform/core/auth"
	"github.com/gin-gonic/gin"
)

// ServiceTokenHeader is the header business modules send on service-to-service calls.
const ServiceTokenHeader = "X-Service-Token"

// RequireServiceToken protects service-to-service endpoints (permission
// registry, permission check) that are not tied to an end-user session.
// When token is empty the middleware is a no-op so existing deployments keep
// working; main.go logs a warning in that case and the reverse proxy must keep
// these paths off the public internet.
func RequireServiceToken(token string) gin.HandlerFunc {
	expected := []byte(token)
	return func(c *gin.Context) {
		if len(expected) == 0 {
			c.Next()
			return
		}
		got := []byte(c.GetHeader(ServiceTokenHeader))
		if subtle.ConstantTimeCompare(got, expected) != 1 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid service token"})
			return
		}
		c.Next()
	}
}

// RequirePermission returns a Gin middleware that checks whether the
// authenticated user has the specified permission (obj + act) in Casbin.
// It must be placed after auth.AuthMiddleware in the handler chain.
func RequirePermission(service *PermissionService, obj, act string) gin.HandlerFunc {
	return func(c *gin.Context) {
		u, ok := auth.CurrentUser(c)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "not authenticated"})
			return
		}

		// Root bypasses all permission checks
		if u.IsRoot {
			c.Next()
			return
		}

		allowed, err := service.CheckPermission(u.ID, obj, act)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "permission check failed"})
			return
		}

		if !allowed {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
			return
		}

		c.Next()
	}
}
