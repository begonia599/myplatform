package permission

import (
	"net/http"

	"github.com/begonia599/myplatform/core/auth"
	"github.com/gin-gonic/gin"
)

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
