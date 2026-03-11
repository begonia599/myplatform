package auth

import (
	"errors"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

const contextUserKey = "current_user"

type Claims struct {
	jwt.RegisteredClaims
	UserID   uint   `json:"user_id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	IsRoot   bool   `json:"is_root"`
}

type ContextUser struct {
	ID       uint
	Username string
	Role     string
	IsRoot   bool
}

func SetCurrentUser(c *gin.Context, u ContextUser) {
	c.Set(contextUserKey, u)
}

func CurrentUser(c *gin.Context) (ContextUser, bool) {
	v, exists := c.Get(contextUserKey)
	if !exists {
		return ContextUser{}, false
	}
	u, ok := v.(ContextUser)
	return u, ok
}

func MustCurrentUser(c *gin.Context) (ContextUser, error) {
	u, ok := CurrentUser(c)
	if !ok {
		return ContextUser{}, errors.New("no authenticated user in context")
	}
	return u, nil
}
