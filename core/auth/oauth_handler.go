package auth

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// HandleOAuthAuthorize returns the OAuth authorization URL for the given provider
// in login mode (no auth required — used by sign-in/sign-up flow).
func (h *Handler) HandleOAuthAuthorize(c *gin.Context) {
	provider := c.Param("provider")
	redirectURI := c.Query("redirect_uri")

	if h.oauthService == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "oauth not configured"})
		return
	}

	if redirectURI == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "redirect_uri is required"})
		return
	}

	authURL, err := h.oauthService.Authorize(provider, redirectURI)
	if err != nil {
		if err == ErrUnsupportedProvider {
			c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported provider"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate auth url"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"auth_url": authURL})
}

// HandleOAuthBindAuthorize returns the OAuth authorization URL for the given
// provider in bind mode. Requires auth — the resulting callback links the
// third-party account to the currently authenticated user.
func (h *Handler) HandleOAuthBindAuthorize(c *gin.Context) {
	cu, err := MustCurrentUser(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "not authenticated"})
		return
	}

	provider := c.Param("provider")
	redirectURI := c.Query("redirect_uri")
	scopesRaw := c.Query("scopes") // optional space-separated extra scopes

	if h.oauthService == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "oauth not configured"})
		return
	}
	if redirectURI == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "redirect_uri is required"})
		return
	}

	var extraScopes []string
	if scopesRaw != "" {
		for _, s := range strings.Split(scopesRaw, " ") {
			s = strings.TrimSpace(s)
			if s != "" {
				extraScopes = append(extraScopes, s)
			}
		}
	}

	authURL, err := h.oauthService.AuthorizeBind(provider, redirectURI, cu.ID, extraScopes)
	if err != nil {
		if err == ErrUnsupportedProvider {
			c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported provider"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate bind url"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"auth_url": authURL})
}

// HandleLinkExisting merges the currently authenticated (OAuth-only) user
// into a local account by verifying the local credentials and migrating
// all data. Returns new tokens for the local account.
func (h *Handler) HandleLinkExisting(c *gin.Context) {
	cu, err := MustCurrentUser(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "not authenticated"})
		return
	}

	var req struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "username and password are required"})
		return
	}

	// Current user must be OAuth-only (no password). This protects against
	// a logged-in local user accidentally clobbering another local account.
	hasPassword, err := h.service.HasPassword(cu.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	if hasPassword {
		c.JSON(http.StatusBadRequest, gin.H{"error": "current user already has a password; use /auth/oauth/:provider/bind instead"})
		return
	}

	// Verify local credentials → produces the primary user.
	access, refresh, err := h.service.Login(req.Username, req.Password)
	if err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	// Login already issued tokens; we'll re-issue after merge to ensure
	// the access token's claims reflect any updated role.
	_ = access
	_ = refresh

	// Resolve the primary user (the local account).
	var primary User
	if err := h.db.Where("username = ?", req.Username).First(&primary).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "primary user not found after login"})
		return
	}

	if primary.ID == cu.ID {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cannot link a user to itself"})
		return
	}

	// Merge: secondary = current OAuth-only user, primary = the local user.
	if err := MergeUser(h.db, h.permApply, primary.ID, cu.ID); err != nil {
		switch {
		case errors.Is(err, ErrMergeRootSecondary):
			c.JSON(http.StatusForbidden, gin.H{"error": "current user is root and cannot be merged away"})
		case errors.Is(err, ErrMergeAlreadyMerged):
			c.JSON(http.StatusConflict, gin.H{"error": "one of the users is already merged"})
		case errors.Is(err, ErrMergeUserNotFound):
			c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "merge failed: " + err.Error()})
		}
		return
	}

	// Re-issue tokens for the primary so the caller is now logged in as the
	// local account and the previous Login()'s refresh token (which may have
	// been revoked during merge if cu happened to share IDs — defensive)
	// is replaced.
	newAccess, err := h.service.generateAccessToken(&primary)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to issue token"})
		return
	}
	newRefresh, err := h.service.generateRefreshToken(primary.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to issue refresh token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":      "accounts linked",
		"primary_id":   primary.ID,
		"secondary_id": cu.ID, // tombstone — caller may want to migrate own data and call purge
		"tokens": TokenResponse{
			AccessToken:  newAccess,
			RefreshToken: newRefresh,
			TokenType:    "Bearer",
			ExpiresIn:    int(h.service.cfg.AccessTokenExpiry.Seconds()),
		},
		"user": gin.H{
			"id":       primary.ID,
			"username": primary.Username,
			"role":     primary.Role,
		},
	})
}

// HandleOAuthCallback handles the callback from the OAuth provider (e.g. GitHub).
// This is a browser-facing endpoint: it processes the auth, then 302 redirects
// back to the business frontend with an exchange_code.
func (h *Handler) HandleOAuthCallback(c *gin.Context) {
	provider := c.Param("provider")
	code := c.Query("code")
	state := c.Query("state")

	if code == "" || state == "" {
		c.String(http.StatusBadRequest, "missing code or state")
		return
	}

	if h.oauthService == nil {
		c.String(http.StatusNotFound, "oauth not configured")
		return
	}

	redirectURL, err := h.oauthService.Callback(h.service, h.permApply, provider, code, state)
	if err != nil {
		c.String(http.StatusBadRequest, "oauth failed: %v", err)
		return
	}

	c.Redirect(http.StatusFound, redirectURL)
}

// HandleGetOAuthToken returns the current user's access_token for the given
// provider. Used by trusted downstream services (e.g. the blog server) that
// need to call provider APIs on behalf of the user — for example, checking
// Discord guild membership for zone gates.
//
// Auth: requires the user's own JWT. The token is scoped to that user.
//
// Responses:
//   - 200 {access_token, scopes, expires_at}
//   - 404 {"error": "provider not linked"}
//   - 410 {"error": "no stored token"}        — must re-auth (legacy account row)
//   - 401 {"error": "token refresh failed"}   — user revoked the app on provider side
func (h *Handler) HandleGetOAuthToken(c *gin.Context) {
	cu, err := MustCurrentUser(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "not authenticated"})
		return
	}
	provider := c.Param("provider")
	if h.oauthService == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "oauth not configured"})
		return
	}
	accessToken, scopes, expiresAt, err := h.oauthService.GetValidAccessToken(cu.ID, provider)
	if err != nil {
		switch {
		case errors.Is(err, gorm.ErrRecordNotFound):
			c.JSON(http.StatusNotFound, gin.H{"error": "provider not linked"})
		case errors.Is(err, ErrNoStoredToken):
			c.JSON(http.StatusGone, gin.H{"error": "no stored token; re-authorization required"})
		case errors.Is(err, ErrTokenRefresh):
			c.JSON(http.StatusUnauthorized, gin.H{"error": "token refresh failed; re-authorization required"})
		case errors.Is(err, ErrUnsupportedProvider):
			c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported provider"})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"access_token": accessToken,
		"scopes":       scopes,
		"expires_at":   expiresAt,
	})
}

// HandleOAuthExchange exchanges a one-time exchange_code for JWT tokens.
func (h *Handler) HandleOAuthExchange(c *gin.Context) {
	var req struct {
		ExchangeCode string `json:"exchange_code" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "exchange_code is required"})
		return
	}

	if h.oauthService == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "oauth not configured"})
		return
	}

	userID, err := h.oauthService.Exchange(req.ExchangeCode)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired exchange code"})
		return
	}

	user, err := h.service.GetUserByID(userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "user not found"})
		return
	}

	accessToken, err := h.service.generateAccessToken(user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate token"})
		return
	}

	refreshToken, err := h.service.generateRefreshToken(user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate refresh token"})
		return
	}

	c.JSON(http.StatusOK, TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(h.service.cfg.AccessTokenExpiry.Seconds()),
	})
}
