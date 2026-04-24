package auth

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// HandleOAuthAuthorize returns the OAuth authorization URL for the given provider.
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