package auth

import (
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// PermissionApplier is an interface for applying default permissions.
// This avoids a circular import between auth and permission packages.
type PermissionApplier interface {
	ApplyDefaultPolicies(db *gorm.DB, userID uint, role string) error
}

type Handler struct {
	service     *AuthService
	rootService *RootService
	permApply   PermissionApplier
	db          *gorm.DB
}

func NewHandler(service *AuthService, rootService *RootService, permApply PermissionApplier, db *gorm.DB) *Handler {
	return &Handler{service: service, rootService: rootService, permApply: permApply, db: db}
}

type RegisterRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
	Role     string `json:"role"`
}

type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

type VerifyRequest struct {
	Token string `json:"token" binding:"required"`
}

type ProfileUpdateRequest struct {
	Nickname  *string `json:"nickname"`
	AvatarURL *string `json:"avatar_url"`
	Bio       *string `json:"bio"`
	Phone     *string `json:"phone"`
	Birthday  *string `json:"birthday"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

func (h *Handler) HandleRegister(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	// Lock: public registration cannot specify admin role
	if req.Role == "admin" {
		req.Role = "user"
	}

	user, err := h.service.Register(req.Username, req.Password, req.Role, false)
	if err != nil {
		switch {
		case errors.Is(err, ErrRegistrationClosed):
			c.JSON(http.StatusForbidden, gin.H{"error": "registration is closed"})
		case errors.Is(err, ErrUsernameTaken):
			c.JSON(http.StatusConflict, gin.H{"error": "username already taken"})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		}
		return
	}

	// Apply default permissions for the user's role
	if h.permApply != nil {
		if err := h.permApply.ApplyDefaultPolicies(h.db, user.ID, user.Role); err != nil {
			log.Printf("Warning: failed to apply default permissions for user %d: %v\n", user.ID, err)
		}
	}

	c.JSON(http.StatusCreated, gin.H{
		"id":       user.ID,
		"username": user.Username,
		"role":     user.Role,
	})
}

func (h *Handler) HandleLogin(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	// Check if this is a root login attempt
	if h.rootService != nil {
		rootUser, _ := h.rootService.GetRootUser()
		if rootUser != nil && req.Username == rootUser.Username && !h.rootService.HasPassword() {
			// Root has no password set — require OTP
			h.rootService.RequestOTP()
			c.JSON(http.StatusOK, gin.H{"require_otp": true, "message": "OTP printed to server console"})
			return
		}
	}

	access, refresh, err := h.service.Login(req.Username, req.Password)
	if err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	c.JSON(http.StatusOK, TokenResponse{
		AccessToken:  access,
		RefreshToken: refresh,
		TokenType:    "Bearer",
		ExpiresIn:    int(h.service.cfg.AccessTokenExpiry.Seconds()),
	})
}

func (h *Handler) HandleRefresh(c *gin.Context) {
	var req RefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	access, refresh, err := h.service.Refresh(req.RefreshToken)
	if err != nil {
		if errors.Is(err, ErrInvalidToken) || errors.Is(err, ErrTokenRevoked) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or revoked refresh token"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	c.JSON(http.StatusOK, TokenResponse{
		AccessToken:  access,
		RefreshToken: refresh,
		TokenType:    "Bearer",
		ExpiresIn:    int(h.service.cfg.AccessTokenExpiry.Seconds()),
	})
}

func (h *Handler) HandleLogout(c *gin.Context) {
	u, err := MustCurrentUser(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "not authenticated"})
		return
	}

	if err := h.service.Logout(u.ID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "logged out successfully"})
}

// HandleMe returns the current authenticated user's info and profile.
func (h *Handler) HandleMe(c *gin.Context) {
	cu, err := MustCurrentUser(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "not authenticated"})
		return
	}

	user, err := h.service.GetUserByID(cu.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get user"})
		return
	}

	profile, err := h.service.GetProfile(cu.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get profile"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"user":    user,
		"profile": profile,
	})
}

// HandleVerify validates a token and returns user info. For service-to-service calls.
func (h *Handler) HandleVerify(c *gin.Context) {
	var req VerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	claims, err := h.service.ValidateAccessToken(req.Token)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"valid": false, "error": "invalid or expired token"})
		return
	}

	// Fetch current user status from DB (token claims may be stale)
	user, err := h.service.GetUserByID(claims.UserID)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"valid": false, "error": "user not found"})
		return
	}

	if user.Status != "active" {
		c.JSON(http.StatusForbidden, gin.H{"valid": false, "error": "user is " + user.Status})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"valid": true,
		"user": gin.H{
			"id":       user.ID,
			"username": user.Username,
			"role":     user.Role,
			"status":   user.Status,
		},
	})
}

// HandleGetProfile returns the current user's profile.
func (h *Handler) HandleGetProfile(c *gin.Context) {
	cu, err := MustCurrentUser(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "not authenticated"})
		return
	}

	profile, err := h.service.GetProfile(cu.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get profile"})
		return
	}

	c.JSON(http.StatusOK, profile)
}

// HandleUpdateProfile updates the current user's profile.
func (h *Handler) HandleUpdateProfile(c *gin.Context) {
	cu, err := MustCurrentUser(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "not authenticated"})
		return
	}

	var req ProfileUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	updates := make(map[string]any)
	if req.Nickname != nil {
		updates["nickname"] = *req.Nickname
	}
	if req.AvatarURL != nil {
		updates["avatar_url"] = *req.AvatarURL
	}
	if req.Bio != nil {
		updates["bio"] = *req.Bio
	}
	if req.Phone != nil {
		updates["phone"] = *req.Phone
	}
	if req.Birthday != nil {
		t, err := time.Parse("2006-01-02", *req.Birthday)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "birthday must be YYYY-MM-DD format"})
			return
		}
		updates["birthday"] = t
	}

	if len(updates) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no fields to update"})
		return
	}

	profile, err := h.service.UpdateProfile(cu.ID, updates)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update profile"})
		return
	}

	c.JSON(http.StatusOK, profile)
}

// ==================== Root Endpoints ====================

type RootOTPRequest struct {
	Code string `json:"code" binding:"required"`
}

type RootSetupRequest struct {
	Action   string `json:"action" binding:"required"` // "set_credentials" or "bind_user"
	Username string `json:"username"`
	Password string `json:"password"`
	UserID   uint   `json:"user_id"`
}

// HandleRootOTP verifies the console OTP and returns a JWT token for root.
func (h *Handler) HandleRootOTP(c *gin.Context) {
	var req RootOTPRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	if !h.rootService.VerifyOTP(req.Code) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired OTP"})
		return
	}

	// OTP valid — generate tokens for the root user
	rootUser, err := h.rootService.GetRootUser()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "root user not found"})
		return
	}

	access, err := h.service.generateAccessToken(rootUser)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate token"})
		return
	}

	refresh, err := h.service.generateRefreshToken(rootUser.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate refresh token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token":  access,
		"refresh_token": refresh,
		"token_type":    "Bearer",
		"expires_in":    int(h.service.cfg.AccessTokenExpiry.Seconds()),
		"is_root":       true,
		"needs_setup":   !h.rootService.HasPassword(),
	})
}

// HandleRootSetup lets the root user set credentials or bind to an existing user.
func (h *Handler) HandleRootSetup(c *gin.Context) {
	cu, err := MustCurrentUser(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "not authenticated"})
		return
	}

	if !h.rootService.IsRootUser(cu.ID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "not root user"})
		return
	}

	var req RootSetupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	switch req.Action {
	case "set_credentials":
		if req.Password == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "password is required"})
			return
		}
		username := req.Username
		if username == "" {
			rootUser, _ := h.rootService.GetRootUser()
			if rootUser != nil {
				username = rootUser.Username
			}
		}
		if err := h.rootService.SetCredentials(username, req.Password); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "credentials updated", "username": username})

	case "bind_user":
		if req.UserID == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "user_id is required"})
			return
		}
		if err := h.rootService.BindUser(req.UserID); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "root bound to user", "user_id": req.UserID})

	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "action must be 'set_credentials' or 'bind_user'"})
	}
}

// ==================== Admin: User Management ====================

// HandleListUsers returns all users (admin only).
func (h *Handler) HandleListUsers(c *gin.Context) {
	var users []User
	if err := h.db.Order("id").Find(&users).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list users"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"users": users})
}

// HandleUpdateUserStatus updates a user's status (active/banned).
func (h *Handler) HandleUpdateUserStatus(c *gin.Context) {
	var req struct {
		UserID uint   `json:"user_id" binding:"required"`
		Status string `json:"status" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	if req.Status != "active" && req.Status != "banned" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "status must be 'active' or 'banned'"})
		return
	}

	result := h.db.Model(&User{}).Where("id = ?", req.UserID).Update("status", req.Status)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update user"})
		return
	}
	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "user status updated"})
}
