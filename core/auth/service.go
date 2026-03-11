package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUsernameTaken      = errors.New("username already taken")
	ErrRegistrationClosed = errors.New("registration is closed")
	ErrInvalidToken       = errors.New("invalid token")
	ErrTokenRevoked       = errors.New("token has been revoked")
)

type AuthService struct {
	db  *gorm.DB
	cfg *AuthConfig
}

func New(cfg *AuthConfig, db *gorm.DB) (*AuthService, error) {
	if cfg.JWTSecret == "" {
		return nil, fmt.Errorf("auth: jwt_secret must not be empty")
	}
	return &AuthService{db: db, cfg: cfg}, nil
}

func (s *AuthService) Register(username, password, role string, isAdmin bool) (*User, error) {
	if !isAdmin && !s.cfg.AllowRegistration {
		return nil, ErrRegistrationClosed
	}

	if role == "" {
		role = "user"
	}

	hash, err := hashPassword(password)
	if err != nil {
		return nil, fmt.Errorf("auth: failed to hash password: %w", err)
	}

	user := User{
		Username:     username,
		PasswordHash: hash,
		Role:         role,
	}

	if err := s.db.Create(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return nil, ErrUsernameTaken
		}
		// Check for unique constraint violation in the error message
		if isDuplicateKeyError(err) {
			return nil, ErrUsernameTaken
		}
		return nil, fmt.Errorf("auth: failed to create user: %w", err)
	}

	return &user, nil
}

func (s *AuthService) Login(username, password string) (string, string, error) {
	var user User
	if err := s.db.Where("username = ?", username).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", "", ErrInvalidCredentials
		}
		return "", "", fmt.Errorf("auth: query failed: %w", err)
	}

	if !checkPassword(user.PasswordHash, password) {
		return "", "", ErrInvalidCredentials
	}

	accessToken, err := s.generateAccessToken(&user)
	if err != nil {
		return "", "", err
	}

	refreshToken, err := s.generateRefreshToken(user.ID)
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

func (s *AuthService) Refresh(refreshTokenStr string) (string, string, error) {
	var rt RefreshToken
	if err := s.db.Where("token = ?", refreshTokenStr).First(&rt).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", "", ErrInvalidToken
		}
		return "", "", fmt.Errorf("auth: query failed: %w", err)
	}

	if rt.Revoked {
		return "", "", ErrTokenRevoked
	}

	if time.Now().After(rt.ExpiresAt) {
		return "", "", ErrInvalidToken
	}

	// Revoke old refresh token (token rotation)
	s.db.Model(&rt).Update("revoked", true)

	var user User
	if err := s.db.First(&user, rt.UserID).Error; err != nil {
		return "", "", fmt.Errorf("auth: user not found: %w", err)
	}

	accessToken, err := s.generateAccessToken(&user)
	if err != nil {
		return "", "", err
	}

	newRefreshToken, err := s.generateRefreshToken(user.ID)
	if err != nil {
		return "", "", err
	}

	return accessToken, newRefreshToken, nil
}

func (s *AuthService) Logout(userID uint) error {
	return s.db.Model(&RefreshToken{}).
		Where("user_id = ? AND revoked = ?", userID, false).
		Update("revoked", true).Error
}

// GetUserByID returns a user by ID.
func (s *AuthService) GetUserByID(id uint) (*User, error) {
	var user User
	if err := s.db.First(&user, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrInvalidCredentials
		}
		return nil, fmt.Errorf("auth: query failed: %w", err)
	}
	return &user, nil
}

// GetProfile returns the profile for the given user, creating one if it doesn't exist.
func (s *AuthService) GetProfile(userID uint) (*UserProfile, error) {
	var profile UserProfile
	err := s.db.Where("user_id = ?", userID).First(&profile).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			profile = UserProfile{UserID: userID}
			if err := s.db.Create(&profile).Error; err != nil {
				return nil, fmt.Errorf("auth: failed to create profile: %w", err)
			}
			return &profile, nil
		}
		return nil, fmt.Errorf("auth: query failed: %w", err)
	}
	return &profile, nil
}

// UpdateProfile updates the profile for the given user.
func (s *AuthService) UpdateProfile(userID uint, updates map[string]any) (*UserProfile, error) {
	profile, err := s.GetProfile(userID)
	if err != nil {
		return nil, err
	}
	if err := s.db.Model(profile).Updates(updates).Error; err != nil {
		return nil, fmt.Errorf("auth: failed to update profile: %w", err)
	}
	return profile, nil
}

func (s *AuthService) ValidateAccessToken(tokenStr string) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(s.cfg.JWTSecret), nil
	})
	if err != nil {
		return nil, ErrInvalidToken
	}
	if !token.Valid {
		return nil, ErrInvalidToken
	}
	return claims, nil
}

// --- internal helpers ---

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func checkPassword(hash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

func (s *AuthService) generateAccessToken(user *User) (string, error) {
	now := time.Now()
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(s.cfg.AccessTokenExpiry)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
		UserID:   user.ID,
		Username: user.Username,
		Role:     user.Role,
		IsRoot:   user.IsRoot,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.cfg.JWTSecret))
}

func (s *AuthService) generateRefreshToken(userID uint) (string, error) {
	raw, err := randomHex(32)
	if err != nil {
		return "", fmt.Errorf("auth: failed to generate refresh token: %w", err)
	}

	rt := RefreshToken{
		UserID:    userID,
		Token:     raw,
		ExpiresAt: time.Now().Add(s.cfg.RefreshTokenExpiry),
	}
	if err := s.db.Create(&rt).Error; err != nil {
		return "", fmt.Errorf("auth: failed to save refresh token: %w", err)
	}

	return raw, nil
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func isDuplicateKeyError(err error) bool {
	// PostgreSQL unique_violation error code 23505
	return err != nil && (errors.Is(err, gorm.ErrDuplicatedKey) ||
		contains(err.Error(), "duplicate key") ||
		contains(err.Error(), "23505"))
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
