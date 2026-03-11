package auth

import (
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	"sync"
	"time"

	"gorm.io/gorm"
)

// RootService manages the root super-admin user with console-based OTP login.
// Root has no hardcoded password — authentication is done via a one-time code
// printed to the server console.
type RootService struct {
	db  *gorm.DB
	cfg *AuthConfig

	mu       sync.Mutex
	otp      string
	otpExpAt time.Time
}

// NewRootService creates a new RootService and ensures a root user exists in the database.
func NewRootService(db *gorm.DB, cfg *AuthConfig) *RootService {
	rs := &RootService{db: db, cfg: cfg}
	rs.ensureRootUser()
	return rs
}

// ensureRootUser creates the root user if it doesn't exist.
// Root starts with an empty password hash (cannot login with password until setup).
func (r *RootService) ensureRootUser() {
	var count int64
	r.db.Model(&User{}).Where("is_root = ?", true).Count(&count)
	if count > 0 {
		return
	}

	// Check if a user named "root" already exists
	var existing User
	if err := r.db.Where("username = ?", "root").First(&existing).Error; err == nil {
		// Promote existing "root" user
		r.db.Model(&existing).Updates(map[string]any{"is_root": true, "role": "admin"})
		log.Println("[ROOT] Existing 'root' user promoted to root.")
		return
	}

	user := User{
		Username:     "root",
		PasswordHash: "", // empty — cannot login with password until setup
		Role:         "admin",
		Status:       "active",
		IsRoot:       true,
	}
	if err := r.db.Create(&user).Error; err != nil {
		log.Printf("[ROOT] Warning: failed to create root user: %v\n", err)
		return
	}
	log.Println("[ROOT] Root user created. Use OTP login to set up credentials.")
}

// RequestOTP generates a 6-digit OTP, stores it, and prints it to the server console.
// The OTP is valid for 60 seconds.
func (r *RootService) RequestOTP() {
	r.mu.Lock()
	defer r.mu.Unlock()

	code, _ := rand.Int(rand.Reader, big.NewInt(900000))
	r.otp = fmt.Sprintf("%06d", code.Int64()+100000)
	r.otpExpAt = time.Now().Add(60 * time.Second)

	log.Println("┌─────────────────────────────────────┐")
	log.Printf("│ [ROOT] Login code: %s              │\n", r.otp)
	log.Println("│ [ROOT] Expires in 60 seconds.       │")
	log.Println("└─────────────────────────────────────┘")
}

// VerifyOTP checks if the provided code matches the current OTP.
// Returns true only once — the OTP is consumed after verification.
func (r *RootService) VerifyOTP(code string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.otp == "" || time.Now().After(r.otpExpAt) {
		r.otp = ""
		return false
	}
	if r.otp != code {
		return false
	}

	// Consume the OTP
	r.otp = ""
	return true
}

// GetRootUser returns the current root user from the database.
func (r *RootService) GetRootUser() (*User, error) {
	var user User
	if err := r.db.Where("is_root = ?", true).First(&user).Error; err != nil {
		return nil, fmt.Errorf("root user not found: %w", err)
	}
	return &user, nil
}

// HasPassword checks if the root user has a password set.
func (r *RootService) HasPassword() bool {
	user, err := r.GetRootUser()
	if err != nil {
		return false
	}
	return user.PasswordHash != ""
}

// SetCredentials sets a username and password for the root user.
// After this, root can login with username/password (OTP is still available).
func (r *RootService) SetCredentials(username, password string) error {
	user, err := r.GetRootUser()
	if err != nil {
		return err
	}

	hash, err := hashPassword(password)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	updates := map[string]any{"password_hash": hash}
	if username != "" && username != user.Username {
		updates["username"] = username
	}

	if err := r.db.Model(user).Updates(updates).Error; err != nil {
		return fmt.Errorf("failed to update root credentials: %w", err)
	}

	log.Printf("[ROOT] Credentials updated for root user (username: %s)\n", username)
	return nil
}

// BindUser transfers root privileges to an existing user.
// The old root user loses root status, the target user becomes root.
func (r *RootService) BindUser(targetUserID uint) error {
	return r.db.Transaction(func(tx *gorm.DB) error {
		// Remove root from current root user
		if err := tx.Model(&User{}).Where("is_root = ?", true).
			Update("is_root", false).Error; err != nil {
			return fmt.Errorf("failed to remove old root: %w", err)
		}

		// Promote target user to root
		result := tx.Model(&User{}).Where("id = ?", targetUserID).
			Updates(map[string]any{"is_root": true, "role": "admin"})
		if result.Error != nil {
			return fmt.Errorf("failed to promote user: %w", result.Error)
		}
		if result.RowsAffected == 0 {
			return fmt.Errorf("user %d not found", targetUserID)
		}

		log.Printf("[ROOT] Root privileges transferred to user ID %d\n", targetUserID)
		return nil
	})
}

// IsRootUser checks whether a given user ID has root privileges.
func (r *RootService) IsRootUser(userID uint) bool {
	var count int64
	r.db.Model(&User{}).Where("id = ? AND is_root = ?", userID, true).Count(&count)
	return count > 0
}
