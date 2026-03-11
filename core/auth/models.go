package auth

import (
	"time"

	"gorm.io/gorm"
)

type User struct {
	ID           uint           `gorm:"primaryKey" json:"id"`
	Username     string         `gorm:"uniqueIndex;size:64;not null" json:"username"`
	PasswordHash string         `gorm:"size:255;not null" json:"-"`
	Email        *string        `gorm:"uniqueIndex;size:255" json:"email,omitempty"`
	Role         string         `gorm:"size:32;not null;default:user" json:"role"`
	Status       string         `gorm:"size:32;not null;default:active" json:"status"`
	IsRoot       bool           `gorm:"not null;default:false" json:"is_root"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
	DeletedAt    gorm.DeletedAt `gorm:"index" json:"-"`
}

type UserProfile struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	UserID    uint      `gorm:"uniqueIndex;not null" json:"user_id"`
	Nickname  string    `gorm:"size:64" json:"nickname"`
	AvatarURL string    `gorm:"size:512" json:"avatar_url"`
	Bio       string    `gorm:"size:500" json:"bio"`
	Phone     string    `gorm:"size:32" json:"phone"`
	Birthday  *time.Time `json:"birthday,omitempty"`
	UpdatedAt time.Time  `json:"updated_at"`
}

type RefreshToken struct {
	ID        uint      `gorm:"primaryKey"`
	UserID    uint      `gorm:"index;not null"`
	Token     string    `gorm:"uniqueIndex;size:512;not null"`
	ExpiresAt time.Time `gorm:"not null"`
	Revoked   bool      `gorm:"not null;default:false"`
	CreatedAt time.Time
}
