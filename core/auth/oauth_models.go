package auth

import "time"

type OAuthAccount struct {
	ID             uint      `gorm:"primaryKey" json:"id"`
	UserID         uint      `gorm:"index;not null" json:"user_id"`
	Provider       string    `gorm:"size:32;not null;uniqueIndex:idx_provider_user" json:"provider"`
	ProviderUserID string    `gorm:"size:128;not null;uniqueIndex:idx_provider_user" json:"provider_user_id"`
	Email          string    `gorm:"size:255" json:"email"`
	AvatarURL      string    `gorm:"size:512" json:"avatar_url"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}