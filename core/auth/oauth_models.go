package auth

import "time"

type OAuthAccount struct {
	ID             uint   `gorm:"primaryKey" json:"id"`
	UserID         uint   `gorm:"index;not null" json:"user_id"`
	Provider       string `gorm:"size:32;not null;uniqueIndex:idx_provider_user" json:"provider"`
	ProviderUserID string `gorm:"size:128;not null;uniqueIndex:idx_provider_user" json:"provider_user_id"`
	Email          string `gorm:"size:255" json:"email"`
	AvatarURL      string `gorm:"size:512" json:"avatar_url"`

	// Token persistence — only populated when the user has consented to a flow
	// that needs them later (e.g. extended-scope authorization for downstream
	// API calls like Discord guild membership checks). Tokens are stored
	// plaintext; callers must only expose them over authenticated channels.
	AccessToken    string     `gorm:"type:text" json:"-"`
	RefreshToken   string     `gorm:"type:text" json:"-"`
	TokenExpiresAt *time.Time `json:"-"`
	Scopes         string     `gorm:"size:500" json:"scopes"` // space-separated, RFC 6749 style

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}
