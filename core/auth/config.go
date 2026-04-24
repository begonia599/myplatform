package auth

import "time"

type AuthConfig struct {
	JWTSecret          string        `yaml:"jwt_secret"`
	AccessTokenExpiry  time.Duration `yaml:"access_token_expiry"`
	RefreshTokenExpiry time.Duration `yaml:"refresh_token_expiry"`
	AllowRegistration  bool          `yaml:"allow_registration"`
	OAuth              OAuthConfig   `yaml:"oauth"`
}

type OAuthConfig struct {
	GitHub GitHubOAuthConfig `yaml:"github"`
}

type GitHubOAuthConfig struct {
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
	RedirectURL  string `yaml:"redirect_url"`
}

func (cfg *AuthConfig) ApplyDefaults() {
	if cfg.AccessTokenExpiry == 0 {
		cfg.AccessTokenExpiry = 15 * time.Minute
	}
	if cfg.RefreshTokenExpiry == 0 {
		cfg.RefreshTokenExpiry = 7 * 24 * time.Hour
	}
}
