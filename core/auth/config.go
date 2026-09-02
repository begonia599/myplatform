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
	GitHub  GitHubOAuthConfig  `yaml:"github"`
	Discord DiscordOAuthConfig `yaml:"discord"`

	// AllowedRedirectHosts lists the hosts (optionally host:port) that a
	// business frontend may pass as redirect_uri. After the provider callback
	// the platform 302s the browser to redirect_uri carrying a one-time
	// exchange_code (login) or bind_result (bind); without this allowlist
	// anyone could start a flow with redirect_uri pointing at their own server
	// and harvest exchange codes — and therefore tokens — from users who
	// complete the provider login. Matching is case-insensitive and exact
	// (no wildcards). When empty, OAuth authorize requests are rejected.
	AllowedRedirectHosts []string `yaml:"allowed_redirect_hosts"`
}

type DiscordOAuthConfig struct {
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
	RedirectURL  string `yaml:"redirect_url"`
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
