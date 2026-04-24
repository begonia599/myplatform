package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"golang.org/x/oauth2"
	githubOAuth "golang.org/x/oauth2/github"
	"gorm.io/gorm"
)

var (
	ErrUnsupportedProvider = errors.New("unsupported oauth provider")
	ErrInvalidState        = errors.New("invalid oauth state")
	ErrInvalidExchangeCode = errors.New("invalid or expired exchange code")
	ErrOAuthFailed         = errors.New("oauth exchange failed")
)

type oauthState struct {
	createdAt   time.Time
	redirectURI string
}

type exchangeEntry struct {
	userID    uint
	createdAt time.Time
}

// OAuthService handles OAuth provider interactions.
type OAuthService struct {
	db            *gorm.DB
	cfg           *AuthConfig
	states        sync.Map // state string → oauthState
	exchangeCodes sync.Map // exchange_code string → exchangeEntry
}

func NewOAuthService(cfg *AuthConfig, db *gorm.DB) *OAuthService {
	svc := &OAuthService{db: db, cfg: cfg}
	go svc.cleanup()
	return svc
}

func (s *OAuthService) githubConfig() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     s.cfg.OAuth.GitHub.ClientID,
		ClientSecret: s.cfg.OAuth.GitHub.ClientSecret,
		RedirectURL:  s.cfg.OAuth.GitHub.RedirectURL,
		Scopes:       []string{"read:user", "user:email"},
		Endpoint:     githubOAuth.Endpoint,
	}
}

// Authorize returns the OAuth authorization URL for the given provider.
// redirectURI is the business frontend URL to redirect back to after auth.
func (s *OAuthService) Authorize(provider, redirectURI string) (string, error) {
	switch provider {
	case "github", "discord":
		state, err := randomHex(16)
		if err != nil {
			return "", fmt.Errorf("auth: generate state: %w", err)
		}
		s.states.Store(state, oauthState{
			createdAt:   time.Now(),
			redirectURI: redirectURI,
		})
		var cfg *oauth2.Config
		switch provider {
		case "github":
			cfg = s.githubConfig()
		case "discord":
			cfg = s.discordConfig()
		}
		return cfg.AuthCodeURL(state), nil
	default:
		return "", ErrUnsupportedProvider
	}
}

// Callback handles the OAuth callback from the provider.
// Returns the redirect URL (business frontend + exchange_code) to 302 to.
func (s *OAuthService) Callback(authService *AuthService, permApply PermissionApplier, provider, code, state string) (string, error) {
	val, loaded := s.states.LoadAndDelete(state)
	if !loaded {
		return "", ErrInvalidState
	}
	st := val.(oauthState)

	var user *User
	var err error
	switch provider {
	case "github":
		user, err = s.githubCallback(authService, permApply, code)
	case "discord":
		user, err = s.discordCallback(authService, permApply, code)
	default:
		return "", ErrUnsupportedProvider
	}
	if err != nil {
		// Redirect back with error
		return appendQuery(st.redirectURI, "error", "oauth_failed"), nil
	}

	// Generate exchange code
	exchangeCode, err := randomHex(32)
	if err != nil {
		return appendQuery(st.redirectURI, "error", "internal_error"), nil
	}
	s.exchangeCodes.Store(exchangeCode, exchangeEntry{
		userID:    user.ID,
		createdAt: time.Now(),
	})

	return appendQuery(st.redirectURI, "exchange_code", exchangeCode), nil
}

// Exchange validates an exchange code and returns the associated user ID.
// The code is consumed (one-time use).
func (s *OAuthService) Exchange(exchangeCode string) (uint, error) {
	val, loaded := s.exchangeCodes.LoadAndDelete(exchangeCode)
	if !loaded {
		return 0, ErrInvalidExchangeCode
	}
	entry := val.(exchangeEntry)
	if time.Since(entry.createdAt) > 5*time.Minute {
		return 0, ErrInvalidExchangeCode
	}
	return entry.userID, nil
}

// --- GitHub provider ---

type githubUser struct {
	ID        int    `json:"id"`
	Login     string `json:"login"`
	Email     string `json:"email"`
	AvatarURL string `json:"avatar_url"`
	Name      string `json:"name"`
}

func (s *OAuthService) githubCallback(authService *AuthService, permApply PermissionApplier, code string) (*User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	token, err := s.githubConfig().Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrOAuthFailed, err)
	}

	ghUser, err := s.fetchGitHubUser(ctx, token.AccessToken)
	if err != nil {
		return nil, err
	}

	providerUserID := fmt.Sprintf("%d", ghUser.ID)

	// Check if OAuth account already exists
	var oauthAccount OAuthAccount
	err = s.db.Where("provider = ? AND provider_user_id = ?", "github", providerUserID).First(&oauthAccount).Error
	if err == nil {
		s.db.Model(&oauthAccount).Updates(map[string]any{
			"email":      ghUser.Email,
			"avatar_url": ghUser.AvatarURL,
		})
		var user User
		if err := s.db.First(&user, oauthAccount.UserID).Error; err != nil {
			return nil, fmt.Errorf("auth: oauth user not found: %w", err)
		}
		return &user, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("auth: query oauth account: %w", err)
	}

	// New OAuth user — create user + profile + oauth account
	var user User
	err = s.db.Transaction(func(tx *gorm.DB) error {
		username := ghUser.Login
		for i := 0; ; i++ {
			candidate := username
			if i > 0 {
				candidate = fmt.Sprintf("%s_%d", username, i)
			}
			var count int64
			tx.Model(&User{}).Where("username = ?", candidate).Count(&count)
			if count == 0 {
				username = candidate
				break
			}
		}

		user = User{
			Username:     username,
			PasswordHash: "",
			Role:         "user",
		}
		if err := tx.Create(&user).Error; err != nil {
			return fmt.Errorf("create user: %w", err)
		}

		nickname := ghUser.Name
		if nickname == "" {
			nickname = ghUser.Login
		}
		profile := UserProfile{
			UserID:    user.ID,
			Nickname:  nickname,
			AvatarURL: ghUser.AvatarURL,
		}
		if err := tx.Create(&profile).Error; err != nil {
			return fmt.Errorf("create profile: %w", err)
		}

		oauthAccount = OAuthAccount{
			UserID:         user.ID,
			Provider:       "github",
			ProviderUserID: providerUserID,
			Email:          ghUser.Email,
			AvatarURL:      ghUser.AvatarURL,
		}
		if err := tx.Create(&oauthAccount).Error; err != nil {
			return fmt.Errorf("create oauth account: %w", err)
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("auth: oauth create user: %w", err)
	}

	if permApply != nil {
		if err := permApply.ApplyDefaultPolicies(s.db, user.ID, user.Role); err != nil {
			fmt.Printf("Warning: failed to apply default permissions for oauth user %d: %v\n", user.ID, err)
		}
	}

	return &user, nil
}

func (s *OAuthService) fetchGitHubUser(ctx context.Context, accessToken string) (*githubUser, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/user", nil)
	if err != nil {
		return nil, fmt.Errorf("auth: create github request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("auth: github api request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("auth: github api returned %d", resp.StatusCode)
	}

	var user githubUser
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, fmt.Errorf("auth: decode github user: %w", err)
	}
	return &user, nil
}

// --- Discord provider ---

var discordEndpoint = oauth2.Endpoint{
	AuthURL:  "https://discord.com/oauth2/authorize",
	TokenURL: "https://discord.com/api/oauth2/token",
}

func (s *OAuthService) discordConfig() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     s.cfg.OAuth.Discord.ClientID,
		ClientSecret: s.cfg.OAuth.Discord.ClientSecret,
		RedirectURL:  s.cfg.OAuth.Discord.RedirectURL,
		Scopes:       []string{"identify"},
		Endpoint:     discordEndpoint,
	}
}

type discordUser struct {
	ID            string  `json:"id"`
	Username      string  `json:"username"`
	GlobalName    *string `json:"global_name"`
	Avatar        *string `json:"avatar"`
	Email         string  `json:"email"`
}

func (s *OAuthService) discordCallback(authService *AuthService, permApply PermissionApplier, code string) (*User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	token, err := s.discordConfig().Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrOAuthFailed, err)
	}

	dcUser, err := s.fetchDiscordUser(ctx, token.AccessToken)
	if err != nil {
		return nil, err
	}

	var avatarURL string
	if dcUser.Avatar != nil {
		avatarURL = fmt.Sprintf("https://cdn.discordapp.com/avatars/%s/%s.png", dcUser.ID, *dcUser.Avatar)
	}

	var oauthAccount OAuthAccount
	err = s.db.Where("provider = ? AND provider_user_id = ?", "discord", dcUser.ID).First(&oauthAccount).Error
	if err == nil {
		s.db.Model(&oauthAccount).Updates(map[string]any{
			"avatar_url": avatarURL,
		})
		var user User
		if err := s.db.First(&user, oauthAccount.UserID).Error; err != nil {
			return nil, fmt.Errorf("auth: oauth user not found: %w", err)
		}
		return &user, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("auth: query oauth account: %w", err)
	}

	var user User
	err = s.db.Transaction(func(tx *gorm.DB) error {
		username := dcUser.Username
		for i := 0; ; i++ {
			candidate := username
			if i > 0 {
				candidate = fmt.Sprintf("%s_%d", username, i)
			}
			var count int64
			tx.Model(&User{}).Where("username = ?", candidate).Count(&count)
			if count == 0 {
				username = candidate
				break
			}
		}

		user = User{
			Username:     username,
			PasswordHash: "",
			Role:         "user",
		}
		if err := tx.Create(&user).Error; err != nil {
			return fmt.Errorf("create user: %w", err)
		}

		nickname := dcUser.Username
		if dcUser.GlobalName != nil && *dcUser.GlobalName != "" {
			nickname = *dcUser.GlobalName
		}
		profile := UserProfile{
			UserID:    user.ID,
			Nickname:  nickname,
			AvatarURL: avatarURL,
		}
		if err := tx.Create(&profile).Error; err != nil {
			return fmt.Errorf("create profile: %w", err)
		}

		oauthAccount = OAuthAccount{
			UserID:         user.ID,
			Provider:       "discord",
			ProviderUserID: dcUser.ID,
			AvatarURL:      avatarURL,
		}
		if err := tx.Create(&oauthAccount).Error; err != nil {
			return fmt.Errorf("create oauth account: %w", err)
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("auth: oauth create user: %w", err)
	}

	if permApply != nil {
		if err := permApply.ApplyDefaultPolicies(s.db, user.ID, user.Role); err != nil {
			fmt.Printf("Warning: failed to apply default permissions for oauth user %d: %v\n", user.ID, err)
		}
	}

	return &user, nil
}

func (s *OAuthService) fetchDiscordUser(ctx context.Context, accessToken string) (*discordUser, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://discord.com/api/users/@me", nil)
	if err != nil {
		return nil, fmt.Errorf("auth: create discord request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("auth: discord api request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("auth: discord api returned %d", resp.StatusCode)
	}

	var user discordUser
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, fmt.Errorf("auth: decode discord user: %w", err)
	}
	return &user, nil
}

func (s *OAuthService) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		s.states.Range(func(key, value any) bool {
			if now.Sub(value.(oauthState).createdAt) > 10*time.Minute {
				s.states.Delete(key)
			}
			return true
		})
		s.exchangeCodes.Range(func(key, value any) bool {
			if now.Sub(value.(exchangeEntry).createdAt) > 5*time.Minute {
				s.exchangeCodes.Delete(key)
			}
			return true
		})
	}
}

func appendQuery(rawURL, key, value string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL + "?" + key + "=" + value
	}
	q := u.Query()
	q.Set(key, value)
	u.RawQuery = q.Encode()
	return u.String()
}