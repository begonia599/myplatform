package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
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
	ErrProviderNotLinked   = errors.New("provider not linked for user")
	ErrNoStoredToken       = errors.New("no stored access token; re-authorization required")
	ErrTokenRefresh        = errors.New("oauth token refresh failed")
)

// tokenExpiryPtr returns a pointer to the token's expiry time, or nil when
// the provider did not specify one (e.g. classic GitHub PATs never expire).
func tokenExpiryPtr(tok *oauth2.Token) *time.Time {
	if tok == nil || tok.Expiry.IsZero() {
		return nil
	}
	e := tok.Expiry
	return &e
}

// tokenUpdatesMap returns the column→value map used to persist token-related
// fields onto an existing OAuthAccount row.
func tokenUpdatesMap(tok *oauth2.Token, scopes []string) map[string]any {
	return map[string]any{
		"access_token":     tok.AccessToken,
		"refresh_token":    tok.RefreshToken,
		"token_expires_at": tokenExpiryPtr(tok),
		"scopes":           strings.Join(scopes, " "),
	}
}

// applyTokenFields populates token-related fields on a fresh OAuthAccount
// before insertion.
func applyTokenFields(acct *OAuthAccount, tok *oauth2.Token, scopes []string) {
	acct.AccessToken = tok.AccessToken
	acct.RefreshToken = tok.RefreshToken
	acct.TokenExpiresAt = tokenExpiryPtr(tok)
	acct.Scopes = strings.Join(scopes, " ")
}

// oauthMode distinguishes login (creates/finds user) from bind (links to current user).
type oauthMode string

const (
	oauthModeLogin oauthMode = "login"
	oauthModeBind  oauthMode = "bind"
)

// Default scopes per provider (login flow). Extended-scope flows (e.g. zone
// gate checks) request additional scopes via the elevate endpoint.
var (
	scopesGitHubLogin  = []string{"read:user", "user:email"}
	scopesDiscordLogin = []string{"identify"}
)

type oauthState struct {
	createdAt   time.Time
	redirectURI string
	mode        oauthMode
	bindUserID  uint // only set when mode == bind
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
		Scopes:       scopesGitHubLogin,
		Endpoint:     githubOAuth.Endpoint,
	}
}

// Authorize returns the OAuth authorization URL for the given provider in
// login mode (creates or finds a user).
func (s *OAuthService) Authorize(provider, redirectURI string) (string, error) {
	return s.authorize(provider, redirectURI, oauthModeLogin, 0)
}

// AuthorizeBind returns the OAuth authorization URL for the given provider in
// bind mode (links the third-party account to bindUserID).
func (s *OAuthService) AuthorizeBind(provider, redirectURI string, bindUserID uint) (string, error) {
	if bindUserID == 0 {
		return "", errors.New("auth: bindUserID is required for bind mode")
	}
	return s.authorize(provider, redirectURI, oauthModeBind, bindUserID)
}

func (s *OAuthService) authorize(provider, redirectURI string, mode oauthMode, bindUserID uint) (string, error) {
	switch provider {
	case "github", "discord":
		state, err := randomHex(16)
		if err != nil {
			return "", fmt.Errorf("auth: generate state: %w", err)
		}
		s.states.Store(state, oauthState{
			createdAt:   time.Now(),
			redirectURI: redirectURI,
			mode:        mode,
			bindUserID:  bindUserID,
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
//
// In login mode it returns a redirect URL to the business frontend with an
// exchange_code query param. In bind mode it links the third-party account
// to the user recorded in state and returns a redirect URL with a
// bind_result query param ("success" or an error code).
func (s *OAuthService) Callback(authService *AuthService, permApply PermissionApplier, provider, code, state string) (string, error) {
	val, loaded := s.states.LoadAndDelete(state)
	if !loaded {
		return "", ErrInvalidState
	}
	st := val.(oauthState)

	if st.mode == oauthModeBind {
		return s.bindCallback(provider, code, st, permApply), nil
	}

	// Default: login mode.
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

// bindCallback links the third-party account to st.bindUserID without creating
// or switching users. Returns a redirect URL with a bind_result query param.
//
// Possible bind_result values:
//   - "success"           — newly bound to current user
//   - "already_bound"     — already bound to current user (idempotent)
//   - "conflict"          — bound to a different user
//   - "oauth_failed"      — provider exchange/userinfo error
//   - "internal_error"    — DB error
func (s *OAuthService) bindCallback(provider, code string, st oauthState, permApply PermissionApplier) string {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var providerUserID, email, avatarURL string
	var oauthTok *oauth2.Token
	var tokenScopes []string
	switch provider {
	case "github":
		token, err := s.githubConfig().Exchange(ctx, code)
		if err != nil {
			return appendQuery(st.redirectURI, "bind_result", "oauth_failed")
		}
		ghUser, err := s.fetchGitHubUser(ctx, token.AccessToken)
		if err != nil {
			return appendQuery(st.redirectURI, "bind_result", "oauth_failed")
		}
		providerUserID = fmt.Sprintf("%d", ghUser.ID)
		email = ghUser.Email
		avatarURL = ghUser.AvatarURL
		oauthTok = token
		tokenScopes = scopesGitHubLogin
	case "discord":
		token, err := s.discordConfig().Exchange(ctx, code)
		if err != nil {
			return appendQuery(st.redirectURI, "bind_result", "oauth_failed")
		}
		dcUser, err := s.fetchDiscordUser(ctx, token.AccessToken)
		if err != nil {
			return appendQuery(st.redirectURI, "bind_result", "oauth_failed")
		}
		providerUserID = dcUser.ID
		if dcUser.Avatar != nil {
			avatarURL = fmt.Sprintf("https://cdn.discordapp.com/avatars/%s/%s.png", dcUser.ID, *dcUser.Avatar)
		}
		oauthTok = token
		tokenScopes = scopesDiscordLogin
	default:
		return appendQuery(st.redirectURI, "bind_result", "oauth_failed")
	}

	// Look up any existing OAuth row for this provider/providerUserID.
	var existing OAuthAccount
	err := s.db.Where("provider = ? AND provider_user_id = ?", provider, providerUserID).
		First(&existing).Error
	if err == nil {
		if existing.UserID == st.bindUserID {
			return appendQuery(st.redirectURI, "bind_result", "already_bound")
		}
		// The provider account is currently held by another user. If that
		// user is just an OAuth-only stub (no password set, not root, not
		// already merged), absorb them into the current user — this turns
		// a "conflict" into the more useful operation the user expects:
		// "I want to take ownership of that third-party login."
		var holder User
		if err := s.db.First(&holder, existing.UserID).Error; err != nil {
			return appendQuery(st.redirectURI, "bind_result", "internal_error")
		}
		stubLike := !holder.IsRoot &&
			holder.MergedInto == nil &&
			holder.PasswordHash == ""
		if !stubLike {
			return appendQuery(st.redirectURI, "bind_result", "conflict")
		}
		// Make sure the bind user doesn't already own this provider — would
		// double-bind in the same provider slot after merge.
		var sameProviderForUser OAuthAccount
		err := s.db.Where("user_id = ? AND provider = ?", st.bindUserID, provider).
			First(&sameProviderForUser).Error
		if err == nil {
			return appendQuery(st.redirectURI, "bind_result", "conflict")
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return appendQuery(st.redirectURI, "bind_result", "internal_error")
		}
		// Merge the stub into the current user. MergeUser moves the
		// oauth_accounts row, casbin roles, profile leftovers, and tombstones
		// the stub. After this, the third-party account is owned by st.bindUserID.
		if err := MergeUser(s.db, permApply, st.bindUserID, holder.ID); err != nil {
			return appendQuery(st.redirectURI, "bind_result", "internal_error")
		}
		// Refresh the (now-current-user-owned) row's tokens with what we just
		// got from the exchange — the stub's old tokens may be stale.
		s.db.Model(&OAuthAccount{}).
			Where("user_id = ? AND provider = ?", st.bindUserID, provider).
			Updates(tokenUpdatesMap(oauthTok, tokenScopes))
		return appendQuery(st.redirectURI, "bind_result", "success")
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return appendQuery(st.redirectURI, "bind_result", "internal_error")
	}

	// Also enforce one-account-per-provider on the bindUser side.
	var sameProviderForUser OAuthAccount
	err = s.db.Where("user_id = ? AND provider = ?", st.bindUserID, provider).
		First(&sameProviderForUser).Error
	if err == nil {
		return appendQuery(st.redirectURI, "bind_result", "conflict")
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return appendQuery(st.redirectURI, "bind_result", "internal_error")
	}

	// Create the link.
	link := OAuthAccount{
		UserID:         st.bindUserID,
		Provider:       provider,
		ProviderUserID: providerUserID,
		Email:          email,
		AvatarURL:      avatarURL,
	}
	applyTokenFields(&link, oauthTok, tokenScopes)
	if err := s.db.Create(&link).Error; err != nil {
		return appendQuery(st.redirectURI, "bind_result", "internal_error")
	}
	return appendQuery(st.redirectURI, "bind_result", "success")
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
		updates := tokenUpdatesMap(token, scopesGitHubLogin)
		updates["email"] = ghUser.Email
		updates["avatar_url"] = ghUser.AvatarURL
		s.db.Model(&oauthAccount).Updates(updates)
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
		applyTokenFields(&oauthAccount, token, scopesGitHubLogin)
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
		Scopes:       scopesDiscordLogin,
		Endpoint:     discordEndpoint,
	}
}

type discordUser struct {
	ID         string  `json:"id"`
	Username   string  `json:"username"`
	GlobalName *string `json:"global_name"`
	Avatar     *string `json:"avatar"`
	Email      string  `json:"email"`
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
		updates := tokenUpdatesMap(token, scopesDiscordLogin)
		updates["avatar_url"] = avatarURL
		s.db.Model(&oauthAccount).Updates(updates)
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
		applyTokenFields(&oauthAccount, token, scopesDiscordLogin)
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

// GetValidAccessToken returns a usable access token for the given user and
// provider, refreshing it via the stored refresh_token if it has expired or is
// within 30 seconds of expiring. The returned scopes are those recorded at the
// time of consent, parsed from the space-separated string in the database.
//
// Errors:
//   - gorm.ErrRecordNotFound — user has no OAuth account for that provider
//   - ErrNoStoredToken       — account exists but predates token persistence
//     (user must re-auth to populate the token)
//   - ErrTokenRefresh        — refresh failed (user revoked the app, network)
//   - ErrUnsupportedProvider — provider name not recognized
func (s *OAuthService) GetValidAccessToken(userID uint, provider string) (string, []string, *time.Time, error) {
	var acct OAuthAccount
	if err := s.db.Where("user_id = ? AND provider = ?", userID, provider).First(&acct).Error; err != nil {
		return "", nil, nil, err
	}
	if acct.AccessToken == "" {
		return "", nil, nil, ErrNoStoredToken
	}
	scopes := splitScopes(acct.Scopes)
	// No expiry recorded — token is treated as long-lived (e.g. classic GH PATs).
	if acct.TokenExpiresAt == nil {
		return acct.AccessToken, scopes, nil, nil
	}
	// Still fresh — return as-is. 30s safety margin avoids racing the clock.
	if time.Until(*acct.TokenExpiresAt) > 30*time.Second {
		return acct.AccessToken, scopes, acct.TokenExpiresAt, nil
	}
	// Need to refresh. Discord requires a refresh_token; if none recorded,
	// the user must re-authorize.
	if acct.RefreshToken == "" {
		return "", nil, nil, ErrTokenRefresh
	}
	var cfg *oauth2.Config
	switch provider {
	case "github":
		cfg = s.githubConfig()
	case "discord":
		cfg = s.discordConfig()
	default:
		return "", nil, nil, ErrUnsupportedProvider
	}
	src := cfg.TokenSource(context.Background(), &oauth2.Token{
		AccessToken:  acct.AccessToken,
		RefreshToken: acct.RefreshToken,
		Expiry:       *acct.TokenExpiresAt,
	})
	fresh, err := src.Token()
	if err != nil {
		return "", nil, nil, fmt.Errorf("%w: %v", ErrTokenRefresh, err)
	}
	// Persist refreshed values. Note: providers may rotate the refresh_token,
	// so we always overwrite both fields.
	updates := map[string]any{
		"access_token":     fresh.AccessToken,
		"refresh_token":    fresh.RefreshToken,
		"token_expires_at": tokenExpiryPtr(fresh),
	}
	if err := s.db.Model(&acct).Updates(updates).Error; err != nil {
		return "", nil, nil, fmt.Errorf("auth: persist refreshed token: %w", err)
	}
	return fresh.AccessToken, scopes, tokenExpiryPtr(fresh), nil
}

// splitScopes parses a space-separated scope string. Empty input returns nil.
func splitScopes(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	return strings.Fields(s)
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
