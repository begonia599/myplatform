package sdk

import (
	"fmt"
	"net/http"
	"time"
)

// AuthService wraps all /auth endpoints.
type AuthService struct {
	c *Client
}

// Register creates a new user account.
func (a *AuthService) Register(username, password, role string) (*RegisterResponse, error) {
	body := map[string]string{
		"username": username,
		"password": password,
	}
	if role != "" {
		body["role"] = role
	}
	var resp RegisterResponse
	if err := a.c.doJSON(http.MethodPost, "/auth/register", body, &resp, false); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Login authenticates and stores the token pair in the client.
func (a *AuthService) Login(username, password string) (*TokenPair, error) {
	var tokens TokenPair
	err := a.c.doJSON(http.MethodPost, "/auth/login", map[string]string{
		"username": username,
		"password": password,
	}, &tokens, false)
	if err != nil {
		return nil, err
	}

	a.c.SetTokens(tokens.AccessToken, tokens.RefreshToken, tokens.ExpiresIn)
	return &tokens, nil
}

// Refresh manually refreshes the token pair.
func (a *AuthService) Refresh() (*TokenPair, error) {
	a.c.mu.RLock()
	rt := a.c.refreshToken
	a.c.mu.RUnlock()

	if rt == "" {
		return nil, &APIError{StatusCode: 401, Message: "no refresh token available"}
	}

	var tokens TokenPair
	err := a.c.doJSON(http.MethodPost, "/auth/refresh", map[string]string{
		"refresh_token": rt,
	}, &tokens, false)
	if err != nil {
		return nil, err
	}

	a.c.SetTokens(tokens.AccessToken, tokens.RefreshToken, tokens.ExpiresIn)
	return &tokens, nil
}

// Logout revokes all refresh tokens for the current user.
func (a *AuthService) Logout() error {
	err := a.c.doJSON(http.MethodPost, "/auth/logout", nil, nil, true)
	if err != nil {
		return err
	}

	a.c.mu.Lock()
	a.c.accessToken = ""
	a.c.refreshToken = ""
	a.c.expiresAt = time.Time{}
	a.c.mu.Unlock()

	return nil
}

// Me returns the current user's info and profile.
func (a *AuthService) Me() (*MeResponse, error) {
	var resp MeResponse
	if err := a.c.doJSON(http.MethodGet, "/auth/me", nil, &resp, true); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Verify validates a token and returns user info (service-to-service, no auth needed).
func (a *AuthService) Verify(token string) (*VerifyResponse, error) {
	var resp VerifyResponse
	err := a.c.doJSON(http.MethodPost, "/auth/verify", map[string]string{
		"token": token,
	}, &resp, false)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetProfile returns the current user's profile.
func (a *AuthService) GetProfile() (*UserProfile, error) {
	var resp UserProfile
	if err := a.c.doJSON(http.MethodGet, "/auth/profile", nil, &resp, true); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ProfileUpdate holds optional fields for updating a profile.
// Only non-nil fields will be sent.
type ProfileUpdate struct {
	Nickname  *string `json:"nickname,omitempty"`
	AvatarURL *string `json:"avatar_url,omitempty"`
	Bio       *string `json:"bio,omitempty"`
	Phone     *string `json:"phone,omitempty"`
	Birthday  *string `json:"birthday,omitempty"` // YYYY-MM-DD
}

// UpdateProfile updates the current user's profile.
func (a *AuthService) UpdateProfile(update *ProfileUpdate) (*UserProfile, error) {
	var resp UserProfile
	if err := a.c.doJSON(http.MethodPut, "/auth/profile", update, &resp, true); err != nil {
		return nil, err
	}
	return &resp, nil
}

// OAuthAuthorize returns the OAuth authorization URL for the given provider.
// redirectURI is the business frontend URL to redirect back to after auth.
func (a *AuthService) OAuthAuthorize(provider, redirectURI string) (*OAuthAuthorizeResponse, error) {
	path := fmt.Sprintf("/auth/oauth/%s?redirect_uri=%s", provider, redirectURI)
	var resp OAuthAuthorizeResponse
	if err := a.c.doJSON(http.MethodGet, path, nil, &resp, false); err != nil {
		return nil, err
	}
	return &resp, nil
}

// OAuthExchange exchanges a one-time exchange code for a token pair.
func (a *AuthService) OAuthExchange(exchangeCode string) (*TokenPair, error) {
	var tokens TokenPair
	err := a.c.doJSON(http.MethodPost, "/auth/oauth/exchange", map[string]string{
		"exchange_code": exchangeCode,
	}, &tokens, false)
	if err != nil {
		return nil, err
	}
	a.c.SetTokens(tokens.AccessToken, tokens.RefreshToken, tokens.ExpiresIn)
	return &tokens, nil
}

// ChangePassword changes the user's password. For OAuth-only users (no existing password),
// pass an empty oldPassword to set password for the first time.
func (a *AuthService) ChangePassword(oldPassword, newPassword string) error {
	body := map[string]string{"new_password": newPassword}
	if oldPassword != "" {
		body["old_password"] = oldPassword
	}
	return a.c.doJSON(http.MethodPut, "/auth/password", body, nil, true)
}

// GetOAuthAccounts returns all OAuth accounts linked to the current user.
func (a *AuthService) GetOAuthAccounts() (*OAuthAccountsResponse, error) {
	var resp OAuthAccountsResponse
	if err := a.c.doJSON(http.MethodGet, "/auth/oauth/accounts", nil, &resp, true); err != nil {
		return nil, err
	}
	return &resp, nil
}

// UnlinkOAuth removes an OAuth account link for the given provider.
func (a *AuthService) UnlinkOAuth(provider string) error {
	return a.c.doJSON(http.MethodDelete, "/auth/oauth/accounts/"+provider, nil, nil, true)
}

// OAuthBindAuthorize returns the OAuth authorization URL in bind mode.
// The callback will link the third-party account to the currently
// authenticated user (no new user is created).
//
// On the redirect_uri, look for ?bind_result=success|already_bound|conflict|oauth_failed|internal_error.
func (a *AuthService) OAuthBindAuthorize(provider, redirectURI string) (*OAuthAuthorizeResponse, error) {
	path := fmt.Sprintf("/auth/oauth/%s/bind?redirect_uri=%s", provider, redirectURI)
	var resp OAuthAuthorizeResponse
	if err := a.c.doJSON(http.MethodGet, path, nil, &resp, true); err != nil {
		return nil, err
	}
	return &resp, nil
}

// LinkExisting merges the currently authenticated (OAuth-only) user into a
// verified local account. Returns new tokens for the local account and the
// secondary (tombstone) ID. The caller should migrate any business-owned
// user_id references to PrimaryID, then call PurgeUser(SecondaryID).
//
// The new tokens are NOT auto-stored on the client because the caller may
// want to perform business-side migrations using the secondary's identity
// before switching identity.
func (a *AuthService) LinkExisting(username, password string) (*LinkExistingResponse, error) {
	body := map[string]string{
		"username": username,
		"password": password,
	}
	var resp LinkExistingResponse
	if err := a.c.doJSON(http.MethodPost, "/auth/oauth/link-existing", body, &resp, true); err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetCanonicalUser resolves a (possibly merged) user ID to the active user.
func (a *AuthService) GetCanonicalUser(id uint) (*CanonicalUserResponse, error) {
	path := fmt.Sprintf("/auth/users/%d/canonical", id)
	var resp CanonicalUserResponse
	if err := a.c.doJSON(http.MethodGet, path, nil, &resp, true); err != nil {
		return nil, err
	}
	return &resp, nil
}

// PurgeUser hard-deletes a tombstone (a user that has been merged).
// Caller must be the merge target or admin/root.
func (a *AuthService) PurgeUser(id uint) error {
	path := fmt.Sprintf("/auth/users/%d/purge", id)
	return a.c.doJSON(http.MethodDelete, path, nil, nil, true)
}
