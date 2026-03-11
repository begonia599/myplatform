package sdk

import (
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
