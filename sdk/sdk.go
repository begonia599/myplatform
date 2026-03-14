package sdk

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// Config holds the SDK client configuration.
type Config struct {
	BaseURL    string
	HTTPClient *http.Client
}

// Client is the top-level SDK entry point.
type Client struct {
	baseURL    string
	httpClient *http.Client

	mu           sync.RWMutex
	accessToken  string
	refreshToken string
	expiresAt    time.Time

	Auth       *AuthService
	Storage    *StorageService
	Permission *PermissionService
	ImageBed   *ImageBedService
}

// New creates a new SDK client.
func New(cfg *Config) *Client {
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}

	c := &Client{
		baseURL:    cfg.BaseURL,
		httpClient: hc,
	}
	c.Auth = &AuthService{c: c}
	c.Storage = &StorageService{c: c}
	c.Permission = &PermissionService{c: c}
	c.ImageBed = &ImageBedService{c: c}
	return c
}

// WithToken creates a lightweight, request-scoped client that uses the given access token.
// Used by business services to act on behalf of a specific user.
// The returned client shares the HTTP client and base URL, but does NOT auto-refresh.
func (c *Client) WithToken(accessToken string) *Client {
	scoped := &Client{
		baseURL:     c.baseURL,
		httpClient:  c.httpClient,
		accessToken: accessToken,
		expiresAt:   time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC), // never auto-refresh
	}
	scoped.Auth = &AuthService{c: scoped}
	scoped.Storage = &StorageService{c: scoped}
	scoped.Permission = &PermissionService{c: scoped}
	scoped.ImageBed = &ImageBedService{c: scoped}
	return scoped
}

// SetTokens manually sets the token pair (useful when restoring from persistence).
func (c *Client) SetTokens(access, refresh string, expiresIn int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.accessToken = access
	c.refreshToken = refresh
	c.expiresAt = time.Now().Add(time.Duration(expiresIn) * time.Second)
}

// AccessToken returns the current access token.
func (c *Client) AccessToken() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.accessToken
}

// GetBaseURL returns the base URL of the platform.
func (c *Client) GetBaseURL() string {
	return c.baseURL
}

// APIError represents an error response from the server.
type APIError struct {
	StatusCode int
	Message    string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("api error %d: %s", e.StatusCode, e.Message)
}

// --- internal HTTP helpers ---

func (c *Client) doJSON(method, path string, body, result any, auth bool) error {
	if auth {
		if err := c.ensureToken(); err != nil {
			return err
		}
	}

	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("sdk: marshal request: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, c.baseURL+path, bodyReader)
	if err != nil {
		return fmt.Errorf("sdk: create request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if auth {
		c.mu.RLock()
		req.Header.Set("Authorization", "Bearer "+c.accessToken)
		c.mu.RUnlock()
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("sdk: http request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return parseErrorResponse(resp)
	}

	if result != nil {
		if err := json.NewDecoder(resp.Body).Decode(result); err != nil {
			return fmt.Errorf("sdk: decode response: %w", err)
		}
	}
	return nil
}

// doRaw performs an HTTP request and returns the raw response (caller must close body).
func (c *Client) doRaw(method, path string, auth bool) (*http.Response, error) {
	if auth {
		if err := c.ensureToken(); err != nil {
			return nil, err
		}
	}

	req, err := http.NewRequest(method, c.baseURL+path, nil)
	if err != nil {
		return nil, fmt.Errorf("sdk: create request: %w", err)
	}
	if auth {
		c.mu.RLock()
		req.Header.Set("Authorization", "Bearer "+c.accessToken)
		c.mu.RUnlock()
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sdk: http request: %w", err)
	}
	if resp.StatusCode >= 400 {
		defer resp.Body.Close()
		return nil, parseErrorResponse(resp)
	}
	return resp, nil
}

func (c *Client) ensureToken() error {
	c.mu.RLock()
	expired := c.accessToken == "" || time.Now().After(c.expiresAt.Add(-10*time.Second))
	refresh := c.refreshToken
	c.mu.RUnlock()

	if !expired {
		return nil
	}
	if refresh == "" {
		return &APIError{StatusCode: 401, Message: "not authenticated, call Login first"}
	}

	// Auto-refresh
	var tokens TokenPair
	err := c.doJSON(http.MethodPost, "/auth/refresh", map[string]string{
		"refresh_token": refresh,
	}, &tokens, false)
	if err != nil {
		return fmt.Errorf("sdk: auto-refresh failed: %w", err)
	}

	c.mu.Lock()
	c.accessToken = tokens.AccessToken
	c.refreshToken = tokens.RefreshToken
	c.expiresAt = time.Now().Add(time.Duration(tokens.ExpiresIn) * time.Second)
	c.mu.Unlock()

	return nil
}

func parseErrorResponse(resp *http.Response) error {
	var body struct {
		Error string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return &APIError{StatusCode: resp.StatusCode, Message: resp.Status}
	}
	msg := body.Error
	if msg == "" {
		msg = resp.Status
	}
	return &APIError{StatusCode: resp.StatusCode, Message: msg}
}

func decodeJSON(r io.Reader, v any) error {
	if err := json.NewDecoder(r).Decode(v); err != nil {
		return fmt.Errorf("sdk: decode response: %w", err)
	}
	return nil
}
