package sdk

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestServiceTokenHeaderIsSent(t *testing.T) {
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.Header.Get(ServiceTokenHeader))
		json.NewEncoder(w).Encode(map[string]any{"allowed": true})
	}))
	defer srv.Close()

	client := New(&Config{BaseURL: srv.URL, ServiceToken: "s3cr3t"})
	if _, err := client.Permission.CheckPermission(1, "blog.comment", "create"); err != nil {
		t.Fatalf("CheckPermission: %v", err)
	}
	// Scoped clients inherit the service token.
	if _, err := client.WithToken("user-jwt").Permission.CheckPermission(1, "blog.comment", "create"); err != nil {
		t.Fatalf("scoped CheckPermission: %v", err)
	}
	if len(got) != 2 || got[0] != "s3cr3t" || got[1] != "s3cr3t" {
		t.Fatalf("expected X-Service-Token on both requests, got %v", got)
	}

	// No token configured → header absent, not empty-string.
	got = nil
	plain := New(&Config{BaseURL: srv.URL})
	if _, err := plain.Permission.CheckPermission(1, "x", "y"); err != nil {
		t.Fatalf("CheckPermission: %v", err)
	}
	if len(got) != 1 || got[0] != "" {
		t.Fatalf("expected no X-Service-Token, got %v", got)
	}
}

func TestLogin_NoTokensIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Root bootstrap response: 200 without any token fields.
		json.NewEncoder(w).Encode(map[string]any{"require_otp": true, "message": "OTP printed to server console"})
	}))
	defer srv.Close()

	client := New(&Config{BaseURL: srv.URL})
	tokens, err := client.Auth.Login("root", "whatever")
	if err == nil {
		t.Fatalf("expected error, got tokens %+v", tokens)
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected *APIError 401, got %v", err)
	}
	if client.AccessToken() != "" {
		t.Fatalf("client must not store empty tokens, got %q", client.AccessToken())
	}
}

func TestOAuthAuthorize_EncodesRedirectURIAndProvider(t *testing.T) {
	const redirect = "https://blog.example.com/oauth/callback?next=/post/1&tab=a b"
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.URL.Path+" | "+r.URL.Query().Get("redirect_uri")+" | "+r.URL.Query().Get("scopes"))
		json.NewEncoder(w).Encode(map[string]any{"auth_url": "https://provider/authorize"})
	}))
	defer srv.Close()

	client := New(&Config{BaseURL: srv.URL})
	if _, err := client.Auth.OAuthAuthorize("github", redirect); err != nil {
		t.Fatalf("OAuthAuthorize: %v", err)
	}
	if _, err := client.WithToken("jwt").Auth.OAuthBindAuthorize("discord", redirect, "guilds", "guilds.members.read"); err != nil {
		t.Fatalf("OAuthBindAuthorize: %v", err)
	}

	want := []string{
		"/auth/oauth/github | " + redirect + " | ",
		"/auth/oauth/discord/bind | " + redirect + " | guilds guilds.members.read",
	}
	if len(seen) != len(want) {
		t.Fatalf("expected %d requests, got %d: %v", len(want), len(seen), seen)
	}
	for i := range want {
		if seen[i] != want[i] {
			t.Fatalf("request %d:\n want %q\n got  %q", i, want[i], seen[i])
		}
	}
}

func TestListPolicies_EscapesRole(t *testing.T) {
	var role string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		role = r.URL.Query().Get("role")
		json.NewEncoder(w).Encode(map[string]any{"policies": []any{}})
	}))
	defer srv.Close()

	client := New(&Config{BaseURL: srv.URL})
	client.SetTokens("jwt", "refresh", 3600)
	if _, err := client.Permission.ListPolicies("odd role&x=y"); err != nil {
		t.Fatalf("ListPolicies: %v", err)
	}
	if role != "odd role&x=y" {
		t.Fatalf("role not round-tripped, got %q", role)
	}
}
