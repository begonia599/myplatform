package auth

import (
	"errors"
	"testing"
)

func newTestOAuthService(allowed ...string) *OAuthService {
	return &OAuthService{cfg: &AuthConfig{OAuth: OAuthConfig{AllowedRedirectHosts: allowed}}}
}

func TestValidateRedirectURI(t *testing.T) {
	svc := newTestOAuthService("blog.example.com", " Localhost:5173 ")

	cases := []struct {
		name string
		uri  string
		ok   bool
	}{
		{"exact host", "https://blog.example.com/oauth/callback", true},
		{"case-insensitive host, with query", "https://BLOG.Example.com/cb?next=/a&b=c", true},
		{"http allowed", "http://blog.example.com/cb", true},
		{"host:port entry matches host:port", "http://localhost:5173/cb", true},
		{"host:port entry does not match other port", "http://localhost:9999/cb", false},
		{"host:port entry does not match bare host", "http://localhost/cb", false},
		{"other host", "https://evil.example/cb", false},
		{"suffix attack", "https://blog.example.com.evil.example/cb", false},
		{"prefix attack", "https://evil-blog.example.com/cb", false},
		{"userinfo trick", "https://blog.example.com@evil.example/cb", false},
		{"scheme-relative", "//evil.example/cb", false},
		{"javascript scheme", "javascript:alert(1)", false},
		{"data scheme", "data:text/html,hi", false},
		{"empty", "", false},
		{"garbage", "not a url", false},
		{"path only", "/relative/path", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := svc.validateRedirectURI(tc.uri)
			if tc.ok && err != nil {
				t.Fatalf("expected %q to be allowed, got %v", tc.uri, err)
			}
			if !tc.ok && !errors.Is(err, ErrRedirectNotAllowed) {
				t.Fatalf("expected %q to be rejected with ErrRedirectNotAllowed, got %v", tc.uri, err)
			}
		})
	}
}

func TestValidateRedirectURI_EmptyAllowlistFailsClosed(t *testing.T) {
	for _, svc := range []*OAuthService{
		newTestOAuthService(),
		newTestOAuthService("", "  "), // only blank entries → still nothing usable
	} {
		err := svc.validateRedirectURI("https://blog.example.com/cb")
		if svc.cfg.OAuth.AllowedRedirectHosts == nil {
			if !errors.Is(err, ErrRedirectAllowlistEmpty) {
				t.Fatalf("nil allowlist: expected ErrRedirectAllowlistEmpty, got %v", err)
			}
		} else if !errors.Is(err, ErrRedirectNotAllowed) {
			t.Fatalf("blank-only allowlist: expected ErrRedirectNotAllowed, got %v", err)
		}
	}
}

func TestAuthorize_RejectsDisallowedRedirectBeforeStoringState(t *testing.T) {
	svc := newTestOAuthService("blog.example.com")

	if _, err := svc.authorize("github", "https://evil.example/cb", oauthModeLogin, 0); !errors.Is(err, ErrRedirectNotAllowed) {
		t.Fatalf("expected ErrRedirectNotAllowed, got %v", err)
	}
	stored := 0
	svc.states.Range(func(_, _ any) bool { stored++; return true })
	if stored != 0 {
		t.Fatalf("rejected authorize must not store oauth state, found %d", stored)
	}

	// Allowed host still works and stores exactly one state.
	if _, err := svc.authorize("github", "https://blog.example.com/cb", oauthModeLogin, 0); err != nil {
		t.Fatalf("expected allowed redirect to succeed, got %v", err)
	}
	svc.states.Range(func(_, _ any) bool { stored++; return true })
	if stored != 1 {
		t.Fatalf("expected exactly one stored state, found %d", stored)
	}

	// Redirect check runs before provider check: unsupported provider with a
	// bad redirect is still reported as a redirect problem.
	if _, err := svc.authorize("nope", "https://evil.example/cb", oauthModeLogin, 0); !errors.Is(err, ErrRedirectNotAllowed) {
		t.Fatalf("expected ErrRedirectNotAllowed, got %v", err)
	}
}
