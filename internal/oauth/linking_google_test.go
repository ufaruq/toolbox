package oauth

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ufaruq/toolbox/internal/domain"
	"github.com/ufaruq/toolbox/internal/security"
	"github.com/ufaruq/toolbox/internal/tokens"
)

func corporateGoogle(t *testing.T) *GoogleProvider {
	t.Helper()
	p, err := NewGoogleProvider(GoogleConfig{ClientID: "test-client", ClientSecret: "secret", CallbackURL: "https://toolbox.example/oauth/callback", PKCEValidated: true, IdentityScopes: true})
	if err != nil {
		t.Fatal(err)
	}
	p.now = func() time.Time { return time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC) }
	return p
}

func TestGoogleIdentityScopeModeIsExplicitAndExact(t *testing.T) {
	for _, identityMode := range []bool{false, true} {
		p := testProvider(t)
		if identityMode {
			p = corporateGoogle(t)
		}
		expected := "openid " + domain.DriveScope
		if identityMode {
			expected = "openid email " + domain.DriveScope
		}
		raw, err := p.AuthorizationURL(security.ID()+"."+security.Random(), security.Random(), security.Random())
		if err != nil {
			t.Fatal(err)
		}
		u, _ := url.Parse(raw)
		if u.Query().Get("scope") != expected || strings.Join(p.ExpectedScopes(), " ") != expected {
			t.Fatalf("wrong scope contract: %s", u.Query().Get("scope"))
		}
		// Callers cannot mutate the provider's contract.
		scopes := p.ExpectedScopes()
		scopes[0] = "https://www.googleapis.com/auth/drive"
		if strings.Join(p.ExpectedScopes(), " ") != expected {
			t.Fatal("mutable scope contract")
		}
		for _, scope := range []string{"openid " + domain.DriveScope, "openid email " + domain.DriveScope, "openid email profile " + domain.DriveScope, "openid email email " + domain.DriveScope} {
			nonce := security.Random()
			claims := testClaims(p, nonce)
			claims["email"], claims["email_verified"], claims["hd"] = "ufaruq@company.com", true, "company.com"
			token := signTestToken(t, map[string]any{"alg": "RS256", "kid": "test-key"}, claims)
			p.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.URL.String() == googleJWKSEndpoint {
					return jsonHTTP(200, testJWKS(t)), nil
				}
				return jsonHTTP(200, map[string]any{"access_token": "known-access", "refresh_token": "known-refresh", "token_type": "Bearer", "expires_in": 3600, "scope": scope, "id_token": token}), nil
			})
			got, err := p.Exchange(context.Background(), "code", security.Random(), security.Hash(nonce))
			if (err == nil) != (scope == expected) {
				t.Fatalf("mode %v accepted wrong contract %q: %v", identityMode, scope, err)
			}
			if err == nil && (got.Subject != "google-subject" || got.Identity.Issuer != "https://accounts.google.com" || got.Identity.Email != "ufaruq@company.com" || !got.Identity.EmailVerified || got.Identity.HostedDomain != "company.com") {
				t.Fatalf("verified identity missing: %+v", got.Identity)
			}
			if err != nil && (got.AccessToken != "known-access" || got.RefreshToken != "known-refresh") {
				t.Fatal("scope rejection discarded cleanup material")
			}
		}
	}
}

func TestGoogleIdentityModeRejectsMalformedSignedClaims(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(map[string]any)
	}{
		{"email object", func(c map[string]any) { c["email"] = map[string]any{"value": "ufaruq@company.com"} }},
		{"email null", func(c map[string]any) { c["email"] = nil }},
		{"verification string", func(c map[string]any) { c["email_verified"] = "true" }},
		{"verification number", func(c map[string]any) { c["email_verified"] = 1 }},
		{"verification null", func(c map[string]any) { c["email_verified"] = nil }},
		{"domain array", func(c map[string]any) { c["hd"] = []string{"company.com"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := corporateGoogle(t)
			nonce := security.Random()
			claims := testClaims(p, nonce)
			claims["email"], claims["email_verified"], claims["hd"] = "ufaruq@company.com", true, "company.com"
			tc.edit(claims)
			token := signTestToken(t, map[string]any{"alg": "RS256", "kid": "test-key"}, claims)
			p.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.URL.String() == googleJWKSEndpoint {
					return jsonHTTP(200, testJWKS(t)), nil
				}
				return jsonHTTP(200, map[string]any{"access_token": "known-access", "refresh_token": "known-refresh", "token_type": "Bearer", "expires_in": 3600, "scope": "openid email " + domain.DriveScope, "id_token": token}), nil
			})
			got, err := p.Exchange(context.Background(), "code", security.Random(), security.Hash(nonce))
			if !errors.Is(err, ErrIdentity) || got.RefreshToken != "known-refresh" {
				t.Fatal("malformed identity accepted or cleanup lost", err)
			}
		})
	}
}

func TestGoogleIdentityModeRefreshKeepsExactScopeContract(t *testing.T) {
	p := corporateGoogle(t)
	for _, scope := range []string{"openid email " + domain.DriveScope, "openid " + domain.DriveScope, "openid email profile " + domain.DriveScope} {
		p.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
			return jsonHTTP(200, map[string]any{"access_token": "next-access", "refresh_token": "next-refresh", "token_type": "Bearer", "expires_in": 3600, "scope": scope}), nil
		})
		got, err := p.Refresh(context.Background(), "refresh")
		if scope == "openid email "+domain.DriveScope {
			if err != nil {
				t.Fatal(err)
			}
		} else if !errors.Is(err, tokens.ErrReauth) || got.RefreshToken != "next-refresh" {
			t.Fatal("refresh scope mismatch accepted or credential lost", err)
		}
	}
}
