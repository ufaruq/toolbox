package ownerlogin

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ufaruq/toolbox/internal/security"
	"github.com/ufaruq/toolbox/internal/testutil/oidcidp"
)

func providerConfig(idp *oidcidp.Server) ProviderConfig {
	return ProviderConfig{Issuer: idp.Issuer, ClientID: idp.ClientID, ClientSecret: idp.ClientSecret, RedirectURI: "http://127.0.0.1:8080/auth/oidc/callback"}
}

func TestOIDCProviderValidation(t *testing.T) {
	tests := []struct {
		name      string
		claims    map[string]any
		configure func(*oidcidp.Server)
		valid     bool
	}{
		{name: "valid", valid: true},
		{name: "wrong issuer", claims: map[string]any{"iss": "https://other.example"}},
		{name: "wrong audience", claims: map[string]any{"aud": "other-client"}},
		{name: "wrong nonce", claims: map[string]any{"nonce": "wrong"}},
		{name: "missing nonce", claims: map[string]any{"nonce": nil}},
		{name: "wrong azp", claims: map[string]any{"azp": "other-client"}},
		{name: "multiple audiences no azp", claims: map[string]any{"aud": []string{"synthetic-client", "other"}}},
		{name: "multiple audiences correct azp", claims: map[string]any{"aud": []string{"synthetic-client", "other"}, "azp": "synthetic-client"}, valid: true},
		{name: "missing subject", claims: map[string]any{"sub": nil}},
		{name: "case alias subject", claims: map[string]any{"sub": nil, "SUB": "alias-owner"}},
		{name: "case alias audience", claims: map[string]any{"aud": nil, "AUD": "synthetic-toolbox-client"}},
		{name: "case alias nonce", claims: map[string]any{"nonce": nil, "NONCE": "synthetic-nonce"}},
		{name: "case alias issuer", configure: func(s *oidcidp.Server) { s.SetClaims(map[string]any{"iss": nil, "ISS": s.Issuer}) }},
		{name: "empty subject", claims: map[string]any{"sub": ""}},
		{name: "oversized subject", claims: map[string]any{"sub": strings.Repeat("s", 256)}},
		{name: "control subject", claims: map[string]any{"sub": "owner\nadmin"}},
		{name: "unicode control subject", claims: map[string]any{"sub": "owner\u0085admin"}},
		{name: "expired", claims: map[string]any{"exp": time.Now().Add(-time.Minute).Unix()}},
		{name: "missing expiry", claims: map[string]any{"exp": nil}},
		{name: "not yet valid", claims: map[string]any{"nbf": time.Now().Add(time.Minute).Unix()}},
		{name: "past not before", claims: map[string]any{"nbf": time.Now().Add(-time.Minute).Unix()}, valid: true},
		{name: "invalid not before type", claims: map[string]any{"nbf": "tomorrow"}},
		{name: "missing iat", claims: map[string]any{"iat": nil}},
		{name: "issuance clock allowance", claims: map[string]any{"iat": time.Now().Add(30 * time.Second).Unix()}, valid: true},
		{name: "future iat", claims: map[string]any{"iat": time.Now().Add(2 * time.Minute).Unix()}},
		{name: "invalid signature", configure: func(s *oidcidp.Server) { s.SetInvalidSignature(true) }},
		{name: "invalid algorithm", configure: func(s *oidcidp.Server) { s.SetSigningAlgorithm("HS256") }},
		{name: "unsigned algorithm", configure: func(s *oidcidp.Server) { s.SetSigningAlgorithm("none") }},
		{name: "missing ID token", configure: func(s *oidcidp.Server) { s.SetTokenResponse(200, `{"access_token":"synthetic","token_type":"Bearer"}`) }},
		{name: "malformed response", configure: func(s *oidcidp.Server) { s.SetTokenResponse(200, `{"id_token":`) }},
		{name: "rejected client authentication", configure: func(s *oidcidp.Server) {
			s.SetTokenResponse(401, `{"error":"invalid_client","error_description":"synthetic private provider detail"}`)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idp := oidcidp.New(t)
			// Keep the audience assertions independent of the fixture's client ID.
			if audiences, ok := tt.claims["aud"].([]string); ok {
				audiences = append([]string(nil), audiences...)
				audiences[0] = idp.ClientID
				tt.claims["aud"] = audiences
			}
			if azp, ok := tt.claims["azp"].(string); ok && azp == "synthetic-client" {
				tt.claims["azp"] = idp.ClientID
			}
			idp.SetClaims(tt.claims)
			if tt.configure != nil {
				tt.configure(idp)
			}
			p, err := NewProvider(context.Background(), providerConfig(idp), idp.TLSClient())
			if err != nil {
				t.Fatal(err)
			}
			const nonce, verifier = "synthetic-nonce", "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"
			code := idp.Authorize(t, nonce, verifier)
			got, err := p.Exchange(context.Background(), code, verifier, security.Hash(nonce))
			if tt.valid {
				if err != nil || got != (Identity{Issuer: idp.Issuer, Subject: "synthetic-owner"}) {
					t.Fatalf("identity = %#v, error = %v", got, err)
				}
			} else if err == nil {
				t.Fatalf("accepted invalid identity: %#v", got)
			}
			if idp.ExchangeCount() != 1 {
				t.Fatalf("exchanges = %d, want one", idp.ExchangeCount())
			}
			if err != nil && strings.Contains(err.Error(), "synthetic private provider detail") {
				t.Fatal("provider error detail leaked")
			}
		})
	}
}

func TestOIDCProviderHTTPBoundaries(t *testing.T) {
	for _, path := range []string{"/.well-known/openid-configuration", "/token", "/jwks"} {
		t.Run("redirect "+path, func(t *testing.T) {
			idp := oidcidp.New(t)
			idp.SetRedirect(path, idp.Issuer+"/redirected")
			client := idp.TLSClient()
			base := client.Transport
			var redirected int
			client.Transport = providerRoundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.URL.Path == "/redirected" {
					redirected++
				}
				return base.RoundTrip(r)
			})
			p, err := NewProvider(context.Background(), providerConfig(idp), client)
			if err == nil {
				const nonce, verifier = "nonce", "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"
				_, err = p.Exchange(context.Background(), idp.Authorize(t, nonce, verifier), verifier, security.Hash(nonce))
			} else if path != "/.well-known/openid-configuration" {
				t.Fatal(err)
			}
			if err == nil {
				t.Fatal("accepted redirect")
			}
			if redirected != 0 {
				t.Fatal("followed redirect")
			}
			if path != "/.well-known/openid-configuration" && idp.ExchangeCount() != 1 {
				t.Fatal("retried exchange")
			}
		})
		t.Run("oversized "+path, func(t *testing.T) {
			idp := oidcidp.New(t)
			client := idp.TLSClient()
			base := client.Transport
			client.Transport = providerRoundTripFunc(func(r *http.Request) (*http.Response, error) {
				response, err := base.RoundTrip(r)
				if err == nil && r.URL.Path == path {
					body, readErr := io.ReadAll(response.Body)
					response.Body.Close()
					if readErr != nil {
						return nil, readErr
					}
					// A valid JSON prefix plus padding detects silent truncation.
					response.Body = io.NopCloser(strings.NewReader(string(body) + strings.Repeat(" ", 1<<20)))
					response.ContentLength = -1
				}
				return response, err
			})
			p, err := NewProvider(context.Background(), providerConfig(idp), client)
			if err == nil {
				const nonce, verifier = "nonce", "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"
				_, err = p.Exchange(context.Background(), idp.Authorize(t, nonce, verifier), verifier, security.Hash(nonce))
			} else if path != "/.well-known/openid-configuration" {
				t.Fatal(err)
			}
			if err == nil {
				t.Fatal("accepted oversized response")
			}
		})
	}
	t.Run("in flight cancellation", func(t *testing.T) {
		idp := oidcidp.New(t)
		p, err := NewProvider(context.Background(), providerConfig(idp), idp.TLSClient())
		if err != nil {
			t.Fatal(err)
		}
		entered, release := idp.BlockExchange()
		defer release()
		const nonce, verifier = "nonce", "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"
		code := idp.Authorize(t, nonce, verifier)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := make(chan error, 1)
		go func() { _, err := p.Exchange(ctx, code, verifier, security.Hash(nonce)); done <- err }()
		select {
		case <-entered:
		case <-time.After(3 * time.Second):
			t.Fatal("exchange did not enter provider")
		}
		cancel()
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("accepted cancelled exchange")
			}
		case <-time.After(3 * time.Second):
			t.Fatal("exchange ignored cancellation")
		}
		if idp.ExchangeCount() != 1 {
			t.Fatal("retried cancelled exchange")
		}
	})
	t.Run("application lifetime", func(t *testing.T) {
		idp := oidcidp.New(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		p, err := NewProvider(ctx, providerConfig(idp), idp.TLSClient())
		if err != nil {
			t.Fatal(err)
		}
		cancel()
		const nonce, verifier = "nonce", "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"
		if _, err = p.Exchange(context.Background(), idp.Authorize(t, nonce, verifier), verifier, security.Hash(nonce)); err == nil {
			t.Fatal("continued after application shutdown")
		}
		if idp.ExchangeCount() != 0 {
			t.Fatal("sent request after shutdown")
		}
	})
}

type providerRoundTripFunc func(*http.Request) (*http.Response, error)

func (f providerRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestOIDCProviderTransport(t *testing.T) {
	t.Run("authorization parameters", func(t *testing.T) {
		idp := oidcidp.New(t)
		cfg := providerConfig(idp)
		p, err := NewProvider(context.Background(), cfg, idp.TLSClient())
		if err != nil {
			t.Fatal(err)
		}
		hash := sha256.Sum256([]byte("synthetic-verifier"))
		challenge := base64.RawURLEncoding.EncodeToString(hash[:])
		raw, err := p.AuthorizationURL("synthetic-state", "synthetic-nonce", challenge)
		if err != nil {
			t.Fatal(err)
		}
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		want := url.Values{"response_type": {"code"}, "client_id": {cfg.ClientID}, "redirect_uri": {cfg.RedirectURI}, "scope": {"openid"}, "state": {"synthetic-state"}, "nonce": {"synthetic-nonce"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}}
		if u.Scheme+"://"+u.Host != idp.Issuer || u.Path != "/authorize" || u.Query().Encode() != want.Encode() {
			t.Fatalf("unexpected authorization parameters: %v", u.Query())
		}
		if strings.Contains(raw, cfg.ClientSecret) {
			t.Fatal("client secret in authorization URL")
		}
	})
	for _, tt := range []struct {
		name      string
		overrides map[string]any
	}{
		{"issuer mismatch", map[string]any{"issuer": "https://other.example"}},
		{"case alias issuer", map[string]any{"issuer": nil, "ISSUER": "synthetic-issuer"}},
		{"insecure authorization endpoint", map[string]any{"authorization_endpoint": "http://127.0.0.1/authorize"}},
		{"cross origin token endpoint", map[string]any{"token_endpoint": "https://other.example/token"}},
		{"cross origin JWKS", map[string]any{"jwks_uri": "https://other.example/jwks"}},
		{"credentialed endpoint", map[string]any{"token_endpoint": "https://user:password@other.example/token"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			idp := oidcidp.New(t)
			if tt.overrides["ISSUER"] == "synthetic-issuer" {
				tt.overrides["ISSUER"] = idp.Issuer
			}
			idp.SetDiscovery(tt.overrides)
			if _, err := NewProvider(context.Background(), providerConfig(idp), idp.TLSClient()); err == nil {
				t.Fatal("accepted invalid discovery")
			}
		})
	}
	t.Run("discovery redirect", func(t *testing.T) {
		idp := oidcidp.New(t)
		idp.SetRedirect("/.well-known/openid-configuration", idp.Issuer+"/redirected")
		if _, err := NewProvider(context.Background(), providerConfig(idp), idp.TLSClient()); err == nil {
			t.Fatal("followed discovery redirect")
		}
	})
	t.Run("oversized discovery", func(t *testing.T) {
		idp := oidcidp.New(t)
		client := idp.TLSClient()
		client.Transport = providerRoundTripFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(strings.Repeat(" ", 1<<20) + `{}`)), ContentLength: -1, Request: r}, nil
		})
		if _, err := NewProvider(context.Background(), providerConfig(idp), client); err == nil {
			t.Fatal("accepted oversized discovery")
		}
	})
	t.Run("cancelled caller", func(t *testing.T) {
		idp := oidcidp.New(t)
		p, err := NewProvider(context.Background(), providerConfig(idp), idp.TLSClient())
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err = p.Exchange(ctx, "synthetic-code", "synthetic-verifier", security.Hash("nonce")); err == nil {
			t.Fatal("ignored cancellation")
		}
		if idp.ExchangeCount() != 0 {
			t.Fatal("sent cancelled exchange")
		}
	})
	t.Run("wrong PKCE verifier", func(t *testing.T) {
		idp := oidcidp.New(t)
		p, err := NewProvider(context.Background(), providerConfig(idp), idp.TLSClient())
		if err != nil {
			t.Fatal(err)
		}
		code := idp.Authorize(t, "nonce", "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG")
		if _, err = p.Exchange(context.Background(), code, strings.Repeat("z", 43), security.Hash("nonce")); err == nil {
			t.Fatal("accepted wrong PKCE verifier")
		}
		if idp.ExchangeCount() != 1 {
			t.Fatal("retried rejected exchange")
		}
	})
}
