package oauth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ufaruq/toolbox/internal/domain"
	"github.com/ufaruq/toolbox/internal/security"
	"github.com/ufaruq/toolbox/internal/tokens"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

var testKeyOnce sync.Once
var testPrivateKey *rsa.PrivateKey

func signingTestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	var err error
	testKeyOnce.Do(func() { testPrivateKey, err = rsa.GenerateKey(rand.Reader, 2048) })
	if err != nil || testPrivateKey == nil {
		t.Fatal("test signing key", err)
	}
	return testPrivateKey
}
func testProvider(t *testing.T) *GoogleProvider {
	t.Helper()
	p, err := NewGoogleProvider(GoogleConfig{ClientID: "test-client", ClientSecret: "CANARY-client-secret", CallbackURL: "https://toolbox.example/oauth/callback", PKCEValidated: true})
	if err != nil {
		t.Fatal(err)
	}
	p.now = func() time.Time { return time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC) }
	return p
}
func testClaims(p *GoogleProvider, nonce string) map[string]any {
	return map[string]any{"iss": "https://accounts.google.com", "aud": p.clientID, "sub": "google-subject", "iat": p.now().Unix(), "exp": p.now().Add(time.Hour).Unix(), "nonce": nonce}
}
func signTestToken(t *testing.T, header, claims map[string]any) string {
	t.Helper()
	hb, _ := json.Marshal(header)
	cb, _ := json.Marshal(claims)
	message := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(cb)
	digest := sha256.Sum256([]byte(message))
	signature, err := rsa.SignPKCS1v15(rand.Reader, signingTestKey(t), crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return message + "." + base64.RawURLEncoding.EncodeToString(signature)
}
func jsonHTTP(status int, value any) *http.Response {
	body, _ := json.Marshal(value)
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(string(body)))}
}
func testJWKS(t *testing.T) any {
	key := signingTestKey(t)
	return map[string]any{"keys": []any{map[string]any{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "test-key", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": "AQAB"}}}
}
func TestGoogleRequiresValidatedPKCE(t *testing.T) {
	config := GoogleConfig{ClientID: "client", ClientSecret: "secret", CallbackURL: "https://toolbox.example/oauth/callback"}
	if _, err := NewGoogleProvider(config); !errors.Is(err, ErrConfiguration) {
		t.Fatal("live Google without PKCE gate accepted")
	}
	config.PKCEValidated = true
	for _, callback := range []string{"http://toolbox.example/oauth/callback", "https://toolbox.example/oauth/callback?return=https://evil.example", "https://user@toolbox.example/oauth/callback", "https://toolbox.example/elsewhere", "https://toolbox.example/oauth/callback#fragment"} {
		config.CallbackURL = callback
		if _, err := NewGoogleProvider(config); !errors.Is(err, ErrConfiguration) {
			t.Fatal("unsafe callback accepted", callback)
		}
	}
	config.CallbackURL = "http://localhost:8080/oauth/callback"
	config.AllowLoopbackHTTP = true
	if _, err := NewGoogleProvider(config); err != nil {
		t.Fatal("explicit loopback rejected", err)
	}
}
func TestGoogleAuthorizationParametersFixed(t *testing.T) {
	p := testProvider(t)
	verifier := security.Random()
	state := security.ID() + "." + security.Random()
	nonce := security.Random()
	raw, err := p.AuthorizationURL(state, nonce, challengeFor(verifier))
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := url.Parse(raw)
	q := parsed.Query()
	if parsed.Scheme+"://"+parsed.Host+parsed.Path != googleAuthorizationEndpoint || q.Get("redirect_uri") != p.callbackURL || q.Get("scope") != "openid "+domain.DriveScope || q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") != challengeFor(verifier) || q.Get("nonce") != nonce || q.Get("state") != state || q.Get("access_type") != "offline" || q.Get("include_granted_scopes") != "false" {
		t.Fatal("authorization request changed")
	}
	if q.Get("client_secret") != "" {
		t.Fatal("client secret in authorization URL")
	}
}
func TestGoogleExchangeValidatesFixedJWKSAndBindsCode(t *testing.T) {
	p := testProvider(t)
	nonce := security.Random()
	verifier := security.Random()
	tokenCalls, keyCalls := 0, 0
	idToken := signTestToken(t, map[string]any{"alg": "RS256", "kid": "test-key", "typ": "JWT"}, testClaims(p, nonce))
	p.client.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.String() == googleTokenEndpoint {
			tokenCalls++
			if request.Method != http.MethodPost || request.ParseForm() != nil || request.PostForm.Get("code_verifier") != verifier || request.PostForm.Get("redirect_uri") != p.callbackURL || request.PostForm.Get("client_secret") != p.clientSecret || request.PostForm.Get("grant_type") != "authorization_code" || len(request.URL.Query()) != 0 {
				t.Fatal("unbound token exchange")
			}
			return jsonHTTP(200, map[string]any{"access_token": "CANARY-access", "refresh_token": "CANARY-refresh", "token_type": "Bearer", "expires_in": 3600, "scope": domain.DriveScope + " openid", "id_token": idToken}), nil
		}
		if request.URL.String() == googleJWKSEndpoint {
			keyCalls++
			if request.Method != http.MethodGet {
				t.Fatal("JWKS method")
			}
			return jsonHTTP(200, testJWKS(t)), nil
		}
		t.Fatal("unexpected provider URL", request.URL)
		return nil, ErrProvider
	})
	result, err := p.Exchange(context.Background(), "CANARY-code", verifier, security.Hash(nonce))
	if err != nil {
		t.Fatal(err)
	}
	if result.Subject != "google-subject" || result.ClientID != p.clientID || tokenCalls != 1 || keyCalls != 1 || !result.Expiry.Equal(p.now().Add(time.Hour)) {
		t.Fatal("invalid exchange result")
	}
	if _, err = p.verifyIDToken(context.Background(), idToken, security.Hash(nonce)); err != nil || keyCalls != 1 {
		t.Fatal("valid keys not cached", err)
	}
}
func TestGoogleRejectsInvalidSignedIdentity(t *testing.T) {
	cases := []struct {
		name string
		edit func(map[string]any)
	}{
		{"wrong issuer", func(c map[string]any) { c["iss"] = "https://attacker.example" }},
		{"wrong client", func(c map[string]any) { c["aud"] = "another-client" }},
		{"wrong nonce", func(c map[string]any) { c["nonce"] = "different" }},
		{"expired", func(c map[string]any) { c["exp"] = time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC).Unix() }},
		{"missing subject", func(c map[string]any) { delete(c, "sub") }},
		{"malformed subject", func(c map[string]any) { c["sub"] = "user\nname" }},
		{"wrong presenter", func(c map[string]any) { c["azp"] = "another-client" }},
		{"multiple audiences without presenter", func(c map[string]any) { c["aud"] = []string{"test-client", "second-client"} }},
		{"future issued", func(c map[string]any) { c["iat"] = time.Date(2026, 10, 18, 0, 2, 0, 0, time.UTC).Unix() }},
		{"missing issue time", func(c map[string]any) { delete(c, "iat") }},
		{"null subject", func(c map[string]any) { c["sub"] = nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := testProvider(t)
			nonce := security.Random()
			claims := testClaims(p, nonce)
			tc.edit(claims)
			token := signTestToken(t, map[string]any{"alg": "RS256", "kid": "test-key"}, claims)
			p.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.URL.String() != googleJWKSEndpoint {
					t.Fatal("untrusted key URL")
				}
				return jsonHTTP(200, testJWKS(t)), nil
			})
			if _, err := p.verifyIDToken(context.Background(), token, security.Hash(nonce)); !errors.Is(err, ErrIdentity) {
				t.Fatal("invalid signed identity accepted", err)
			}
		})
	}
}
func TestGoogleRejectsUnsafeHeadersAndSignature(t *testing.T) {
	for _, header := range []map[string]any{{"alg": "none", "kid": "test-key"}, {"alg": "HS256", "kid": "test-key"}, {"alg": "RS256", "kid": "test-key", "jku": "http://127.0.0.1/keys"}, {"alg": "RS256", "kid": "test-key", "x5u": "https://attacker.example/keys"}, {"alg": "RS256", "kid": "test-key", "typ": "toolbox-delegation+jwt"}} {
		p := testProvider(t)
		nonce := security.Random()
		token := signTestToken(t, header, testClaims(p, nonce))
		p.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
			t.Fatal("unsafe JWT triggered key fetch")
			return nil, ErrProvider
		})
		if _, err := p.verifyIDToken(context.Background(), token, security.Hash(nonce)); !errors.Is(err, ErrIdentity) {
			t.Fatal("unsafe header accepted")
		}
	}
	p := testProvider(t)
	nonce := security.Random()
	token := signTestToken(t, map[string]any{"alg": "RS256", "kid": "test-key"}, testClaims(p, nonce))
	parts := strings.Split(token, ".")
	parts[2] = base64.RawURLEncoding.EncodeToString(make([]byte, 256))
	p.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) { return jsonHTTP(200, testJWKS(t)), nil })
	if _, err := p.verifyIDToken(context.Background(), strings.Join(parts, "."), security.Hash(nonce)); !errors.Is(err, ErrIdentity) {
		t.Fatal("bad signature accepted")
	}
}
func TestGoogleRefreshAndRevokeAreFixedAndNeverRetry(t *testing.T) {
	p := testProvider(t)
	calls := 0
	p.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != http.MethodPost || r.URL.String() != googleTokenEndpoint || r.ParseForm() != nil || r.PostForm.Get("grant_type") != "refresh_token" || r.PostForm.Get("refresh_token") != "CANARY-refresh" || r.PostForm.Get("client_secret") != p.clientSecret {
			t.Fatal("unsafe refresh request")
		}
		return jsonHTTP(200, map[string]any{"access_token": "next-access", "token_type": "Bearer", "expires_in": 3600}), nil
	})
	refreshed, err := p.Refresh(context.Background(), "CANARY-refresh")
	if err != nil || refreshed.RefreshToken != "" || len(refreshed.Scopes) != 0 || calls != 1 {
		t.Fatal("optional fields not preserved for manager", err)
	}
	p.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		return nil, errors.New("CANARY-provider-detail")
	})
	_, err = p.Refresh(context.Background(), "CANARY-refresh")
	if !errors.Is(err, tokens.ErrRefreshUncertain) || strings.Contains(err.Error(), "CANARY") || calls != 2 {
		t.Fatal("uncertain refresh retried or leaked", err)
	}
	p.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return jsonHTTP(400, map[string]any{"error": "invalid_grant", "error_description": "CANARY"}), nil
	})
	if _, err = p.Refresh(context.Background(), "CANARY-refresh"); !errors.Is(err, tokens.ErrInvalidGrant) {
		t.Fatal("invalid_grant lost", err)
	}
	p.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodPost || r.URL.String() != googleRevocationEndpoint || r.ParseForm() != nil || r.PostForm.Get("token") != "CANARY-refresh" || len(r.PostForm) != 1 {
			t.Fatal("unsafe revocation request")
		}
		return jsonHTTP(200, map[string]any{}), nil
	})
	if err := p.Revoke(context.Background(), "CANARY-refresh"); err != nil {
		t.Fatal(err)
	}
}
func TestGoogleRedirectRefused(t *testing.T) {
	p := testProvider(t)
	calls := 0
	p.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		response := jsonHTTP(http.StatusTemporaryRedirect, map[string]any{})
		response.Header.Set("Location", "https://attacker.example/token")
		return response, nil
	})
	if _, err := p.Refresh(context.Background(), "CANARY-refresh"); err == nil || calls != 1 {
		t.Fatal("provider redirect followed")
	}
}
func TestGoogleExchangeNeverOmitsPKCE(t *testing.T) {
	p := testProvider(t)
	p.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("missing verifier dispatched")
		return nil, ErrProvider
	})
	if _, err := p.Exchange(context.Background(), "code", "", security.Hash("nonce")); !errors.Is(err, ErrCallback) {
		t.Fatal("omitted verifier accepted", err)
	}
}

func TestGoogleRevocationAlreadyInvalidIsTerminalOnlyForExactError(t *testing.T) {
	for _, tc := range []struct {
		name    string
		status  int
		body    string
		success bool
	}{
		{"already invalid", 400, `{"error":"invalid_token","error_description":"expired or revoked"}`, true},
		{"invalid request", 400, `{"error":"invalid_request"}`, false},
		{"missing code", 400, `{}`, false},
		{"duplicate code", 400, `{"error":"invalid_request","error":"invalid_token"}`, false},
		{"wrong status", 500, `{"error":"invalid_token"}`, false},
		{"malformed", 400, `not JSON`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := testProvider(t)
			p.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: tc.status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(tc.body))}, nil
			})
			err := p.Revoke(context.Background(), "stored-refresh-token")
			if (err == nil) != tc.success {
				t.Fatal("incorrect terminal revocation result", err)
			}
		})
	}
}
