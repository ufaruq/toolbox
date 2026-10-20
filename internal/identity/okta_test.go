package identity

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ufaruq/toolbox/internal/security"
)

// This issuer serves real discovery, JWKS and token responses. Tests never bypass
// the maintained OIDC verifier or substitute a signature-verification mock.
type testIssuer struct {
	server        *httptest.Server
	key           *rsa.PrivateKey
	mu            sync.Mutex
	kid           string
	token         string
	tokenStatus   int
	tokenBody     string
	form          url.Values
	authorization string
	discovery     map[string]any
	jwksRequests  int
}

func newTestIssuer(t *testing.T) *testIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &testIssuer{key: key, kid: "key-1"}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration", "/oauth2/default/.well-known/openid-configuration":
			d := map[string]any{"issuer": f.server.URL, "authorization_endpoint": f.server.URL + "/authorize", "token_endpoint": f.server.URL + "/token", "jwks_uri": f.server.URL + "/keys", "response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"}, "id_token_signing_alg_values_supported": []string{"RS256", "RS512"}}
			if strings.HasPrefix(r.URL.Path, "/oauth2/default/") {
				d["issuer"] = f.server.URL + "/oauth2/default"
			}
			for k, v := range f.discovery {
				d[k] = v
			}
			json.NewEncoder(w).Encode(d)
		case "/keys":
			f.jwksRequests++
			json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{"kty": "RSA", "kid": f.kid, "use": "sig", "alg": "RS256", "n": base64.RawURLEncoding.EncodeToString(f.key.N.Bytes()), "e": "AQAB"}}})
		case "/token":
			if err := r.ParseForm(); err != nil {
				t.Error(err)
			}
			f.form = r.PostForm
			f.authorization = r.Header.Get("Authorization")
			if f.tokenStatus != 0 {
				w.WriteHeader(f.tokenStatus)
				fmt.Fprint(w, f.tokenBody)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"access_token": "must-never-be-returned", "token_type": "Bearer", "id_token": f.token})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.server.Close)
	return f
}
func (f *testIssuer) config() Config {
	return Config{Issuer: f.server.URL, Audience: "api://toolbox-mcp", OwnerClientID: "owner-client", OwnerClientSecret: "owner-secret-do-not-leak", OwnerCallbackURL: "https://toolbox.example/owner/callback", Clients: map[string]string{"agent-client": "Agent"}, AllowLoopbackHTTP: true}
}
func (f *testIssuer) claims() map[string]any {
	now := time.Now().Unix()
	return map[string]any{"iss": f.server.URL, "aud": "api://toolbox-mcp", "sub": "different-from-canonical-uid", "uid": "00uImmutable", "cid": "agent-client", "scp": []string{"openid", "mcp"}, "iat": now, "exp": now + 300}
}
func (f *testIssuer) sign(t *testing.T, c map[string]any) string {
	return f.signAlgorithm(t, c, "RS256", f.key)
}
func (f *testIssuer) signAlgorithm(t *testing.T, c map[string]any, alg string, key *rsa.PrivateKey) string {
	t.Helper()
	f.mu.Lock()
	kid := f.kid
	f.mu.Unlock()
	h, _ := json.Marshal(map[string]string{"typ": "JWT", "alg": alg, "kid": kid})
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	raw := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(raw))
	hash, digest := crypto.SHA256, sum[:]
	if alg == "RS512" {
		otherSum := sha512.Sum512([]byte(raw))
		hash, digest = crypto.SHA512, otherSum[:]
	}
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, hash, digest)
	if err != nil {
		t.Fatal(err)
	}
	return raw + "." + base64.RawURLEncoding.EncodeToString(sig)
}
func newService(t *testing.T, f *testIssuer) *Service {
	t.Helper()
	s, err := New(context.Background(), f.config())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestVerifyAccessCanonicalIdentityAndCopies(t *testing.T) {
	f := newTestIssuer(t)
	cfg := f.config()
	s, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Clients["attacker"] = "Attacker"
	published := s.Clients()
	published["attacker"] = "Attacker"
	delete(published, "agent-client")
	if len(s.Clients()) != 1 || s.Clients()["agent-client"] != "Agent" || s.Issuer() != f.server.URL {
		t.Fatal("configuration leaked mutable state")
	}
	got, err := s.VerifyAccess(context.Background(), f.sign(t, f.claims()))
	if err != nil {
		t.Fatal(err)
	}
	if got.UserID != "00uImmutable" || got.ClientID != "agent-client" || got.Issuer != f.server.URL || !got.ExpiresAt.After(time.Now()) {
		t.Fatalf("wrong identity: %#v", got)
	}
	bad := f.claims()
	bad["cid"] = "attacker"
	if _, err = s.VerifyAccess(context.Background(), f.sign(t, bad)); err == nil {
		t.Fatal("mutated config admitted client")
	}
}
func TestVerifyAccessRejectsInvalidClaims(t *testing.T) {
	f := newTestIssuer(t)
	s := newService(t, f)
	now := time.Now().Unix()
	cases := []struct {
		name   string
		key    string
		value  any
		remove bool
	}{
		{"wrong issuer", "iss", "https://attacker.example", false}, {"wrong audience", "aud", "api://other", false}, {"ID token audience", "aud", "owner-client", false}, {"mixed ID audience", "aud", []string{"api://toolbox-mcp", "owner-client"}, false},
		{"unknown client", "cid", "other", false}, {"missing client", "cid", nil, true}, {"malformed client", "cid", []string{"agent-client"}, false},
		{"missing uid", "uid", nil, true}, {"blank uid", "uid", " ", false}, {"malformed uid", "uid", 17, false},
		{"missing scope", "scp", nil, true}, {"wrong scope", "scp", []string{"openid"}, false}, {"substring scope", "scp", []string{"not-mcp"}, false}, {"malformed scope", "scp", "mcp", false},
		{"expired", "exp", now - 1, false}, {"missing expiry", "exp", nil, true}, {"malformed expiry", "exp", "tomorrow", false}, {"null expiry", "exp", nil, false},
		{"future issued", "iat", now + 120, false}, {"missing issued", "iat", nil, true}, {"zero issued", "iat", 0, false}, {"null issued", "iat", nil, false}, {"malformed issued", "iat", "today", false},
		{"future not before within OIDC skew", "nbf", now + 120, false}, {"malformed not before", "nbf", "soon", false}, {"null not before", "nbf", nil, false}, {"expiry before issued", "iat", now + 301, false},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			c := f.claims()
			if tt.remove {
				delete(c, tt.key)
			} else {
				c[tt.key] = tt.value
			}
			raw := f.sign(t, c)
			got, err := s.VerifyAccess(context.Background(), raw)
			if err == nil {
				t.Fatalf("accepted invalid token: %#v", got)
			}
			if got != (Claims{}) {
				t.Fatal("returned partial identity")
			}
			if strings.Contains(err.Error(), raw) || strings.Contains(err.Error(), "attacker.example") {
				t.Fatal("error exposed token data")
			}
		})
	}
	t.Run("expiry precedes issued within skew", func(t *testing.T) {
		c := f.claims()
		c["iat"] = now + 30
		c["exp"] = now + 20
		if _, err := s.VerifyAccess(context.Background(), f.sign(t, c)); err == nil {
			t.Fatal("accepted empty token lifetime")
		}
	})
	t.Run("bounded clock skew accepted", func(t *testing.T) {
		c := f.claims()
		c["iat"] = now + 30
		c["nbf"] = now + 30
		if _, err := s.VerifyAccess(context.Background(), f.sign(t, c)); err != nil {
			t.Fatal(err)
		}
	})
}
func TestVerifyAccessSignatureAlgorithmAndRotation(t *testing.T) {
	f := newTestIssuer(t)
	s := newService(t, f)
	raw := f.sign(t, f.claims())
	if _, err := s.VerifyAccess(context.Background(), raw); err != nil {
		t.Fatal(err)
	}
	if _, err := s.VerifyAccess(context.Background(), f.signAlgorithm(t, f.claims(), "RS512", f.key)); err == nil {
		t.Fatal("accepted unsupported algorithm")
	}
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.VerifyAccess(context.Background(), f.signAlgorithm(t, f.claims(), "RS256", other)); err == nil {
		t.Fatal("accepted wrong signature")
	}
	for _, raw := range []string{"not-a-token", strings.Repeat("sensitive", 3000), "eyJhbGciOiJub25lIn0.e30."} {
		if _, err := s.VerifyAccess(context.Background(), raw); err == nil {
			t.Fatal("accepted malformed JWT")
		}
	}
	f.mu.Lock()
	f.key = other
	f.kid = "key-2"
	f.mu.Unlock()
	if _, err := s.VerifyAccess(context.Background(), f.sign(t, f.claims())); err != nil {
		t.Fatalf("rotation failed: %v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.jwksRequests < 2 {
		t.Fatal("rotation did not refresh JWKS")
	}
}
func TestAuthorizationURLAndOwnerExchange(t *testing.T) {
	f := newTestIssuer(t)
	s := newService(t, f)
	verifier := strings.Repeat("v", 43)
	raw, err := s.AuthorizationURL("random-state", "random-nonce", verifier)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	sum := sha256.Sum256([]byte(verifier))
	for k, want := range map[string]string{"client_id": "owner-client", "redirect_uri": f.config().OwnerCallbackURL, "response_type": "code", "scope": "openid", "state": "random-state", "nonce": "random-nonce", "code_challenge_method": "S256", "code_challenge": base64.RawURLEncoding.EncodeToString(sum[:])} {
		if q.Get(k) != want {
			t.Errorf("%s=%q, want %q", k, q.Get(k), want)
		}
	}
	if u.Scheme+"://"+u.Host+u.Path != f.server.URL+"/authorize" || q.Has("client_secret") {
		t.Fatal("wrong authorization endpoint or leaked secret")
	}
	c := f.claims()
	c["aud"] = "owner-client"
	c["nonce"] = "random-nonce"
	delete(c, "cid")
	delete(c, "scp")
	f.token = f.sign(t, c)
	owner, err := s.Complete(context.Background(), "one-time-code", verifier, security.Hash("random-nonce"))
	if err != nil {
		t.Fatal(err)
	}
	if owner != (Owner{Issuer: f.server.URL, UserID: "00uImmutable"}) {
		t.Fatalf("wrong owner: %#v", owner)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for k, want := range map[string]string{"code": "one-time-code", "grant_type": "authorization_code", "redirect_uri": f.config().OwnerCallbackURL, "code_verifier": verifier} {
		if f.form.Get(k) != want {
			t.Errorf("%s=%q, want %q", k, f.form.Get(k), want)
		}
	}
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("owner-client:owner-secret-do-not-leak"))
	if f.authorization != want {
		t.Fatal("owner token exchange did not authenticate configured client")
	}
}
func TestOwnerExchangeRejectsInvalidIdentity(t *testing.T) {
	f := newTestIssuer(t)
	s := newService(t, f)
	v := strings.Repeat("v", 43)
	for _, tt := range []struct {
		name, key string
		value     any
		remove    bool
	}{
		{"wrong nonce", "nonce", "other", false}, {"missing nonce", "nonce", nil, true}, {"wrong audience", "aud", "api://toolbox-mcp", false}, {"wrong authorized party", "azp", "other-client", false}, {"wrong issuer", "iss", "https://attacker.example", false}, {"missing uid", "uid", nil, true}, {"blank uid", "uid", "", false}, {"wrong uid type", "uid", true, false}, {"future issued", "iat", time.Now().Add(2 * time.Minute).Unix(), false}, {"expired", "exp", time.Now().Add(-time.Minute).Unix(), false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := f.claims()
			c["aud"] = "owner-client"
			c["nonce"] = "nonce"
			if tt.remove {
				delete(c, tt.key)
			} else {
				c[tt.key] = tt.value
			}
			raw := f.sign(t, c)
			f.mu.Lock()
			f.token = raw
			f.mu.Unlock()
			got, err := s.Complete(context.Background(), "sensitive-code", v, security.Hash("nonce"))
			if err == nil || got != (Owner{}) {
				t.Fatal("accepted invalid owner token")
			}
			assertSanitized(t, err)
		})
	}
}

func assertSanitized(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected error")
	}
	for _, secret := range []string{"sensitive-code", "owner-secret-do-not-leak", "server-secret", "raw-token-secret"} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("error leaked %q", secret)
		}
	}
}
func TestOwnerTokenEndpointErrorsAreSanitized(t *testing.T) {
	f := newTestIssuer(t)
	s := newService(t, f)
	for _, tt := range []struct {
		status int
		body   string
	}{{400, `{"error":"invalid_grant","error_description":"server-secret sensitive-code owner-secret-do-not-leak"}`}, {200, `{"access_token":"raw-token-secret","token_type":"Bearer"}`}, {200, `{"id_token":17,"access_token":"raw-token-secret","token_type":"Bearer"}`}, {302, `{"error":"server-secret"}`}} {
		f.mu.Lock()
		f.tokenStatus = tt.status
		f.tokenBody = tt.body
		f.mu.Unlock()
		owner, err := s.Complete(context.Background(), "sensitive-code", strings.Repeat("v", 43), security.Hash("nonce"))
		if owner != (Owner{}) {
			t.Fatal("partial owner returned")
		}
		assertSanitized(t, err)
	}
}
func TestInputAndConfigValidation(t *testing.T) {
	f := newTestIssuer(t)
	for _, change := range []func(*Config){func(c *Config) { c.AllowLoopbackHTTP = false }, func(c *Config) { c.Issuer = "http://example.com" }, func(c *Config) { c.Issuer = "https://user:secret@example.com" }, func(c *Config) { c.Audience = "" }, func(c *Config) { c.Audience = c.OwnerClientID }, func(c *Config) { c.OwnerClientID = "" }, func(c *Config) { c.OwnerClientSecret = "" }, func(c *Config) { c.OwnerCallbackURL = "http://example.com/callback" }, func(c *Config) { c.OwnerCallbackURL = "https://example.com/callback#fragment" }, func(c *Config) { c.Clients = nil }, func(c *Config) { c.Clients[""] = "Invalid" }} {
		cfg := f.config()
		change(&cfg)
		if _, err := New(context.Background(), cfg); err == nil {
			t.Fatal("accepted invalid config")
		}
	}
	s := newService(t, f)
	for _, args := range [][3]string{{"", "nonce", strings.Repeat("v", 43)}, {"state", "", strings.Repeat("v", 43)}, {"state", "nonce", "short"}, {"state", "nonce", strings.Repeat("+", 43)}} {
		if _, err := s.AuthorizationURL(args[0], args[1], args[2]); err == nil {
			t.Fatal("accepted invalid authorization arguments")
		}
	}
	for _, args := range [][3]string{{"", strings.Repeat("v", 43), security.Hash("nonce")}, {"code", "short", security.Hash("nonce")}, {"code", strings.Repeat("v", 43), ""}} {
		if _, err := s.Complete(context.Background(), args[0], args[1], args[2]); err == nil {
			t.Fatal("accepted invalid completion arguments")
		}
	}
}
func TestDiscoveryRejectsUnsafeEndpointsAndRedirects(t *testing.T) {
	for _, tt := range []struct{ name, key, value string }{{"unsafe jwks", "jwks_uri", "http://example.com/keys"}, {"unsafe token", "token_endpoint", "http://example.com/token"}, {"unsafe auth", "authorization_endpoint", "http://example.com/auth"}, {"wrong issuer", "issuer", "https://attacker.example"}} {
		t.Run(tt.name, func(t *testing.T) {
			f := newTestIssuer(t)
			f.discovery = map[string]any{tt.key: tt.value}
			if _, err := New(context.Background(), f.config()); err == nil {
				t.Fatal("accepted unsafe discovery")
			}
		})
	}
	var hits atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer destination.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, destination.URL, http.StatusFound) }))
	defer redirect.Close()
	f := newTestIssuer(t)
	cfg := f.config()
	cfg.Issuer = redirect.URL
	if _, err := New(context.Background(), cfg); err == nil {
		t.Fatal("accepted redirected discovery")
	}
	if hits.Load() != 0 {
		t.Fatal("followed redirect")
	}
}

func TestProviderHTTPBodyLimitAndCancellation(t *testing.T) {
	f := newTestIssuer(t)
	var large *httptest.Server
	large = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"issuer": large.URL, "authorization_endpoint": large.URL + "/auth", "token_endpoint": large.URL + "/token", "jwks_uri": large.URL + "/keys", "padding": strings.Repeat("x", 1<<20)})
	}))
	defer large.Close()
	cfg := f.config()
	cfg.Issuer = large.URL
	if _, err := New(context.Background(), cfg); err == nil {
		t.Fatal("accepted oversized discovery response")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := New(ctx, f.config()); err == nil {
		t.Fatal("ignored canceled discovery context")
	}
	s := newService(t, f)
	if _, err := s.Complete(ctx, "sensitive-code", strings.Repeat("v", 43), security.Hash("nonce")); err == nil {
		t.Fatal("ignored canceled token exchange context")
	}
}
func TestTokenAndJWKSRedirectsAreNeverFollowed(t *testing.T) {
	var hits atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer destination.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	for _, endpoint := range []string{"token_endpoint", "jwks_uri"} {
		t.Run(endpoint, func(t *testing.T) {
			f := newTestIssuer(t)
			f.discovery = map[string]any{endpoint: redirect.URL}
			s := newService(t, f)
			if endpoint == "token_endpoint" {
				_, err := s.Complete(context.Background(), "sensitive-code", strings.Repeat("v", 43), security.Hash("nonce"))
				assertSanitized(t, err)
			} else {
				if _, err := s.VerifyAccess(context.Background(), f.sign(t, f.claims())); err == nil {
					t.Fatal("accepted redirected JWKS")
				}
			}
		})
	}
	if hits.Load() != 0 {
		t.Fatal("followed endpoint redirect")
	}
}
func TestConcurrentAccessVerification(t *testing.T) {
	f := newTestIssuer(t)
	s := newService(t, f)
	raw := f.sign(t, f.claims())
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Go(func() {
			got, err := s.VerifyAccess(context.Background(), raw)
			if err != nil || got.UserID != "00uImmutable" {
				t.Errorf("concurrent verification failed: %#v %v", got, err)
			}
		})
	}
	wg.Wait()
}
