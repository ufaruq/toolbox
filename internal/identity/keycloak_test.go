package identity

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Real TLS discovery, JWKS and RSA signatures exercise the public verifier.
type keycloakFixture struct {
	server        *httptest.Server
	key           *rsa.PrivateKey
	kid           string
	mu            sync.Mutex
	discovery     map[string]any
	discoveryBody string
	jwksBody      string
	jwksRedirect  string
}

func newKeycloakFixture(t *testing.T) *keycloakFixture {
	return newKeycloakFixtureWithTLS(t, true)
}

func newKeycloakFixtureWithTLS(t *testing.T, useTLS bool) *keycloakFixture {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &keycloakFixture{key: key, kid: "key-1"}
	f.server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/realms/toolbox/.well-known/openid-configuration":
			if f.discoveryBody != "" {
				fmt.Fprint(w, f.discoveryBody)
				return
			}
			d := map[string]any{"issuer": f.issuer(), "authorization_endpoint": f.issuer() + "/protocol/openid-connect/auth", "token_endpoint": f.issuer() + "/protocol/openid-connect/token", "jwks_uri": f.issuer() + "/protocol/openid-connect/certs", "id_token_signing_alg_values_supported": []string{"RS256"}}
			for k, v := range f.discovery {
				d[k] = v
			}
			json.NewEncoder(w).Encode(d)
		case "/realms/toolbox/protocol/openid-connect/certs":
			if f.jwksRedirect != "" {
				http.Redirect(w, r, f.jwksRedirect, http.StatusFound)
				return
			}
			if f.jwksBody != "" {
				fmt.Fprint(w, f.jwksBody)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{"kty": "RSA", "kid": f.kid, "alg": "RS256", "use": "sig", "n": base64.RawURLEncoding.EncodeToString(f.key.N.Bytes()), "e": "AQAB"}}})
		default:
			http.NotFound(w, r)
		}
	}))
	if useTLS {
		f.server.StartTLS()
	} else {
		f.server.Start()
	}
	t.Cleanup(f.server.Close)
	return f
}

func (f *keycloakFixture) issuer() string { return f.server.URL + "/realms/toolbox" }
func (f *keycloakFixture) config() AccessConfig {
	return AccessConfig{Provider: "keycloak", Issuer: f.issuer(), OwnerIssuer: f.issuer(), Audience: "https://toolbox.example/mcp", OwnerClientID: "owner-client", Clients: map[string]string{"agent-client": "Agent"}, HTTPClient: f.server.Client()}
}
func (f *keycloakFixture) claims() map[string]any {
	now := time.Now().Unix()
	return map[string]any{"iss": f.issuer(), "aud": "https://toolbox.example/mcp", "sub": "realm-immutable-user", "azp": "agent-client", "typ": "Bearer", "scope": "openid mcp profile", "sid": "user-session", "iat": now, "exp": now + 300}
}
func (f *keycloakFixture) sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	b, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return f.signRaw(t, `{"typ":"JWT","alg":"RS256","kid":"`+f.kid+`"}`, string(b))
}
func (f *keycloakFixture) signRaw(t *testing.T, header, payload string) string {
	t.Helper()
	raw := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(payload))
	sum := sha256.Sum256([]byte(raw))
	sig, err := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return raw + "." + base64.RawURLEncoding.EncodeToString(sig)
}
func keycloakService(t *testing.T, f *keycloakFixture) *Service {
	t.Helper()
	s, err := NewAccess(context.Background(), f.config())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestKeycloakAccessUsesRealmSubjectAndSession(t *testing.T) {
	f := newKeycloakFixture(t)
	cfg := f.config()
	s, err := NewAccess(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Clients["attacker"] = "Attacker"
	published := s.Clients()
	published["attacker"] = "Attacker"
	delete(published, "agent-client")
	c := f.claims()
	c["uid"] = "untrusted-upstream-id"
	c["cid"] = "untrusted-client"
	// Opaque nested data must not turn a legitimate client named "N" or "SID"
	// into a reserved top-level claim or JWK field.
	c["resource_access"] = map[string]any{"N": map[string]any{"roles": []string{"read"}}, "SID": map[string]any{"roles": []string{"read"}}}
	got, err := s.VerifyAccess(context.Background(), f.sign(t, c))
	if err != nil {
		t.Fatal(err)
	}
	if got.UserID != "realm-immutable-user" || got.ClientID != "agent-client" || got.Issuer != f.issuer() || s.OwnerIssuer() != f.issuer() || len(s.Clients()) != 1 {
		t.Fatalf("lost pinned identity or copied clients: %#v", got)
	}
	if _, err := s.AuthorizationURL("state", "nonce", strings.Repeat("v", 43)); err == nil {
		t.Fatal("access-only verifier exposed owner authorization")
	}
	if _, err := s.Complete(context.Background(), "code", strings.Repeat("v", 43), strings.Repeat("a", 64)); err == nil {
		t.Fatal("access-only verifier exposed code exchange")
	}
	c["aud"] = []string{cfg.Audience}
	c["iat"] = time.Now().Unix() + 30
	c["nbf"] = time.Now().Unix() + 30
	if _, err := s.VerifyAccess(context.Background(), f.sign(t, c)); err != nil {
		t.Fatalf("valid singleton audience and bounded skew: %v", err)
	}
}

func TestKeycloakRejectsNonUserAndAmbiguousClaims(t *testing.T) {
	f := newKeycloakFixture(t)
	s := keycloakService(t, f)
	now := time.Now().Unix()
	cases := []struct {
		name, key string
		value     any
		remove    bool
	}{
		{"wrong realm", "iss", "https://other.example/realms/toolbox", false},
		{"wrong audience", "aud", "https://other.example/mcp", false},
		{"owner ID audience", "aud", "owner-client", false},
		{"client ID audience", "aud", "agent-client", false},
		{"multi audience", "aud", []string{f.config().Audience, "other"}, false},
		{"duplicate audience", "aud", []string{f.config().Audience, f.config().Audience}, false},
		{"missing audience", "aud", nil, true}, {"null audience", "aud", nil, false},
		{"missing subject", "sub", nil, true}, {"blank subject", "sub", " ", false}, {"long subject", "sub", strings.Repeat("u", 257), false}, {"wrong subject type", "sub", 42, false},
		{"unknown client", "azp", "attacker", false}, {"owner client", "azp", "owner-client", false}, {"missing client", "azp", nil, true}, {"wrong client type", "azp", []string{"agent-client"}, false},
		{"ID token", "typ", "ID", false}, {"wrong type case", "typ", "bearer", false}, {"missing type", "typ", nil, true},
		{"missing session", "sid", nil, true}, {"blank session", "sid", " ", false}, {"null session", "sid", nil, false}, {"nonstring session", "sid", 42, false},
		{"missing scope", "scope", nil, true}, {"substring scope", "scope", "not-mcp", false}, {"array scope", "scope", []string{"mcp"}, false}, {"wrong separator scope", "scope", "openid\tmcp", false},
		{"missing iat", "iat", nil, true}, {"zero iat", "iat", 0, false}, {"null iat", "iat", nil, false}, {"future iat", "iat", now + 120, false}, {"fractional iat", "iat", float64(now) + 0.5, false}, {"string iat", "iat", "123", false},
		{"missing exp", "exp", nil, true}, {"expired", "exp", now - 1, false}, {"null exp", "exp", nil, false}, {"string exp", "exp", "123", false},
		{"future nbf", "nbf", now + 120, false}, {"null nbf", "nbf", nil, false}, {"negative nbf", "nbf", -1, false}, {"string nbf", "nbf", "123", false},
		{"not before after expiry", "nbf", now + 400, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := f.claims()
			if tc.remove {
				delete(c, tc.key)
			} else {
				c[tc.key] = tc.value
			}
			raw := f.sign(t, c)
			got, err := s.VerifyAccess(context.Background(), raw)
			if err == nil || got != (Claims{}) {
				t.Fatalf("accepted invalid identity: %#v %v", got, err)
			}
			if err.Error() != "invalid access token" || strings.Contains(err.Error(), raw) {
				t.Fatal("unsanitized error")
			}
		})
	}
	t.Run("expiry before issue", func(t *testing.T) {
		c := f.claims()
		c["iat"] = now + 30
		c["exp"] = now + 20
		if _, err := s.VerifyAccess(context.Background(), f.sign(t, c)); err == nil {
			t.Fatal("accepted empty lifetime")
		}
	})
}

func TestKeycloakRejectsSignedJSONAmbiguity(t *testing.T) {
	f := newKeycloakFixture(t)
	s := keycloakService(t, f)
	b, _ := json.Marshal(f.claims())
	base := string(b)
	header := `{"alg":"RS256","kid":"key-1","typ":"JWT"}`
	cases := []struct{ name, header, payload string }{
		{"duplicate subject", header, strings.Replace(base, `"sub":"realm-immutable-user"`, `"sub":"attacker","sub":"realm-immutable-user"`, 1)},
		{"escaped duplicate subject", header, strings.Replace(base, `"sub":"realm-immutable-user"`, `"s\u0075b":"attacker","sub":"realm-immutable-user"`, 1)},
		{"case subject", header, strings.Replace(base, `"sub":`, `"SUB":`, 1)},
		{"shadow subject", header, strings.Replace(base, `"sub":`, `"SUB":"attacker","sub":`, 1)},
		{"unicode shadow subject", header, strings.Replace(base, `"sub":`, `"ſub":"attacker","sub":`, 1)},
		{"unicode shadow issuer", header, strings.Replace(base, `"iss":`, `"iſſ":"https://attacker.example/realms/toolbox","iss":`, 1)},
		{"case issuer", header, strings.Replace(base, `"iss":`, `"ISS":`, 1)},
		{"case authorized party", header, strings.Replace(base, `"azp":`, `"AZP":`, 1)},
		{"duplicate nested unknown", header, strings.TrimSuffix(base, "}") + `,"extra":{"x":1,"x":2}}`},
		{"duplicate algorithm", `{"alg":"none","alg":"RS256","kid":"key-1"}`, base},
		{"case algorithm", `{"ALG":"RS256","kid":"key-1"}`, base},
		{"critical header", `{"alg":"RS256","kid":"key-1","crit":["future"],"future":true}`, base},
		{"trailing document", header, base + ` {}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := s.VerifyAccess(context.Background(), f.signRaw(t, tc.header, tc.payload)); err == nil {
				t.Fatal("accepted ambiguous signed JSON")
			}
		})
	}
	for _, raw := range []string{"not-jwt", strings.Repeat("s", 16385), f.signRaw(t, `{"alg":"none","kid":"key-1"}`, base)} {
		if _, err := s.VerifyAccess(context.Background(), raw); err == nil {
			t.Fatal("accepted malformed token")
		}
	}
}

func TestKeycloakBindingAndProviderConfiguration(t *testing.T) {
	for _, tc := range []struct {
		owner, access string
		local, valid  bool
	}{
		{"https://sso.example/realms/toolbox", "https://sso.example/realms/toolbox", false, true},
		{"https://sso.example/auth/realms/toolbox", "https://sso.example/auth/realms/toolbox", false, true},
		{"https://sso.example/realms/toolbox", "https://sso.example/realms/other", false, false},
		{"https://sso.example/realms/toolbox/", "https://sso.example/realms/toolbox/", false, false},
		{"https://sso.example/realms/toolbox?x=y", "https://sso.example/realms/toolbox?x=y", false, false},
		{"https://sso.example/realms/toolbox?", "https://sso.example/realms/toolbox?", false, false},
		{"https://sso.example/realms/toolbox#x", "https://sso.example/realms/toolbox#x", false, false},
		{"https://sso.example/realms/toolbox#", "https://sso.example/realms/toolbox#", false, false},
		{"https://user@sso.example/realms/toolbox", "https://user@sso.example/realms/toolbox", false, false},
		{"https://sso.example/realms/a%2fb", "https://sso.example/realms/a%2fb", false, false},
		{"https://sso.example/a/../realms/toolbox", "https://sso.example/a/../realms/toolbox", false, false},
		{"http://sso.example/realms/toolbox", "http://sso.example/realms/toolbox", true, false},
		{"http://127.0.0.1:1234/realms/toolbox", "http://127.0.0.1:1234/realms/toolbox", false, false},
		{"http://127.0.0.1:1234/realms/toolbox", "http://127.0.0.1:1234/realms/toolbox", true, true},
	} {
		if got := ValidKeycloakOwnerBinding(tc.owner, tc.access, tc.local); got != tc.valid {
			t.Errorf("binding %q / %q = %v", tc.owner, tc.access, got)
		}
	}
	f := newKeycloakFixture(t)
	for _, name := range []string{"unknown provider", "mismatched owner", "owner in allowlist", "audience in allowlist", "client audience", "empty clients", "untrusted TLS", "insecure TLS"} {
		t.Run(name, func(t *testing.T) {
			cfg := f.config()
			switch name {
			case "unknown provider":
				cfg.Provider = "KEYCLOAK"
			case "mismatched owner":
				cfg.OwnerIssuer += "-other"
			case "owner in allowlist":
				cfg.Clients[cfg.OwnerClientID] = "Owner"
			case "audience in allowlist":
				cfg.Clients[cfg.Audience] = "Resource"
			case "client audience":
				cfg.Audience = cfg.OwnerClientID
			case "empty clients":
				cfg.Clients = nil
			case "untrusted TLS":
				cfg.HTTPClient = nil
			case "insecure TLS":
				cfg.HTTPClient = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
			}
			if _, err := NewAccess(context.Background(), cfg); err == nil {
				t.Fatal("accepted invalid configuration")
			}
		})
	}
}

func TestKeycloakDiscoveryAndJWKSStayOnPinnedTLSOrigin(t *testing.T) {
	f := newKeycloakFixture(t)
	var foreignCalls atomic.Int32
	foreign := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { foreignCalls.Add(1); fmt.Fprint(w, `{"keys":[]}`) }))
	t.Cleanup(foreign.Close)
	for _, endpoint := range []string{"issuer", "jwks_uri", "authorization_endpoint", "token_endpoint"} {
		t.Run(endpoint, func(t *testing.T) {
			f.mu.Lock()
			f.discovery = map[string]any{endpoint: foreign.URL + "/realms/toolbox"}
			f.mu.Unlock()
			if _, err := NewAccess(context.Background(), f.config()); err == nil {
				t.Fatal("accepted foreign discovery endpoint")
			}
		})
	}
	if foreignCalls.Load() != 0 {
		t.Fatal("contacted foreign endpoint")
	}
	f.mu.Lock()
	f.discovery = nil
	f.mu.Unlock()
	s := keycloakService(t, f)
	f.mu.Lock()
	f.jwksRedirect = foreign.URL + "/keys"
	f.mu.Unlock()
	if _, err := s.VerifyAccess(context.Background(), f.sign(t, f.claims())); err == nil {
		t.Fatal("accepted JWKS redirect")
	}
	if foreignCalls.Load() != 0 {
		t.Fatal("followed foreign redirect")
	}
}

func TestKeycloakRejectsMalformedAndOversizedProviderBodies(t *testing.T) {
	f := newKeycloakFixture(t)
	discovery, _ := json.Marshal(map[string]any{"issuer": f.issuer(), "authorization_endpoint": f.issuer() + "/protocol/openid-connect/auth", "token_endpoint": f.issuer() + "/protocol/openid-connect/token", "jwks_uri": f.issuer() + "/protocol/openid-connect/certs", "id_token_signing_alg_values_supported": []string{"RS256"}})
	validDiscovery := string(discovery)
	for _, body := range []string{
		strings.Replace(validDiscovery, `"issuer":`, `"issuer":"`+f.issuer()+`","issuer":`, 1),
		strings.Replace(validDiscovery, `"issuer":`, `"ISSUER":`, 1),
		strings.Repeat("x", (1<<20)+1),
	} {
		f.mu.Lock()
		f.discoveryBody = body
		f.mu.Unlock()
		if _, err := NewAccess(context.Background(), f.config()); err == nil || err.Error() != "identity provider unavailable" {
			t.Fatalf("accepted malformed discovery or leaked error: %v", err)
		}
	}
	f.mu.Lock()
	f.discoveryBody = ""
	f.mu.Unlock()
	s := keycloakService(t, f)
	f.mu.Lock()
	f.jwksBody = strings.Repeat("x", (1<<20)+1)
	f.mu.Unlock()
	if _, err := s.VerifyAccess(context.Background(), f.sign(t, f.claims())); err == nil {
		t.Fatal("accepted oversized JWKS")
	}
}

func TestKeycloakSignatureRotationAndCancelledDiscoveryContext(t *testing.T) {
	f := newKeycloakFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	s, err := NewAccess(ctx, f.config())
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	raw := f.sign(t, f.claims())
	if _, err := s.VerifyAccess(context.Background(), raw); err != nil {
		t.Fatalf("constructor cancellation broke key fetch: %v", err)
	}
	parts := strings.Split(raw, ".")
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	sig[0] ^= 1
	parts[2] = base64.RawURLEncoding.EncodeToString(sig)
	if _, err := s.VerifyAccess(context.Background(), strings.Join(parts, ".")); err == nil {
		t.Fatal("accepted invalid RSA signature")
	}
	b, _ := json.Marshal(f.claims())
	if _, err := s.VerifyAccess(context.Background(), f.signRaw(t, `{"alg":"RS512","kid":"key-1"}`, string(b))); err == nil {
		t.Fatal("accepted non-RS256 algorithm")
	}
	rotated, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.key = rotated
	f.kid = "key-2"
	f.mu.Unlock()
	if _, err := s.VerifyAccess(context.Background(), f.sign(t, f.claims())); err != nil {
		t.Fatalf("rotation failed: %v", err)
	}
}

func TestKeycloakRejectsAmbiguousJWKS(t *testing.T) {
	f := newKeycloakFixture(t)
	key := `{"kty":"RSA","kid":"key-1","n":"` + base64.RawURLEncoding.EncodeToString(f.key.N.Bytes()) + `","e":"AQAB"}`
	for _, body := range []string{
		`{"keys":[` + key + `],"keys":[` + key + `]}`,
		`{"KEYS":[` + key + `]}`,
		`{"keys":[{"kty":"RSA","kid":"key-1","n":"invalid","n":"` + base64.RawURLEncoding.EncodeToString(f.key.N.Bytes()) + `","e":"AQAB"}]}`,
		`{"keys":[` + strings.Replace(key, `"kty":`, `"KTY":`, 1) + `]}`,
	} {
		f.mu.Lock()
		f.jwksBody = body
		f.mu.Unlock()
		s := keycloakService(t, f)
		if _, err := s.VerifyAccess(context.Background(), f.sign(t, f.claims())); err == nil {
			t.Fatal("accepted ambiguous JWKS")
		}
	}
}

func TestKeycloakLoopbackHTTPRequiresExplicitFixtureFlag(t *testing.T) {
	f := newKeycloakFixtureWithTLS(t, false)
	cfg := f.config()
	if _, err := NewAccess(context.Background(), cfg); err == nil {
		t.Fatal("allowed cleartext without explicit fixture configuration")
	}
	cfg.AllowLoopbackHTTP = true
	s, err := NewAccess(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.VerifyAccess(context.Background(), f.sign(t, f.claims())); err != nil {
		t.Fatal(err)
	}
}

func TestAccessProviderExplicitOktaPreservesDefaultPolicy(t *testing.T) {
	f := newTestIssuer(t)
	for _, provider := range []string{"", "okta"} {
		cfg := AccessConfig{Provider: provider, Issuer: f.server.URL + "/oauth2/default", OwnerIssuer: f.server.URL, Audience: "api://toolbox-mcp", OwnerClientID: "owner-client", Clients: map[string]string{"agent-client": "Agent"}, AllowLoopbackHTTP: true}
		s, err := NewAccess(context.Background(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		c := f.claims()
		c["iss"] = cfg.Issuer
		claims, err := s.VerifyAccess(context.Background(), f.sign(t, c))
		if err != nil || claims.UserID != "00uImmutable" || claims.ClientID != "agent-client" {
			t.Fatalf("provider %q changed default Okta behavior: %#v %v", provider, claims, err)
		}
	}
}
