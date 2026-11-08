// Package keycloaktest contains controlled protocol fixtures for the opt-in real
// Keycloak acceptance test. Production packages must not import it.
package keycloaktest

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Config contains only generated synthetic upstream credentials. Never log it.
type Config struct {
	OktaIssuer         string `json:"okta_issuer"`
	GoogleIssuer       string `json:"google_issuer"`
	OktaClientID       string `json:"okta_client_id"`
	OktaClientSecret   string `json:"okta_client_secret"`
	GoogleClientID     string `json:"google_client_id"`
	GoogleClientSecret string `json:"google_client_secret"`
}

type upstream struct {
	issuer, clientID, secret, subject string
}

type authorization struct {
	provider, redirect, nonce, challenge string
	expires                              time.Time
}

type fixture struct {
	providers map[string]upstream
	key       *rsa.PrivateKey
	mu        sync.Mutex
	codes     map[string]authorization
	tokens    map[string]authorization
}

// New constructs two independent synthetic OIDC providers. Both deliberately
// return the same verified email, so the broker test can detect email merging.
// Authorize auto-consents; no real person, password, Okta, or Google is involved.
func New(config Config) (http.Handler, error) {
	providers := map[string]upstream{
		"okta":   {config.OktaIssuer, config.OktaClientID, config.OktaClientSecret, "okta-subject"},
		"google": {config.GoogleIssuer, config.GoogleClientID, config.GoogleClientSecret, "google-subject"},
	}
	for alias, provider := range providers {
		u, err := url.Parse(provider.issuer)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "/"+alias || provider.clientID == "" || provider.secret == "" {
			return nil, errors.New("invalid synthetic OIDC configuration")
		}
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, errors.New("generate synthetic OIDC signing key")
	}
	return &fixture{providers: providers, key: key, codes: map[string]authorization{}, tokens: map[string]authorization{}}, nil
}

func (f *fixture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.Path == "/healthz" && r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		return
	}
	parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/"), "/", 2)
	if len(parts) != 2 {
		http.NotFound(w, r)
		return
	}
	provider, ok := f.providers[parts[0]]
	if !ok {
		http.NotFound(w, r)
		return
	}
	endpoint := strings.TrimPrefix(parts[1], "v1/")
	if endpoint == "keys" {
		endpoint = "jwks"
	}
	switch endpoint {
	case ".well-known/openid-configuration":
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"issuer": provider.issuer, "authorization_endpoint": provider.issuer + "/authorize",
			"token_endpoint": provider.issuer + "/token", "jwks_uri": provider.issuer + "/jwks",
			"userinfo_endpoint": provider.issuer + "/userinfo", "response_types_supported": []string{"code"},
			"subject_types_supported": []string{"public"}, "id_token_signing_alg_values_supported": []string{"RS256"},
			"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
			"code_challenge_methods_supported":      []string{"S256"}, "scopes_supported": []string{"openid", "profile", "email"},
		})
	case "jwks":
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"keys": []any{map[string]any{
			"kty": "RSA", "use": "sig", "kid": "controlled-upstream", "alg": "RS256",
			"n": base64.RawURLEncoding.EncodeToString(f.key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(f.key.E)).Bytes()),
		}}})
	case "authorize":
		f.authorize(w, r, parts[0], provider)
	case "token":
		f.token(w, r, parts[0], provider)
	case "userinfo":
		f.userinfo(w, r, parts[0], provider)
	default:
		http.NotFound(w, r)
	}
}

func (f *fixture) authorize(w http.ResponseWriter, r *http.Request, alias string, provider upstream) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	redirect, err := url.Parse(q.Get("redirect_uri"))
	// The fixture accepts only the real broker callback for its own provider.
	if err != nil || redirect.Scheme != "https" || redirect.Host == "" || redirect.User != nil || redirect.RawQuery != "" || redirect.Fragment != "" || !strings.HasSuffix(redirect.Path, "/broker/"+alias+"/endpoint") ||
		q.Get("client_id") != provider.clientID || q.Get("response_type") != "code" || q.Get("state") == "" || !containsScope(q.Get("scope"), "openid") ||
		(q.Get("code_challenge") != "" && q.Get("code_challenge_method") != "S256") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	code, err := randomToken()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	f.mu.Lock()
	f.codes[code] = authorization{provider: alias, redirect: redirect.String(), nonce: q.Get("nonce"), challenge: q.Get("code_challenge"), expires: time.Now().Add(5 * time.Minute)}
	f.mu.Unlock()
	callback := redirect.Query()
	callback.Set("code", code)
	callback.Set("state", q.Get("state"))
	redirect.RawQuery = callback.Encode()
	// nosemgrep: go.lang.security.injection.open-redirect.open-redirect -- Synthetic IdP accepts HTTPS broker callbacks for its configured test provider.
	http.Redirect(w, r, redirect.String(), http.StatusFound)
}

func (f *fixture) token(w http.ResponseWriter, r *http.Request, alias string, provider upstream) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid_request"})
		return
	}
	clientID, secret, basic := r.BasicAuth()
	if !basic {
		clientID, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	if subtle.ConstantTimeCompare([]byte(clientID), []byte(provider.clientID)) != 1 || subtle.ConstantTimeCompare([]byte(secret), []byte(provider.secret)) != 1 {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}
	if r.PostForm.Get("grant_type") != "authorization_code" {
		writeJSON(w, 400, map[string]string{"error": "unsupported_grant_type"})
		return
	}
	f.mu.Lock()
	auth, found := f.codes[r.PostForm.Get("code")]
	if found {
		delete(f.codes, r.PostForm.Get("code"))
	}
	f.mu.Unlock()
	digest := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if !found || auth.provider != alias || !time.Now().Before(auth.expires) || auth.redirect != r.PostForm.Get("redirect_uri") ||
		(auth.challenge != "" && (r.PostForm.Get("code_verifier") == "" || auth.challenge != base64.RawURLEncoding.EncodeToString(digest[:]))) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		return
	}
	claims := identityClaims(alias, provider)
	now := time.Now().Unix()
	claims["iss"], claims["aud"], claims["iat"], claims["exp"], claims["auth_time"] = provider.issuer, provider.clientID, now, now+300, now
	if auth.nonce != "" {
		claims["nonce"] = auth.nonce
	}
	idToken, err := f.sign(claims)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	access, err := randomToken()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	f.mu.Lock()
	f.tokens[access] = auth
	f.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"access_token": access, "token_type": "Bearer", "expires_in": 300, "id_token": idToken, "scope": "openid profile email"})
}

func (f *fixture) userinfo(w http.ResponseWriter, r *http.Request, alias string, provider upstream) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	parts := strings.Fields(r.Header.Get("Authorization"))
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	f.mu.Lock()
	auth, found := f.tokens[parts[1]]
	f.mu.Unlock()
	if !found || auth.provider != alias || !time.Now().Before(auth.expires) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	writeJSON(w, http.StatusOK, identityClaims(alias, provider))
}

func identityClaims(alias string, provider upstream) map[string]any {
	claims := map[string]any{"sub": provider.subject, "email": "owner@example.test", "email_verified": true,
		"name": "Synthetic Owner", "given_name": "Synthetic", "family_name": "Owner", "preferred_username": alias + "-owner"}
	if alias == "google" {
		claims["hd"] = "example.test"
	}
	return claims
}

func (f *fixture) sign(claims map[string]any) (string, error) {
	header, err := json.Marshal(map[string]string{"typ": "JWT", "alg": "RS256", "kid": "controlled-upstream"})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(input))
	signature, err := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func containsScope(scopes, want string) bool {
	for _, scope := range strings.Fields(scopes) {
		if scope == want {
			return true
		}
	}
	return false
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
