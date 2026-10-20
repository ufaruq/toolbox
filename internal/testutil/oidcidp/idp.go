// Package oidcidp provides an entirely synthetic TLS OpenID Connect provider.
// It is test support; production packages must not import it.
package oidcidp

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// Server is a real protocol fixture with a unique RSA signing key and trusted
// test TLS certificate. All credentials and identities are synthetic.
type Server struct {
	Issuer       string
	ClientID     string
	ClientSecret string

	httpServer *httptest.Server
	key        *rsa.PrivateKey

	mu               sync.Mutex
	codes            map[string]authorization
	claims           map[string]any
	discovery        map[string]any
	redirects        map[string]string
	tokenResponse    *tokenResponse
	signingAlgorithm string
	invalidSignature bool
	exchanges        int
	block            *exchangeBlock
}

type authorization struct {
	nonce       string
	challenge   string
	redirectURI string
	subject     string
}

type tokenResponse struct {
	status int
	body   string
}

type exchangeBlock struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

// New starts a local TLS provider and arranges cleanup through t. No external
// network, tenant, or credential is involved.
func New(t testing.TB) *Server {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate synthetic OIDC key: %v", err)
	}
	s := &Server{
		ClientID:         "synthetic-toolbox-client",
		ClientSecret:     "synthetic-toolbox-client-secret",
		key:              key,
		codes:            make(map[string]authorization),
		claims:           make(map[string]any),
		discovery:        make(map[string]any),
		redirects:        make(map[string]string),
		signingAlgorithm: "RS256",
	}
	s.httpServer = httptest.NewTLSServer(http.HandlerFunc(s.serveHTTP))
	s.Issuer = s.httpServer.URL
	t.Cleanup(func() {
		// An assertion failure must not leave Close waiting on a deliberately
		// blocked token exchange.
		s.mu.Lock()
		block := s.block
		s.mu.Unlock()
		if block != nil {
			block.unblock()
		}
		s.httpServer.Close()
	})
	return s
}

// TLSClient trusts this fixture's certificate, while retaining TLS verification.
func (s *Server) TLSClient() *http.Client {
	return s.httpServer.Client()
}

// SPKIHash returns the base64 SHA-256 certificate public-key pin accepted by
// Chromium's test-only ignore-certificate-errors-spki-list option.
func (s *Server) SPKIHash() string {
	hash := sha256.Sum256(s.httpServer.Certificate().RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(hash[:])
}

// ExchangeCount includes rejected token requests, allowing tests to detect
// client-authentication retries and duplicate exchanges.
func (s *Server) ExchangeCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.exchanges
}

// SetClaims replaces the overrides applied to generated ID-token claims.
// Defaults are iss=Issuer, sub=synthetic-owner, aud=ClientID, iat=now,
// exp=now+300 seconds and nonce=the authorization nonce. A nil override deletes
// its claim, making missing-claim tests possible.
func (s *Server) SetClaims(claims map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.claims = copyMap(claims)
}

// SetDiscovery replaces overrides to the default same-origin discovery
// document. A nil value removes the named property.
func (s *Server) SetDiscovery(overrides map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.discovery = copyMap(overrides)
}

// SetTokenResponse overrides all token responses, after recording and optionally
// blocking the attempted exchange. Passing status=0 restores normal behavior.
func (s *Server) SetTokenResponse(status int, body string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if status == 0 {
		s.tokenResponse = nil
		return
	}
	s.tokenResponse = &tokenResponse{status: status, body: body}
}

// SetSigningAlgorithm controls the JWT alg and corresponding signature. RS256
// is the normal setting; alternatives permit verification-negative tests.
func (s *Server) SetSigningAlgorithm(algorithm string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.signingAlgorithm = algorithm
}

// SetInvalidSignature corrupts the next and subsequent ID-token signatures.
func (s *Server) SetInvalidSignature(invalid bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.invalidSignature = invalid
}

// SetRedirect installs an HTTP redirect at a fixture path. An empty target
// removes the override. This permits redirect-policy tests without another IdP.
func (s *Server) SetRedirect(path, target string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if target == "" {
		delete(s.redirects, path)
	} else {
		s.redirects[path] = target
	}
}

// BlockExchange pauses token responses after the request has been counted. The
// entered channel closes when the first request is blocked. release is safe to
// call more than once. A new call releases any earlier block.
func (s *Server) BlockExchange() (entered <-chan struct{}, release func()) {
	block := &exchangeBlock{entered: make(chan struct{}), release: make(chan struct{})}
	s.mu.Lock()
	previous := s.block
	s.block = block
	s.mu.Unlock()
	if previous != nil {
		previous.unblock()
	}
	return block.entered, block.unblock
}

func (b *exchangeBlock) unblock() {
	b.once.Do(func() { close(b.release) })
}

// Authorize directly creates an authorization code for protocol unit tests.
// The token endpoint still independently computes SHA-256(verifier) and checks
// it against the stored S256 challenge. Browser tests use /authorize instead.
func (s *Server) Authorize(t testing.TB, nonce, verifier string) string {
	t.Helper()
	if nonce == "" || verifier == "" {
		t.Fatal("synthetic authorization requires nonce and PKCE verifier")
	}
	digest := sha256.Sum256([]byte(verifier))
	code, err := s.authorize(nonce, base64.RawURLEncoding.EncodeToString(digest[:]), "", "synthetic-owner")
	if err != nil {
		t.Fatalf("create synthetic authorization: %v", err)
	}
	return code
}

func (s *Server) authorize(nonce, challenge, redirectURI, subject string) (string, error) {
	random := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, random); err != nil {
		return "", err
	}
	code := base64.RawURLEncoding.EncodeToString(random)
	s.mu.Lock()
	s.codes[code] = authorization{nonce: nonce, challenge: challenge, redirectURI: redirectURI, subject: subject}
	s.mu.Unlock()
	return code, nil
}

func (s *Server) serveHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.Path == "/token" {
		s.serveToken(w, r)
		return
	}
	s.mu.Lock()
	redirect := s.redirects[r.URL.Path]
	s.mu.Unlock()
	if redirect != "" {
		http.Redirect(w, r, redirect, http.StatusFound)
		return
	}
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		s.serveDiscovery(w, r)
	case "/jwks":
		s.serveJWKS(w, r)
	case "/authorize":
		s.serveAuthorize(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) serveDiscovery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	document := map[string]any{
		"issuer":                                s.Issuer,
		"authorization_endpoint":                s.Issuer + "/authorize",
		"token_endpoint":                        s.Issuer + "/token",
		"jwks_uri":                              s.Issuer + "/jwks",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic"},
		"code_challenge_methods_supported":      []string{"S256"},
		"scopes_supported":                      []string{"openid"},
	}
	s.mu.Lock()
	applyOverrides(document, s.discovery)
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, document)
}

func (s *Server) serveJWKS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"keys": []any{map[string]any{
		"kty": "RSA", "use": "sig", "kid": "synthetic-rsa", "alg": "RS256",
		"n": base64.RawURLEncoding.EncodeToString(s.key.PublicKey.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(s.key.PublicKey.E)).Bytes()),
	}}})
}

func (s *Server) serveAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid synthetic authorization request", http.StatusBadRequest)
		return
	}
	q := r.Form
	redirectURI, err := url.Parse(q.Get("redirect_uri"))
	if err != nil || redirectURI.Host == "" || (redirectURI.Scheme != "http" && redirectURI.Scheme != "https") ||
		q.Get("client_id") != s.ClientID || q.Get("response_type") != "code" ||
		q.Get("scope") != "openid" || q.Get("state") == "" || q.Get("nonce") == "" ||
		q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		http.Error(w, "invalid synthetic authorization request", http.StatusBadRequest)
		return
	}
	if r.Method == http.MethodGet {
		fields := make(map[string]string)
		for _, name := range []string{"client_id", "response_type", "redirect_uri", "scope", "state", "nonce", "code_challenge_method", "code_challenge"} {
			fields[name] = q.Get(name)
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = authorizationPage.Execute(w, fields)
		return
	}
	subject := q.Get("subject")
	if subject == "" || len(subject) > 255 || strings.ContainsAny(subject, "\r\n\t\x00") {
		http.Error(w, "invalid synthetic subject", http.StatusBadRequest)
		return
	}
	code, err := s.authorize(q.Get("nonce"), q.Get("code_challenge"), redirectURI.String(), subject)
	if err != nil {
		http.Error(w, "synthetic authorization unavailable", http.StatusInternalServerError)
		return
	}
	callback := redirectURI.Query()
	callback.Set("code", code)
	callback.Set("state", q.Get("state"))
	redirectURI.RawQuery = callback.Encode()
	http.Redirect(w, r, redirectURI.String(), http.StatusFound)
}

var authorizationPage = template.Must(template.New("authorization").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Synthetic identity provider</title>
<link rel="icon" href="data:,"></head><body>
<h1>Synthetic identity provider</h1><p>Choose an invented test subject. No password or external account is used.</p>
<form method="post" action="/authorize">
{{range $name, $value := .}}<input type="hidden" name="{{$name}}" value="{{$value}}">{{end}}
<label for="subject">Synthetic subject</label>
<input id="subject" name="subject" value="synthetic-owner" required maxlength="255">
<button id="authorize" type="submit">Authorize synthetic owner</button>
</form></body></html>`))

func (s *Server) serveToken(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.exchanges++
	block := s.block
	s.mu.Unlock()
	if block != nil {
		// Several callbacks may reach this endpoint during concurrency tests.
		// Close once while holding the mutex shared by those requests.
		s.mu.Lock()
		select {
		case <-block.entered:
		default:
			close(block.entered)
		}
		s.mu.Unlock()
		select {
		case <-block.release:
		case <-r.Context().Done():
			return
		}
	}
	s.mu.Lock()
	redirect := s.redirects[r.URL.Path]
	response := s.tokenResponse
	s.mu.Unlock()
	if redirect != "" {
		http.Redirect(w, r, redirect, http.StatusFound)
		return
	}
	if response != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(response.status)
		_, _ = io.WriteString(w, response.body)
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	clientID, secret, ok := r.BasicAuth()
	if !ok || clientID != s.ClientID || secret != s.ClientSecret {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid_client"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := r.ParseForm(); err != nil || r.Form.Get("grant_type") != "authorization_code" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_request"})
		return
	}
	s.mu.Lock()
	auth, exists := s.codes[r.Form.Get("code")]
	if exists {
		// An attempted authenticated exchange always consumes its code.
		delete(s.codes, r.Form.Get("code"))
	}
	claims := copyMap(s.claims)
	algorithm, invalidSignature := s.signingAlgorithm, s.invalidSignature
	s.mu.Unlock()
	digest := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
	if !exists || r.Form.Get("code_verifier") == "" ||
		base64.RawURLEncoding.EncodeToString(digest[:]) != auth.challenge ||
		(auth.redirectURI != "" && r.Form.Get("redirect_uri") != auth.redirectURI) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_grant"})
		return
	}
	now := time.Now().Unix()
	tokenClaims := map[string]any{
		"iss": s.Issuer, "sub": auth.subject, "aud": s.ClientID,
		"iat": now, "exp": now + 300, "nonce": auth.nonce,
	}
	applyOverrides(tokenClaims, claims)
	idToken, err := s.sign(tokenClaims, algorithm, invalidSignature)
	if err != nil {
		http.Error(w, "synthetic signing unavailable", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": "synthetic-access-token", "token_type": "Bearer",
		"expires_in": 300, "id_token": idToken,
	})
}

func (s *Server) sign(claims map[string]any, algorithm string, invalid bool) (string, error) {
	header, err := json.Marshal(map[string]any{"typ": "JWT", "alg": algorithm, "kid": "synthetic-rsa"})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	var signature []byte
	switch algorithm {
	case "none":
	case "HS256":
		mac := hmac.New(sha256.New, []byte(s.ClientSecret))
		_, _ = mac.Write([]byte(input))
		signature = mac.Sum(nil)
	case "RS384":
		digest := sha512.Sum384([]byte(input))
		signature, err = rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA384, digest[:])
	case "RS512":
		digest := sha512.Sum512([]byte(input))
		signature, err = rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA512, digest[:])
	default:
		digest := sha256.Sum256([]byte(input))
		signature, err = rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, digest[:])
	}
	if err != nil {
		return "", fmt.Errorf("sign synthetic ID token: %w", err)
	}
	if invalid {
		if len(signature) == 0 {
			signature = []byte("invalid")
		} else {
			signature[0] ^= 0xff
		}
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func applyOverrides(destination, overrides map[string]any) {
	for name, value := range overrides {
		if value == nil {
			delete(destination, name)
		} else {
			destination[name] = value
		}
	}
}

func copyMap(source map[string]any) map[string]any {
	if source == nil {
		return make(map[string]any)
	}
	// Clone nested arrays/maps too, so the fixture never retains caller-owned
	// mutable claim values. These fixture APIs accept JSON values.
	encoded, err := json.Marshal(source)
	if err != nil {
		panic(fmt.Sprintf("synthetic OIDC values are not JSON: %v", err))
	}
	var copy map[string]any
	decoder := json.NewDecoder(strings.NewReader(string(encoded)))
	decoder.UseNumber()
	if err := decoder.Decode(&copy); err != nil {
		panic(fmt.Sprintf("clone synthetic OIDC values: %v", err))
	}
	return copy
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
