// Package identity verifies user identities against one configured Okta custom
// authorization server. Configure its immutable uid claim on BOTH the owner's
// ID tokens and the MCP API access tokens; sub is deliberately not an owner key.
package identity

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/ufaruq/toolbox/internal/security"
	"golang.org/x/oauth2"
)

// Config pins the issuer, API audience, supported agent clients, and a separate
// confidential OIDC client for owner login. AllowLoopbackHTTP is for fixtures
// only and must never be enabled by hosted configuration.
type Config struct {
	Issuer, Audience, OwnerClientID, OwnerClientSecret, OwnerCallbackURL, OwnerIssuer string
	Clients                                                                           map[string]string
	AllowLoopbackHTTP                                                                 bool
}
type Claims struct {
	Issuer, UserID, ClientID string
	ExpiresAt                time.Time
}
type Owner struct{ Issuer, UserID string }

// Errors intentionally omit provider responses, codes, JWTs, and credentials.
var (
	errConfig        = errors.New("invalid identity configuration")
	errDiscovery     = errors.New("identity provider unavailable")
	errAccess        = errors.New("invalid access token")
	errAuthorization = errors.New("invalid authorization request")
	errComplete      = errors.New("owner authentication failed")
)

type Service struct {
	issuer                        string
	ownerIssuer                   string
	clients                       map[string]string
	ownerClientID                 string
	client                        *http.Client
	oauth                         oauth2.Config
	accessVerifier, ownerVerifier *oidc.IDTokenVerifier
}

func New(ctx context.Context, cfg Config) (*Service, error) { return newIdentity(ctx, cfg, false) }

func newIdentity(ctx context.Context, cfg Config, accessOnly bool) (*Service, error) {
	ownerIssuer := cfg.Issuer
	if accessOnly {
		if !ValidOwnerBinding(cfg.OwnerIssuer, cfg.Issuer, cfg.AllowLoopbackHTTP) {
			return nil, errConfig
		}
		ownerIssuer = cfg.OwnerIssuer
	}
	if !safeURL(cfg.Issuer, cfg.AllowLoopbackHTTP) || (!accessOnly && (!safeURL(cfg.OwnerCallbackURL, cfg.AllowLoopbackHTTP) || cfg.OwnerClientSecret == "")) || !nonblank(cfg.Audience) || !nonblank(cfg.OwnerClientID) || cfg.Audience == cfg.OwnerClientID || len(cfg.Clients) == 0 {
		return nil, errConfig
	}
	issuerURL, _ := url.Parse(cfg.Issuer)
	if issuerURL.RawQuery != "" || issuerURL.ForceQuery {
		return nil, errConfig
	}
	clients := make(map[string]string, len(cfg.Clients))
	for id, name := range cfg.Clients {
		if !nonblank(id) || !nonblank(name) || id == cfg.Audience {
			return nil, errConfig
		}
		clients[id] = name
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSHandshakeTimeout = 5 * time.Second
	transport.ResponseHeaderTimeout = 5 * time.Second
	client := &http.Client{Timeout: 10 * time.Second, Transport: &boundedTransport{base: transport, allowLoopbackHTTP: cfg.AllowLoopbackHTTP}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	provider, err := oidc.NewProvider(oidc.ClientContext(ctx, client), cfg.Issuer)
	if err != nil {
		return nil, errDiscovery
	}
	var discovery struct {
		JWKSURL string `json:"jwks_uri"`
	}
	if provider.Claims(&discovery) != nil || !safeURL(discovery.JWKSURL, cfg.AllowLoopbackHTTP) {
		return nil, errDiscovery
	}
	endpoint := provider.Endpoint()
	if !safeURL(endpoint.AuthURL, cfg.AllowLoopbackHTTP) || !safeURL(endpoint.TokenURL, cfg.AllowLoopbackHTTP) {
		return nil, errDiscovery
	}
	// The confidential owner client uses client_secret_basic; do not probe token
	// endpoints with alternative authentication styles or put secrets in URLs.
	endpoint.AuthStyle = oauth2.AuthStyleInHeader
	service := &Service{
		ownerIssuer: ownerIssuer, issuer: cfg.Issuer, clients: clients, ownerClientID: cfg.OwnerClientID, client: client,
		oauth: oauth2.Config{
			ClientID: cfg.OwnerClientID, ClientSecret: cfg.OwnerClientSecret,
			RedirectURL: cfg.OwnerCallbackURL, Endpoint: endpoint, Scopes: []string{oidc.ScopeOpenID},
		},
		accessVerifier: provider.Verifier(&oidc.Config{ClientID: cfg.Audience, SupportedSigningAlgs: []string{oidc.RS256}}),
		ownerVerifier:  provider.Verifier(&oidc.Config{ClientID: cfg.OwnerClientID, SupportedSigningAlgs: []string{oidc.RS256}}),
	}
	if accessOnly {
		service.ownerVerifier = nil
	}
	return service, nil
}

// VerifyAccess verifies the API JWT's signature, issuer and audience using the
// maintained OIDC verifier, then applies Okta user-access-token policy. This is
// unrelated to IDToken.VerifyAccessToken, which only checks an at_hash binding.
func (s *Service) VerifyAccess(ctx context.Context, raw string) (Claims, error) {
	if len(raw) == 0 || len(raw) > 16384 {
		return Claims{}, errAccess
	}
	token, err := s.accessVerifier.Verify(oidc.ClientContext(ctx, s.client), raw)
	if err != nil || token.Issuer != s.issuer {
		return Claims{}, errAccess
	}
	var c userClaims
	if token.Claims(&c) != nil || !validUserClaims(c, time.Now()) || !nonblank(c.ClientID) {
		return Claims{}, errAccess
	}
	if _, ok := s.clients[c.ClientID]; !ok {
		return Claims{}, errAccess
	}
	// Reject ID-token audiences even if an ambiguous multi-audience JWT also
	// includes the API audience. API and OIDC client audiences must be separate.
	for _, aud := range token.Audience {
		if aud == s.ownerClientID {
			return Claims{}, errAccess
		}
		if _, ok := s.clients[aud]; ok {
			return Claims{}, errAccess
		}
	}
	hasScope := false
	for _, scope := range c.Scopes {
		if scope == "mcp" {
			hasScope = true
		}
	}
	if !hasScope {
		return Claims{}, errAccess
	}
	return Claims{Issuer: s.issuer, UserID: c.UserID, ClientID: c.ClientID, ExpiresAt: time.Unix(c.ExpiresAt, 0)}, nil
}
func (s *Service) AuthorizationURL(state, nonce, verifier string) (string, error) {
	if s.ownerVerifier == nil || !boundedInput(state, 1024) || !boundedInput(nonce, 1024) || !validVerifier(verifier) {
		return "", errAuthorization
	}
	return s.oauth.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)), nil
}

// Complete exchanges the one-time code using the fixed callback and PKCE, and
// returns only the immutable owner identity. OAuth tokens remain private here.
func (s *Service) Complete(ctx context.Context, code, verifier, nonceHash string) (Owner, error) {
	if s.ownerVerifier == nil || !boundedInput(code, 4096) || !validVerifier(verifier) || !validHash(nonceHash) {
		return Owner{}, errComplete
	}
	ctx = oidc.ClientContext(ctx, s.client)
	oauthToken, err := s.oauth.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return Owner{}, errComplete
	}
	raw, ok := oauthToken.Extra("id_token").(string)
	if !ok || len(raw) == 0 || len(raw) > 16384 {
		return Owner{}, errComplete
	}
	token, err := s.ownerVerifier.Verify(ctx, raw)
	if err != nil || token.Issuer != s.issuer || len(token.Audience) != 1 || token.Audience[0] != s.ownerClientID || token.Nonce == "" || !security.Equal(security.Hash(token.Nonce), nonceHash) {
		return Owner{}, errComplete
	}
	var c userClaims
	if token.Claims(&c) != nil || !validUserClaims(c, time.Now()) || (c.AuthorizedParty != "" && c.AuthorizedParty != s.ownerClientID) {
		return Owner{}, errComplete
	}
	return Owner{Issuer: s.issuer, UserID: c.UserID}, nil
}
func (s *Service) Clients() map[string]string {
	clients := make(map[string]string, len(s.clients))
	for k, v := range s.clients {
		clients[k] = v
	}
	return clients
}
func (s *Service) Issuer() string      { return s.issuer }
func (s *Service) OwnerIssuer() string { return s.ownerIssuer }

type userClaims struct {
	AuthorizedParty string          `json:"azp"`
	UserID          string          `json:"uid"`
	ClientID        string          `json:"cid"`
	Scopes          []string        `json:"scp"`
	IssuedAt        int64           `json:"iat"`
	ExpiresAt       int64           `json:"exp"`
	NotBefore       json.RawMessage `json:"nbf"`
}

func validUserClaims(c userClaims, now time.Time) bool {
	// go-oidc allows five minutes of nbf skew and does not constrain iat. Keep
	// API/owner policy explicit: at most 60s future skew, no expiry leeway.
	if !nonblank(c.UserID) || len(c.UserID) > 256 || c.IssuedAt <= 0 || c.IssuedAt > now.Unix()+60 || c.ExpiresAt <= now.Unix() || c.ExpiresAt <= c.IssuedAt {
		return false
	}
	if len(c.NotBefore) == 0 {
		return true
	}
	var notBefore *int64
	return json.Unmarshal(c.NotBefore, &notBefore) == nil && notBefore != nil && *notBefore >= 0 && *notBefore <= now.Unix()+60
}
func nonblank(s string) bool              { return s != "" && strings.TrimSpace(s) == s }
func boundedInput(s string, max int) bool { return nonblank(s) && len(s) <= max }
func validVerifier(s string) bool {
	if len(s) < 43 || len(s) > 128 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("-._~", c)) {
			return false
		}
	}
	return true
}
func validHash(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func safeURL(raw string, allowLoopbackHTTP bool) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	if !allowLoopbackHTTP || u.Scheme != "http" {
		return false
	}
	host := u.Hostname()
	ip := net.ParseIP(host)
	return host == "localhost" || (ip != nil && ip.IsLoopback())
}

type boundedTransport struct {
	base              http.RoundTripper
	allowLoopbackHTTP bool
}

func (t *boundedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if !safeURL(r.URL.String(), t.allowLoopbackHTTP) {
		return nil, errDiscovery
	}
	response, err := t.base.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	// Bound discovery, JWKS and token bodies, including chunked responses.
	const maxBody = 1 << 20
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxBody+1))
	if err != nil || len(body) > maxBody {
		return nil, errDiscovery
	}
	response.Body = io.NopCloser(strings.NewReader(string(body)))
	return response, nil
}
