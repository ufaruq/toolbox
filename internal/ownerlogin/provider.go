// Package ownerlogin establishes first-party sessions from verified owner identities.
package ownerlogin

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/ufaruq/toolbox/internal/security"
	"github.com/ufaruq/toolbox/internal/strict"
	"golang.org/x/oauth2"
)

// Identity contains only the verified stable identity, never provider credentials.
type Identity struct{ Issuer, Subject string }

// Provider is the owner identity boundary; it is independent of Google consent.
type Provider interface {
	AuthorizationURL(state, nonce, challenge string) (string, error)
	Exchange(context.Context, string, string, string) (Identity, error)
}

type ProviderConfig struct{ Issuer, ClientID, ClientSecret, RedirectURI string }

var errProvider = errors.New("owner identity provider unavailable or response rejected")

const providerResponseLimit = 1 << 20

type oidcProvider struct {
	issuer   string
	clientID string
	client   *http.Client
	oauth    oauth2.Config
	verifier *oidc.IDTokenVerifier
}

// NewProvider discovers only the configured HTTPS issuer. The optional client is
// trusted application/test transport configuration, not a browser-supplied value.
// ctx must have application lifetime: cancelling it stops even background JWKS IO.
func NewProvider(ctx context.Context, cfg ProviderConfig, client *http.Client) (Provider, error) {
	issuer, err := providerURL(cfg.Issuer)
	if ctx == nil || err != nil || !safeProviderValue(cfg.ClientID, 2048) || !safeProviderValue(cfg.ClientSecret, 4096) || !providerCallback(cfg.RedirectURI) {
		return nil, errors.New("invalid owner identity provider configuration")
	}
	client = providerHTTP(ctx, issuer, client)
	providerCtx := oidc.ClientContext(ctx, client)
	discovered, err := oidc.NewProvider(providerCtx, cfg.Issuer)
	if err != nil {
		return nil, errProvider
	}
	var rawMetadata json.RawMessage
	var fields map[string]json.RawMessage
	if discovered.Claims(&rawMetadata) != nil || strict.Decode(rawMetadata, &fields) != nil {
		return nil, errProvider
	}
	var discoveredIssuer string
	if json.Unmarshal(fields["issuer"], &discoveredIssuer) != nil || discoveredIssuer != cfg.Issuer {
		return nil, errProvider
	}
	endpoints := make(map[string]string, 3)
	for _, key := range []string{"authorization_endpoint", "token_endpoint", "jwks_uri"} {
		var raw string
		if json.Unmarshal(fields[key], &raw) != nil {
			return nil, errProvider
		}
		endpoint, err := providerURL(raw)
		if err != nil || endpoint.Host != issuer.Host {
			return nil, errProvider
		}
		endpoints[key] = raw
	}
	// An explicit auth style prevents oauth2's client-authentication probe from
	// retrying an authorization code after a failed exchange. Construct endpoints
	// from exact JSON keys, avoiding encoding/json's case-insensitive aliases.
	endpoint := oauth2.Endpoint{AuthURL: endpoints["authorization_endpoint"], TokenURL: endpoints["token_endpoint"], AuthStyle: oauth2.AuthStyleInHeader}
	return &oidcProvider{
		issuer: cfg.Issuer, clientID: cfg.ClientID, client: client,
		oauth:    oauth2.Config{ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret, RedirectURL: cfg.RedirectURI, Scopes: []string{oidc.ScopeOpenID}, Endpoint: endpoint},
		verifier: oidc.NewVerifier(cfg.Issuer, oidc.NewRemoteKeySet(providerCtx, endpoints["jwks_uri"]), &oidc.Config{ClientID: cfg.ClientID, SupportedSigningAlgs: []string{oidc.RS256}}),
	}, nil
}

func (p *oidcProvider) AuthorizationURL(state, nonce, challenge string) (string, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(challenge)
	if !safeProviderValue(state, 256) || !safeProviderValue(nonce, 256) || err != nil || len(decoded) != 32 {
		return "", errProvider
	}
	return p.oauth.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.SetAuthURLParam("code_challenge", challenge), oauth2.SetAuthURLParam("code_challenge_method", "S256")), nil
}

func (p *oidcProvider) Exchange(ctx context.Context, code, verifier, nonceHash string) (Identity, error) {
	if ctx.Err() != nil || !safeProviderValue(code, 4096) || !pkceValue(verifier, 43, 128) || len(nonceHash) != 64 {
		return Identity{}, errProvider
	}
	token, err := p.oauth.Exchange(oidc.ClientContext(ctx, p.client), code, oauth2.VerifierOption(verifier))
	if err != nil {
		return Identity{}, errProvider
	}
	raw, ok := token.Extra("id_token").(string)
	if !ok || raw == "" {
		return Identity{}, errProvider
	}
	verified, err := p.verifier.Verify(ctx, raw)
	if err != nil || verified.Issuer != p.issuer || !safeProviderValue(verified.Subject, 255) || verified.Nonce == "" || !security.Equal(security.Hash(verified.Nonce), nonceHash) {
		return Identity{}, errProvider
	}
	// Claims preserves the signed JSON. Reject duplicate claim names while
	// allowing provider extension claims, then validate the stricter local policy.
	var payload json.RawMessage
	var claims map[string]json.RawMessage
	if verified.Claims(&payload) != nil || strict.Decode(payload, &claims) != nil {
		return Identity{}, errProvider
	}
	// encoding/json accepts case-insensitive struct field aliases, whereas OIDC
	// claim names are case-sensitive. Require exact signed keys and agreement
	// with the library's verified interpretation before using an identity.
	var issuer, subject, nonce string
	if json.Unmarshal(claims["iss"], &issuer) != nil || issuer != verified.Issuer || json.Unmarshal(claims["sub"], &subject) != nil || subject != verified.Subject || json.Unmarshal(claims["nonce"], &nonce) != nil || nonce != verified.Nonce {
		return Identity{}, errProvider
	}
	var audience []string
	var singleAudience string
	if json.Unmarshal(claims["aud"], &singleAudience) == nil {
		audience = []string{singleAudience}
	} else if json.Unmarshal(claims["aud"], &audience) != nil {
		return Identity{}, errProvider
	}
	if !slices.Equal(audience, verified.Audience) || !slices.Contains(audience, p.clientID) {
		return Identity{}, errProvider
	}
	var issuedAt, expiry int64
	if json.Unmarshal(claims["iat"], &issuedAt) != nil || issuedAt <= 0 || json.Unmarshal(claims["exp"], &expiry) != nil || expiry <= 0 {
		return Identity{}, errProvider
	}
	now := time.Now()
	if time.Unix(issuedAt, 0).After(now.Add(60*time.Second)) || !now.Before(time.Unix(expiry, 0)) {
		return Identity{}, errProvider
	}
	if raw, ok := claims["nbf"]; ok {
		var notBefore int64
		if json.Unmarshal(raw, &notBefore) != nil || notBefore <= 0 || now.Before(time.Unix(notBefore, 0)) {
			return Identity{}, errProvider
		}
	}
	if raw, ok := claims["azp"]; ok {
		var authorizedParty string
		if json.Unmarshal(raw, &authorizedParty) != nil || authorizedParty != p.clientID {
			return Identity{}, errProvider
		}
	} else if len(verified.Audience) > 1 {
		return Identity{}, errProvider
	}
	return Identity{Issuer: verified.Issuer, Subject: verified.Subject}, nil
}

func safeProviderValue(s string, max int) bool {
	return s != "" && len(s) <= max && !strings.ContainsFunc(s, unicode.IsControl)
}

func pkceValue(s string, min, max int) bool {
	if len(s) < min || len(s) > max {
		return false
	}
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || strings.ContainsRune("-._~", c)) {
			return false
		}
	}
	return true
}

func providerURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || len(raw) > 2048 || u.Scheme != "https" || u.Host == "" || u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return nil, errProvider
	}
	return u, nil
}

func providerCallback(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && len(raw) <= 2048 && u.Host != "" && u.Opaque == "" && u.User == nil && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && (u.Scheme == "http" || u.Scheme == "https")
}

// boundedHTTP owns endpoint policy and response buffering. Buffering is needed
// because oauth2 independently truncates token bodies at 1 MiB, which could hide
// an oversized response's trailing bytes from a streaming limit reader.
type boundedHTTP struct {
	lifetime context.Context
	origin   string
	base     http.RoundTripper
}

func providerHTTP(ctx context.Context, issuer *url.URL, supplied *http.Client) *http.Client {
	client := &http.Client{Timeout: 10 * time.Second}
	if supplied != nil {
		*client = *supplied
		if client.Timeout <= 0 || client.Timeout > 10*time.Second {
			client.Timeout = 10 * time.Second
		}
	}
	base := client.Transport
	if base == nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.Proxy = nil // No implicit trust of arbitrary proxy environment variables.
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		base = transport
	}
	client.Jar = nil
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return errProvider }
	client.Transport = boundedHTTP{lifetime: ctx, origin: issuer.Scheme + "://" + issuer.Host, base: base}
	return client
}

func (t boundedHTTP) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme+"://"+r.URL.Host != t.origin || r.URL.User != nil || t.lifetime.Err() != nil {
		return nil, errProvider
	}
	ctx, cancel := context.WithCancel(r.Context())
	stop := context.AfterFunc(t.lifetime, cancel)
	defer stop()
	defer cancel()
	response, err := t.base.RoundTrip(r.Clone(ctx))
	if err != nil {
		return nil, errProvider
	}
	defer response.Body.Close()
	if response.ContentLength > providerResponseLimit {
		return nil, errProvider
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, providerResponseLimit+1))
	if err != nil || len(body) > providerResponseLimit {
		return nil, errProvider
	}
	response.Body = io.NopCloser(bytes.NewReader(body))
	response.ContentLength = int64(len(body))
	return response, nil
}
