package oauth

import (
	"context"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/ufaruq/toolbox/internal/domain"
	"github.com/ufaruq/toolbox/internal/security"
	"github.com/ufaruq/toolbox/internal/tokens"
)

// FixtureProvider is an explicit in-memory fake. Its locally asserted subject is
// not authentication and must never be reachable in production mode.
type FixtureProvider struct {
	mu                                           sync.Mutex
	clientID, callbackURL, authorizationEndpoint string
	codes                                        map[string]fixtureCode
	refresh                                      map[string]bool
	now                                          func() time.Time
	exchangeCalls                                int
}
type fixtureCode struct {
	subject, nonce, challenge string
	expires                   time.Time
	noRefresh                 bool
	scopes                    []string
}

var _ Provider = (*FixtureProvider)(nil)
var _ tokens.Provider = (*FixtureProvider)(nil)

func NewFixtureProvider(clientID, callbackURL string) (*FixtureProvider, error) {
	if clientID == "" || !validCallback(callbackURL, true) {
		return nil, ErrConfiguration
	}
	callback, _ := url.Parse(callbackURL)
	endpoint := callback.Scheme + "://" + callback.Host + "/fixture/google/authorize"
	return &FixtureProvider{clientID: clientID, callbackURL: callbackURL, authorizationEndpoint: endpoint, codes: map[string]fixtureCode{}, refresh: map[string]bool{}, now: time.Now}, nil
}
func (p *FixtureProvider) ClientID() string { return p.clientID }
func (p *FixtureProvider) AuthorizationURL(state, nonce, challenge string) (string, error) {
	if _, _, err := security.CredentialParts(state); err != nil || !validVerifier(nonce) || !validVerifier(challenge) {
		return "", ErrConfiguration
	}
	return p.authorizationEndpoint + "?" + authorizationValues(p.clientID, p.callbackURL, state, nonce, challenge).Encode(), nil
}

// Authorize simulates consent and returns a callback URL containing a one-use
// fixture code. The caller chooses a synthetic subject only in fixture mode.
func (p *FixtureProvider) Authorize(ctx context.Context, authorizationURL, subject string) (string, error) {
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	u, err := url.Parse(authorizationURL)
	if err != nil || u.User != nil || u.Fragment != "" || u.Scheme+"://"+u.Host+u.Path != p.authorizationEndpoint || !validSubject(subject) {
		return "", ErrCallback
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return "", ErrCallback
	}
	expected := authorizationValues(p.clientID, p.callbackURL, query.Get("state"), query.Get("nonce"), query.Get("code_challenge"))
	if len(query) != len(expected) {
		return "", ErrCallback
	}
	for key, values := range expected {
		if len(query[key]) != 1 || query.Get(key) != values[0] {
			return "", ErrCallback
		}
	}
	if _, _, err = security.CredentialParts(query.Get("state")); err != nil || !validVerifier(query.Get("nonce")) || !validVerifier(query.Get("code_challenge")) {
		return "", ErrCallback
	}
	code := security.Random()
	p.mu.Lock()
	p.codes[code] = fixtureCode{subject: subject, nonce: query.Get("nonce"), challenge: query.Get("code_challenge"), expires: p.now().Add(TransactionLifetime), scopes: []string{"openid", domain.DriveScope}}
	p.mu.Unlock()
	callback, _ := url.Parse(p.callbackURL)
	callback.RawQuery = url.Values{"state": {query.Get("state")}, "code": {code}}.Encode()
	return callback.String(), nil
}
func (p *FixtureProvider) Exchange(ctx context.Context, code, verifier, nonceHash string) (ExchangeResult, error) {
	if ctx.Err() != nil {
		return ExchangeResult{}, ctx.Err()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.exchangeCalls++
	c, ok := p.codes[code]
	delete(p.codes, code)
	if !ok || !p.now().Before(c.expires) || !validVerifier(verifier) || !security.Equal(c.challenge, challengeFor(verifier)) || !security.Equal(security.Hash(c.nonce), nonceHash) {
		return ExchangeResult{}, ErrIdentity
	}
	refresh := "fixture-refresh-" + security.Random()
	if c.noRefresh {
		refresh = ""
	} else {
		p.refresh[refresh] = true
	}
	return ExchangeResult{Subject: c.subject, ClientID: p.clientID, AccessToken: "fixture-access-" + security.Random(), RefreshToken: refresh, Expiry: p.now().Add(time.Hour), Scopes: append([]string(nil), c.scopes...)}, nil
}
func (p *FixtureProvider) ExchangeCalls() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.exchangeCalls
}
func (p *FixtureProvider) Refresh(ctx context.Context, refreshToken string) (tokens.RefreshResult, error) {
	if ctx.Err() != nil {
		return tokens.RefreshResult{}, ctx.Err()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.refresh[refreshToken] {
		return tokens.RefreshResult{}, tokens.ErrInvalidGrant
	}
	return tokens.RefreshResult{AccessToken: "fixture-access-" + security.Random(), Expiry: p.now().Add(time.Hour), Scopes: []string{"openid", domain.DriveScope}}, nil
}
func (p *FixtureProvider) Revoke(ctx context.Context, token string) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if strings.HasPrefix(token, "fixture-refresh-") {
		delete(p.refresh, token)
	}
	return nil
}
