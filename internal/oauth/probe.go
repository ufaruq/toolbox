package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/ufaruq/toolbox/internal/security"
	"github.com/ufaruq/toolbox/internal/strict"
)

var ErrProbe = errors.New("GOOGLE_PKCE_PROBE_FAILED")

type ProbeStatus struct {
	Completed int
	Done      bool
	Failed    bool
}
type probeTransaction struct {
	state, nonce, verifier string
	expiry                 time.Time
}

// PKCEProbe is an isolated operator tool. It never establishes a connection,
// writes a credential store, or changes the runtime's PKCE release assertion.
// Use a dedicated Google test client: cleanup revokes its app authorization.
type PKCEProbe struct {
	mu        sync.Mutex
	provider  *GoogleProvider
	status    ProbeStatus
	pending   *probeTransaction
	cleanup   []string
	seenCodes map[string]bool
}

func NewPKCEProbe(config GoogleConfig) (*PKCEProbe, error) {
	// Only this isolated test tool may construct a provider before the gate.
	// Positive tests still use the normal signature/nonce/scope validation.
	config.PKCEValidated, config.IdentityScopes = true, true
	p, err := NewGoogleProvider(config)
	if err != nil {
		return nil, err
	}
	return &PKCEProbe{provider: p, seenCodes: map[string]bool{}}, nil
}
func (p *PKCEProbe) Status() ProbeStatus { p.mu.Lock(); defer p.mu.Unlock(); return p.status }
func (p *PKCEProbe) Begin() (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.status.Done || p.status.Failed || p.pending != nil {
		return "", ErrProbe
	}
	tx := &probeTransaction{state: security.ID() + "." + security.Random(), nonce: security.Random(), verifier: security.Random(), expiry: p.provider.now().Add(TransactionLifetime)}
	u, err := p.provider.AuthorizationURL(tx.state, tx.nonce, challengeFor(tx.verifier))
	if err != nil {
		return "", err
	}
	p.pending = tx
	return u, nil
}
func (p *PKCEProbe) Complete(ctx context.Context, state, code string) (ProbeStatus, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	tx := p.pending
	if tx == nil || !security.Equal(state, tx.state) || !p.provider.now().Before(tx.expiry) || code == "" || len(code) > 4096 || strings.ContainsAny(code, "\x00\r\n") || p.seenCodes[security.Hash(code)] {
		return p.status, ErrCallback
	}
	p.seenCodes[security.Hash(code)] = true
	p.pending = nil // Consume before the non-idempotent provider exchange.
	var err error
	if p.status.Completed == 0 || p.status.Completed == 3 {
		var result ExchangeResult
		result, err = p.provider.Exchange(ctx, code, tx.verifier, security.Hash(tx.nonce))
		p.retain(result.AccessToken, result.RefreshToken)
		if err == nil && result.RefreshToken == "" {
			err = ErrProbe
		}
	} else {
		form := url.Values{"client_id": {p.provider.clientID}, "client_secret": {p.provider.clientSecret}, "redirect_uri": {p.provider.callbackURL}, "code": {code}, "grant_type": {"authorization_code"}}
		if p.status.Completed == 2 {
			form.Set("code_verifier", security.Random())
		}
		var data []byte
		var status int
		data, status, err = p.provider.post(ctx, googleTokenEndpoint, form)
		if err == nil {
			err = p.negativeResult(data, status)
		}
	}
	if err != nil {
		p.status.Failed = true
		_ = p.closeLocked(context.WithoutCancel(ctx))
		return p.status, ErrProbe
	}
	p.status.Completed++
	if p.status.Completed == 4 {
		if err := p.closeLocked(context.WithoutCancel(ctx)); err != nil {
			p.status.Failed = true
			return p.status, ErrProbe
		}
		p.status.Done = true
	}
	return p.status, nil
}
func (p *PKCEProbe) negativeResult(data []byte, status int) error {
	var values map[string]json.RawMessage
	if strict.Decode(data, &values) != nil || values == nil {
		return ErrProbe
	}
	get := func(key string) string {
		var s string
		if json.Unmarshal(values[key], &s) != nil || len(s) > 65536 {
			return ""
		}
		return s
	}
	if status == http.StatusOK {
		p.retain(get("access_token"), get("refresh_token"))
		return ErrProbe
	}
	// A client/configuration failure is not evidence of PKCE enforcement.
	if status != http.StatusBadRequest {
		return ErrProbe
	}
	if get("error") == "invalid_grant" || get("error") == "invalid_request" && strings.Contains(strings.ToLower(get("error_description")), "verifier") {
		return nil
	}
	return ErrProbe
}
func (p *PKCEProbe) retain(access, refresh string) {
	if refresh != "" {
		p.cleanup = append(p.cleanup, refresh)
	} else if access != "" {
		p.cleanup = append(p.cleanup, access)
	}
}
func (p *PKCEProbe) Close(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pending = nil
	return p.closeLocked(ctx)
}
func (p *PKCEProbe) closeLocked(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	remaining := []string{}
	for _, token := range p.cleanup {
		if p.provider.Revoke(ctx, token) != nil {
			remaining = append(remaining, token)
		}
	}
	p.cleanup = remaining
	if len(remaining) > 0 {
		return ErrProbe
	}
	return nil
}
