package oauth

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ufaruq/toolbox/internal/domain"
	"github.com/ufaruq/toolbox/internal/security"
	"github.com/ufaruq/toolbox/internal/strict"
	"github.com/ufaruq/toolbox/internal/tokens"
)

const (
	googleAuthorizationEndpoint = "https://accounts.google.com/o/oauth2/v2/auth"
	googleTokenEndpoint         = "https://oauth2.googleapis.com/token"
	googleRevocationEndpoint    = "https://oauth2.googleapis.com/revoke"
	googleJWKSEndpoint          = "https://www.googleapis.com/oauth2/v3/certs"
	maxProviderResponse         = 1 << 20
)

// GoogleConfig is trusted server configuration, never request input. PKCEValidated
// is an explicit release gate: set it only after negative tests demonstrate that
// this actual Google web-client configuration rejects absent/wrong verifiers.
type GoogleConfig struct {
	ClientID          string
	ClientSecret      string
	CallbackURL       string
	PKCEValidated     bool
	AllowLoopbackHTTP bool
}

type GoogleProvider struct {
	clientID, clientSecret, callbackURL string
	client                              *http.Client
	now                                 func() time.Time
	mu                                  sync.Mutex
	keys                                map[string]*rsa.PublicKey
	keysExpire                          time.Time
}

var _ Provider = (*GoogleProvider)(nil)
var _ tokens.Provider = (*GoogleProvider)(nil)

func NewGoogleProvider(config GoogleConfig) (*GoogleProvider, error) {
	if !config.PKCEValidated || config.ClientID == "" || config.ClientSecret == "" || !validCallback(config.CallbackURL, config.AllowLoopbackHTTP) {
		return nil, ErrConfiguration
	}
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           publicDial,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          10,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
	}
	client := &http.Client{Transport: transport, Timeout: 12 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &GoogleProvider{clientID: config.ClientID, clientSecret: config.ClientSecret, callbackURL: config.CallbackURL, client: client, now: time.Now, keys: map[string]*rsa.PublicKey{}}, nil
}

func validCallback(raw string, allowLoopback bool) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "/v1/oauth/google/callback" && u.Path != "/oauth/callback") || u.RawPath != "" {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	return allowLoopback && u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1")
}

// DNS results are checked before dialing the selected numeric address. Google
// endpoints are constants; redirects and ambient proxy variables are disabled.
func publicDial(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || port != "443" {
		return nil, ErrProvider
	}
	if host != "oauth2.googleapis.com" && host != "www.googleapis.com" {
		return nil, ErrProvider
	}
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, ErrProvider
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	for _, address := range addresses {
		ip := address.IP
		if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return nil, ErrProvider
		}
	}
	for _, address := range addresses {
		conn, e := dialer.DialContext(ctx, network, net.JoinHostPort(address.IP.String(), port))
		if e == nil {
			return conn, nil
		}
	}
	return nil, ErrProvider
}

func (p *GoogleProvider) ClientID() string { return p.clientID }
func (p *GoogleProvider) AuthorizationURL(state, nonce, challenge string) (string, error) {
	if _, _, err := security.CredentialParts(state); err != nil || !validVerifier(nonce) || !validVerifier(challenge) {
		return "", ErrConfiguration
	}
	values := authorizationValues(p.clientID, p.callbackURL, state, nonce, challenge)
	return googleAuthorizationEndpoint + "?" + values.Encode(), nil
}
func authorizationValues(clientID, callback, state, nonce, challenge string) url.Values {
	return url.Values{
		"client_id": {clientID}, "redirect_uri": {callback}, "response_type": {"code"},
		"scope": {"openid " + domain.DriveScope}, "state": {state}, "nonce": {nonce},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"},
		"access_type": {"offline"}, "prompt": {"consent select_account"}, "include_granted_scopes": {"false"},
	}
}
func challengeFor(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}
func validVerifier(v string) bool {
	if len(v) != 43 {
		return false
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(v)
	return err == nil && len(b) == 32
}

func (p *GoogleProvider) Exchange(ctx context.Context, code, verifier, nonceHash string) (ExchangeResult, error) {
	var none ExchangeResult
	if code == "" || len(code) > 4096 || !validVerifier(verifier) || len(nonceHash) != 64 {
		return none, ErrCallback
	}
	start := p.now()
	response, err := p.tokenRequest(ctx, url.Values{"client_id": {p.clientID}, "client_secret": {p.clientSecret}, "redirect_uri": {p.callbackURL}, "code": {code}, "grant_type": {"authorization_code"}, "code_verifier": {verifier}}, false)
	if err != nil {
		return none, err
	}
	subject, err := p.verifyIDToken(ctx, response.IDToken, nonceHash)
	if err != nil {
		return none, err
	}
	scopes := strings.Fields(response.Scope)
	if !exactScopes(scopes) {
		return none, ErrScope
	}
	return ExchangeResult{Subject: subject, ClientID: p.clientID, AccessToken: response.AccessToken, RefreshToken: response.RefreshToken, Expiry: start.Add(time.Duration(response.ExpiresIn) * time.Second), Scopes: scopes}, nil
}

func (p *GoogleProvider) Refresh(ctx context.Context, refreshToken string) (tokens.RefreshResult, error) {
	var none tokens.RefreshResult
	if refreshToken == "" {
		return none, tokens.ErrInvalidGrant
	}
	start := p.now()
	response, err := p.tokenRequest(ctx, url.Values{"client_id": {p.clientID}, "client_secret": {p.clientSecret}, "refresh_token": {refreshToken}, "grant_type": {"refresh_token"}}, true)
	if err != nil {
		return none, err
	}
	scopes := strings.Fields(response.Scope)
	if len(scopes) > 0 && !exactScopes(scopes) {
		return none, tokens.ErrReauth
	}
	return tokens.RefreshResult{AccessToken: response.AccessToken, RefreshToken: response.RefreshToken, Expiry: start.Add(time.Duration(response.ExpiresIn) * time.Second), Scopes: scopes}, nil
}
func (p *GoogleProvider) Revoke(ctx context.Context, token string) error {
	if token == "" {
		return nil
	}
	body, status, err := p.post(ctx, googleRevocationEndpoint, url.Values{"token": {token}})
	if err != nil {
		return ErrProvider
	}
	if status == http.StatusOK {
		return nil
	}
	if status == http.StatusBadRequest {
		var fields map[string]json.RawMessage
		var code string
		if strict.Decode(body, &fields) == nil && json.Unmarshal(fields["error"], &code) == nil && code == "invalid_token" {
			// Google's reference defines this as already expired or revoked.
			// The saved credential is unusable; this does not prove that every
			// historical project/account authorization has been revoked.
			return nil
		}
	}
	return ErrProvider
}

type tokenResponse struct {
	AccessToken, RefreshToken, IDToken, Scope, TokenType string
	ExpiresIn                                            int64
}

func (p *GoogleProvider) tokenRequest(ctx context.Context, form url.Values, refresh bool) (tokenResponse, error) {
	var none tokenResponse
	body, status, err := p.post(ctx, googleTokenEndpoint, form)
	if err != nil {
		if refresh {
			return none, tokens.ErrRefreshUncertain
		}
		return none, ErrProvider
	}
	var fields map[string]json.RawMessage
	if strict.Decode(body, &fields) != nil || fields == nil {
		if refresh {
			return none, tokens.ErrRefreshUncertain
		}
		return none, ErrProvider
	}
	var providerError string
	if b, ok := fields["error"]; ok {
		if json.Unmarshal(b, &providerError) != nil {
			return none, ErrProvider
		}
	}
	if providerError == "invalid_grant" {
		return none, tokens.ErrInvalidGrant
	}
	if status != http.StatusOK || providerError != "" {
		if refresh {
			return none, tokens.ErrRefreshUncertain
		}
		return none, ErrProvider
	}
	var response tokenResponse
	for key, destination := range map[string]*string{"access_token": &response.AccessToken, "refresh_token": &response.RefreshToken, "id_token": &response.IDToken, "scope": &response.Scope, "token_type": &response.TokenType} {
		if b, ok := fields[key]; ok {
			if json.Unmarshal(b, destination) != nil {
				return none, ErrProvider
			}
		}
	}
	if b, ok := fields["expires_in"]; !ok || json.Unmarshal(b, &response.ExpiresIn) != nil {
		return none, ErrProvider
	}
	if response.AccessToken == "" || len(response.AccessToken) > 65536 || len(response.RefreshToken) > 65536 || response.TokenType != "Bearer" || response.ExpiresIn <= 0 || response.ExpiresIn > 86400 {
		return none, ErrProvider
	}
	return response, nil
}
func (p *GoogleProvider) post(ctx context.Context, endpoint string, values url.Values) ([]byte, int, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(values.Encode()))
	if err != nil {
		return nil, 0, ErrProvider
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	response, err := p.client.Do(req)
	if err != nil {
		return nil, 0, ErrProvider
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxProviderResponse+1))
	if err != nil || len(body) > maxProviderResponse {
		return nil, 0, ErrProvider
	}
	return body, response.StatusCode, nil
}

type idHeader struct {
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
	Type      string `json:"typ,omitempty"`
}

func (p *GoogleProvider) verifyIDToken(ctx context.Context, token, nonceHash string) (string, error) {
	if len(token) == 0 || len(token) > 16384 {
		return "", ErrIdentity
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", ErrIdentity
	}
	headerBytes, err := base64.RawURLEncoding.Strict().DecodeString(parts[0])
	var header idHeader
	if err != nil || strict.Decode(headerBytes, &header) != nil || header.Algorithm != "RS256" || header.KeyID == "" || len(header.KeyID) > 256 || (header.Type != "" && header.Type != "JWT") {
		return "", ErrIdentity
	}
	key, err := p.signingKey(ctx, header.KeyID)
	if err != nil {
		return "", ErrIdentity
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if err != nil {
		return "", ErrIdentity
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature) != nil {
		return "", ErrIdentity
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	var claims map[string]json.RawMessage
	if err != nil || strict.Decode(payload, &claims) != nil || claims == nil {
		return "", ErrIdentity
	}
	var issuer, subject, nonce, authorizedParty string
	for key, destination := range map[string]*string{"iss": &issuer, "sub": &subject, "nonce": &nonce, "azp": &authorizedParty} {
		if b, ok := claims[key]; ok {
			if json.Unmarshal(b, destination) != nil {
				return "", ErrIdentity
			}
		}
	}
	if (issuer != "https://accounts.google.com" && issuer != "accounts.google.com") || !validSubject(subject) || nonce == "" || !security.Equal(security.Hash(nonce), nonceHash) || (authorizedParty != "" && authorizedParty != p.clientID) {
		return "", ErrIdentity
	}
	var audience string
	var audiences []string
	audienceJSON, ok := claims["aud"]
	if !ok {
		return "", ErrIdentity
	}
	if json.Unmarshal(audienceJSON, &audience) == nil {
		audiences = []string{audience}
	} else if json.Unmarshal(audienceJSON, &audiences) != nil {
		return "", ErrIdentity
	}
	found := false
	for _, a := range audiences {
		if a == p.clientID {
			found = true
		}
	}
	if !found || (len(audiences) > 1 && authorizedParty != p.clientID) {
		return "", ErrIdentity
	}
	var expires, issued, notBefore int64
	for key, destination := range map[string]*int64{"exp": &expires, "iat": &issued, "nbf": &notBefore} {
		if b, ok := claims[key]; ok {
			if json.Unmarshal(b, destination) != nil {
				return "", ErrIdentity
			}
		}
	}
	now := p.now().Unix()
	if expires <= now || issued <= 0 || issued > now+60 || expires <= issued || notBefore > now+60 {
		return "", ErrIdentity
	}
	return subject, nil
}

func (p *GoogleProvider) signingKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.now().Before(p.keysExpire) {
		if key := p.keys[kid]; key != nil {
			return key, nil
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, googleJWKSEndpoint, nil)
	if err != nil {
		return nil, ErrIdentity
	}
	req.Header.Set("Accept", "application/json")
	response, err := p.client.Do(req)
	if err != nil {
		return nil, ErrIdentity
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, ErrIdentity
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxProviderResponse+1))
	if err != nil || len(body) > maxProviderResponse {
		return nil, ErrIdentity
	}
	var document map[string]json.RawMessage
	if strict.Decode(body, &document) != nil {
		return nil, ErrIdentity
	}
	var entries []map[string]json.RawMessage
	if json.Unmarshal(document["keys"], &entries) != nil || len(entries) == 0 || len(entries) > 100 {
		return nil, ErrIdentity
	}
	keys := make(map[string]*rsa.PublicKey)
	for _, entry := range entries {
		var kty, alg, use, id, n, e string
		for name, destination := range map[string]*string{"kty": &kty, "alg": &alg, "use": &use, "kid": &id, "n": &n, "e": &e} {
			if value, ok := entry[name]; ok {
				if json.Unmarshal(value, destination) != nil {
					return nil, ErrIdentity
				}
			}
		}
		if kty != "RSA" || alg != "RS256" || use != "sig" {
			continue
		}
		if id == "" || len(id) > 256 || keys[id] != nil {
			return nil, ErrIdentity
		}
		modulus, err := base64.RawURLEncoding.Strict().DecodeString(n)
		if err != nil || len(modulus) < 256 || len(modulus) > 1024 {
			return nil, ErrIdentity
		}
		exponent, err := base64.RawURLEncoding.Strict().DecodeString(e)
		if err != nil || len(exponent) == 0 || len(exponent) > 4 {
			return nil, ErrIdentity
		}
		number := 0
		for _, b := range exponent {
			number = number*256 + int(b)
		}
		if number < 3 || number%2 == 0 || number > 2147483647 {
			return nil, ErrIdentity
		}
		modulusInt := new(big.Int).SetBytes(modulus)
		if modulusInt.BitLen() < 2048 || modulusInt.Bit(0) != 1 {
			return nil, ErrIdentity
		}
		keys[id] = &rsa.PublicKey{N: modulusInt, E: number}
	}
	p.keys = keys
	p.keysExpire = p.now().Add(cacheDuration(response.Header.Get("Cache-Control")))
	if key := keys[kid]; key != nil {
		return key, nil
	}
	return nil, ErrIdentity
}
func cacheDuration(header string) time.Duration {
	ttl := 5 * time.Minute
	for _, item := range strings.Split(header, ",") {
		pair := strings.SplitN(strings.TrimSpace(item), "=", 2)
		if len(pair) == 2 && pair[0] == "max-age" {
			seconds, err := strconv.ParseInt(pair[1], 10, 64)
			if err == nil && seconds >= 0 && seconds <= 3600 {
				ttl = time.Duration(seconds) * time.Second
			}
		}
	}
	return ttl
}
