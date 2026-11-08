package identity

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/coreos/go-oidc/v3/oidc"
)

// ValidKeycloakOwnerBinding requires the exact same canonical realm issuer for
// owner logins and MCP users. An optional deployment prefix (e.g. /auth) is valid.
func ValidKeycloakOwnerBinding(owner, access string, allowLoopback bool) bool {
	if owner != access || strings.Contains(owner, "#") || !safeURL(owner, allowLoopback) {
		return false
	}
	u, err := url.Parse(owner)
	if err != nil || !canonicalKeycloakURL(u) || strings.HasSuffix(u.Path, "/") {
		return false
	}
	parts := strings.Split(u.Path, "/")
	if len(parts) < 3 || parts[len(parts)-2] != "realms" {
		return false
	}
	realm := parts[len(parts)-1]
	if realm == "" || realm == "." || realm == ".." {
		return false
	}
	for _, c := range realm {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("._-", c)) {
			return false
		}
	}
	return true
}

func canonicalKeycloakURL(u *url.URL) bool {
	return u.RawPath == "" && u.RawQuery == "" && !u.ForceQuery &&
		u.Path == path.Clean(u.Path) && strings.HasPrefix(u.Path, "/")
}

// newKeycloakAccess deliberately does not construct an owner verifier or OAuth
// configuration. Owner authorization remains the responsibility of ownerlogin.
func newKeycloakAccess(ctx context.Context, cfg AccessConfig) (*Service, error) {
	if !ValidKeycloakOwnerBinding(cfg.OwnerIssuer, cfg.Issuer, cfg.AllowLoopbackHTTP) ||
		!boundedInput(cfg.Audience, 2048) || !boundedInput(cfg.OwnerClientID, 256) ||
		cfg.Audience == cfg.OwnerClientID || len(cfg.Clients) == 0 {
		return nil, errConfig
	}
	clients := make(map[string]string, len(cfg.Clients))
	for id, name := range cfg.Clients {
		if !boundedInput(id, 256) || !boundedInput(name, 256) || id == cfg.Audience || id == cfg.OwnerClientID {
			return nil, errConfig
		}
		clients[id] = name
	}
	issuerURL, _ := url.Parse(cfg.Issuer)
	client, err := keycloakHTTPClient(cfg.HTTPClient, issuerURL, cfg.AllowLoopbackHTTP)
	if err != nil {
		return nil, err
	}
	provider, err := oidc.NewProvider(oidc.ClientContext(ctx, client), cfg.Issuer)
	if err != nil {
		return nil, errDiscovery
	}
	var discovery struct {
		Issuer  string `json:"issuer"`
		JWKSURL string `json:"jwks_uri"`
	}
	endpoint := provider.Endpoint()
	if provider.Claims(&discovery) != nil || discovery.Issuer != cfg.Issuer ||
		!keycloakEndpoint(discovery.JWKSURL, issuerURL, cfg.AllowLoopbackHTTP) ||
		!keycloakEndpoint(endpoint.AuthURL, issuerURL, cfg.AllowLoopbackHTTP) ||
		!keycloakEndpoint(endpoint.TokenURL, issuerURL, cfg.AllowLoopbackHTTP) {
		return nil, errDiscovery
	}
	return &Service{issuer: cfg.Issuer, ownerIssuer: cfg.OwnerIssuer, ownerClientID: cfg.OwnerClientID,
		keycloakAudience: cfg.Audience, clients: clients, client: client,
		accessVerifier: provider.Verifier(&oidc.Config{ClientID: cfg.Audience, SupportedSigningAlgs: []string{oidc.RS256}})}, nil
}

func keycloakHTTPClient(trusted *http.Client, issuer *url.URL, allowLoopback bool) (*http.Client, error) {
	client := http.Client{}
	if trusted != nil {
		client = *trusted
	}
	base := client.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	if transport, ok := base.(*http.Transport); ok {
		transport = transport.Clone()
		if transport.TLSClientConfig != nil && transport.TLSClientConfig.InsecureSkipVerify {
			return nil, errConfig
		}
		transport.TLSHandshakeTimeout = 5 * time.Second
		transport.ResponseHeaderTimeout = 5 * time.Second
		base = transport
	}
	client.Transport = &keycloakTransport{base: base, issuer: issuer, allowLoopback: allowLoopback}
	if client.Timeout <= 0 || client.Timeout > 10*time.Second {
		client.Timeout = 10 * time.Second
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &client, nil
}

func keycloakEndpoint(raw string, issuer *url.URL, allowLoopback bool) bool {
	if strings.Contains(raw, "#") || !safeURL(raw, allowLoopback) {
		return false
	}
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == issuer.Scheme && u.Host == issuer.Host && canonicalKeycloakURL(u)
}

type keycloakTransport struct {
	base          http.RoundTripper
	issuer        *url.URL
	allowLoopback bool
}

func (t *keycloakTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if !keycloakEndpoint(r.URL.String(), t.issuer, t.allowLoopback) {
		return nil, errDiscovery
	}
	response, err := t.base.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	const maxBody = 1 << 20
	body, err := io.ReadAll(io.LimitReader(response.Body, maxBody+1))
	if err != nil || len(body) > maxBody {
		return nil, errDiscovery
	}
	if response.StatusCode == http.StatusOK {
		object, err := strictKeycloakObject(body)
		if err != nil {
			return nil, errDiscovery
		}
		if rawKeys, ok := object["keys"]; ok {
			var keys []json.RawMessage
			if json.Unmarshal(rawKeys, &keys) != nil {
				return nil, errDiscovery
			}
			for _, key := range keys {
				if _, err := strictKeycloakObject(key); err != nil {
					return nil, errDiscovery
				}
			}
		}
	}
	response.Body = io.NopCloser(bytes.NewReader(body))
	return response, nil
}

func (s *Service) verifyKeycloakAccess(ctx context.Context, raw string) (Claims, error) {
	if len(raw) == 0 || len(raw) > 16384 {
		return Claims{}, errAccess
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return Claims{}, errAccess
	}
	headerBytes, err := base64.RawURLEncoding.Strict().DecodeString(parts[0])
	if err != nil {
		return Claims{}, errAccess
	}
	header, err := strictKeycloakObject(headerBytes)
	if err != nil || exactString(header, "alg", 16) != oidc.RS256 {
		return Claims{}, errAccess
	}
	for _, key := range []string{"crit", "b64", "jku", "jwk", "x5u"} {
		if _, ok := header[key]; ok {
			return Claims{}, errAccess
		}
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil {
		return Claims{}, errAccess
	}
	c, err := strictKeycloakObject(payload)
	if err != nil {
		return Claims{}, errAccess
	}
	// These are only untrusted parse results until Verify succeeds below. Parsing
	// first avoids case-insensitive JSON struct matching and duplicate-key policy.
	issuer := exactString(c, "iss", 2048)
	subject := exactString(c, "sub", 256)
	client := exactString(c, "azp", 256)
	session := exactString(c, "sid", 256)
	scope := exactString(c, "scope", 4096)
	iat, hasIAT := exactInteger(c, "iat")
	exp, hasEXP := exactInteger(c, "exp")
	if issuer != s.issuer || subject == "" || client == "" || session == "" ||
		exactString(c, "typ", 16) != "Bearer" || !singletonAudience(c["aud"], s.keycloakAudience) ||
		!keycloakMCPScope(scope) || !hasIAT || !hasEXP {
		return Claims{}, errAccess
	}
	if _, ok := s.clients[client]; !ok {
		return Claims{}, errAccess
	}
	if !validUserClaims(userClaims{UserID: subject, IssuedAt: iat, ExpiresAt: exp, NotBefore: c["nbf"]}, time.Now()) {
		return Claims{}, errAccess
	}
	if _, ok := c["nbf"]; ok {
		nbf, valid := exactInteger(c, "nbf")
		if !valid || nbf >= exp {
			return Claims{}, errAccess
		}
	}
	token, err := s.accessVerifier.Verify(oidc.ClientContext(ctx, s.client), raw)
	if err != nil || token.Issuer != s.issuer || len(token.Audience) != 1 || token.Audience[0] != s.keycloakAudience {
		return Claims{}, errAccess
	}
	return Claims{Issuer: s.issuer, UserID: subject, ClientID: client, ExpiresAt: time.Unix(exp, 0)}, nil
}

func exactString(object map[string]json.RawMessage, name string, max int) string {
	var value string
	if json.Unmarshal(object[name], &value) != nil || !boundedInput(value, max) {
		return ""
	}
	return value
}

func exactInteger(object map[string]json.RawMessage, name string) (int64, bool) {
	var value *int64
	if json.Unmarshal(object[name], &value) != nil || value == nil {
		return 0, false
	}
	return *value, true
}

func singletonAudience(raw json.RawMessage, expected string) bool {
	var single string
	if json.Unmarshal(raw, &single) == nil {
		return single == expected
	}
	var values []string
	return json.Unmarshal(raw, &values) == nil && len(values) == 1 && values[0] == expected
}

func keycloakMCPScope(scope string) bool {
	if scope == "" {
		return false
	}
	for _, c := range scope {
		if c != ' ' && (c < 0x21 || c > 0x7e || c == '"' || c == '\\') {
			return false
		}
	}
	for _, value := range strings.Split(scope, " ") {
		if value == "mcp" {
			return true
		}
	}
	return false
}

// All consumed OIDC/JWK fields use exact JSON spelling. encoding/json otherwise
// permits case-insensitive struct matches; duplicate decoded names are also
// rejected throughout the document, including fields this policy does not use.
var keycloakJSONNames = map[string]bool{
	"iss": true, "aud": true, "sub": true, "azp": true, "typ": true,
	"scope": true, "sid": true, "iat": true, "exp": true, "nbf": true,
	"alg": true, "kid": true, "crit": true, "b64": true, "jku": true, "jwk": true,
	"issuer": true, "jwks_uri": true, "authorization_endpoint": true, "token_endpoint": true,
	"id_token_signing_alg_values_supported": true,
	"keys":                                  true, "kty": true, "use": true, "key_ops": true, "n": true, "e": true, "x5u": true,
}

func strictKeycloakObject(raw []byte) (map[string]json.RawMessage, error) {
	if !utf8.Valid(raw) {
		return nil, errAccess
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	first, err := d.Token()
	if err != nil || first != json.Delim('{') || strictKeycloakMembers(d, 0, true) != nil {
		return nil, errAccess
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, errAccess
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil {
		return nil, errAccess
	}
	for key := range object {
		if keycloakJSONNames[key] {
			continue
		}
		for name := range keycloakJSONNames {
			if strings.EqualFold(key, name) {
				return nil, errAccess
			}
		}
	}
	return object, nil
}

func strictKeycloakMembers(d *json.Decoder, depth int, object bool) error {
	if depth > 32 {
		return errAccess
	}
	seen := map[string]bool{}
	for d.More() {
		if object {
			token, err := d.Token()
			key, ok := token.(string)
			if err != nil || !ok || seen[key] {
				return errAccess
			}
			seen[key] = true
		}
		token, err := d.Token()
		if err != nil {
			return errAccess
		}
		if delimiter, ok := token.(json.Delim); ok {
			if delimiter != '{' && delimiter != '[' || strictKeycloakMembers(d, depth+1, delimiter == '{') != nil {
				return errAccess
			}
		}
	}
	closing, err := d.Token()
	if err != nil || object && closing != json.Delim('}') || !object && closing != json.Delim(']') {
		return errAccess
	}
	return nil
}
