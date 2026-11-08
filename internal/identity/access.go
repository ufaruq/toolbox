package identity

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
)

// AccessConfig selects the MCP access-token policy. Empty Provider and "okta"
// preserve the organization/custom-server immutable Okta uid binding. "keycloak"
// requires one pinned realm for owner and access-token identities.
type AccessConfig struct {
	Provider                                     string
	Issuer, OwnerIssuer, Audience, OwnerClientID string
	Clients                                      map[string]string
	AllowLoopbackHTTP                            bool         // signed local fixtures only
	HTTPClient                                   *http.Client // trusted TLS roots for embedded callers; Keycloak only
}

var customServerPath = regexp.MustCompile(`^/oauth2/[A-Za-z0-9_-]+$`)

func ValidOwnerBinding(owner, access string, allowLoopback bool) bool {
	if !safeURL(owner, allowLoopback) || !safeURL(access, allowLoopback) {
		return false
	}
	org, e1 := url.Parse(owner)
	api, e2 := url.Parse(access)
	return e1 == nil && e2 == nil && org.Scheme == api.Scheme && org.Host == api.Host &&
		org.Path == "" && org.RawPath == "" && org.RawQuery == "" && !org.ForceQuery &&
		api.RawPath == "" && customServerPath.MatchString(api.Path) && api.RawQuery == "" && !api.ForceQuery
}

func NewAccess(ctx context.Context, cfg AccessConfig) (*Service, error) {
	switch cfg.Provider {
	case "keycloak":
		return newKeycloakAccess(ctx, cfg)
	case "", "okta":
	default:
		return nil, errConfig
	}
	return newIdentity(ctx, Config{Issuer: cfg.Issuer, OwnerIssuer: cfg.OwnerIssuer, Audience: cfg.Audience,
		OwnerClientID: cfg.OwnerClientID, Clients: cfg.Clients, AllowLoopbackHTTP: cfg.AllowLoopbackHTTP}, true)
}
