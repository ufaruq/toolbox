package identity

import (
	"context"
	"net/url"
	"regexp"
)

// AccessConfig binds one Okta custom server to its existing organization owner
// identity. The org ID-token sub and custom-server access-token uid are Okta user
// IDs. The token's sub/email never establish that binding.
type AccessConfig struct {
	Issuer, OwnerIssuer, Audience, OwnerClientID string
	Clients                                      map[string]string
	AllowLoopbackHTTP                            bool // signed local fixtures only
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
	return newIdentity(ctx, Config{Issuer: cfg.Issuer, OwnerIssuer: cfg.OwnerIssuer, Audience: cfg.Audience,
		OwnerClientID: cfg.OwnerClientID, Clients: cfg.Clients, AllowLoopbackHTTP: cfg.AllowLoopbackHTTP}, true)
}
