package keycloakrealm

import (
	"errors"
	"net"
	"regexp"
	"strings"
)

type registrationComponent struct {
	Name       string              `json:"name"`
	ProviderID string              `json:"providerId"`
	SubType    string              `json:"subType"`
	Config     map[string][]string `json:"config"`
}

func validateRegistration(cfg Config) error {
	invalid := errors.New("dynamic registration requires explicit exact trusted callback hosts")
	if !cfg.DynamicClientRegistration {
		if len(cfg.DynamicRegistrationTrustedHosts) != 0 {
			return invalid
		}
		return nil
	}
	if len(cfg.DynamicRegistrationTrustedHosts) == 0 || len(cfg.DynamicRegistrationTrustedHosts) > 32 {
		return invalid
	}
	seen := map[string]bool{}
	for _, host := range cfg.DynamicRegistrationTrustedHosts {
		if seen[host] || host != strings.ToLower(host) || len(host) > 253 || host == "" {
			return invalid
		}
		seen[host] = true
		if ip := net.ParseIP(host); ip != nil {
			if host != ip.String() {
				return invalid
			}
			continue
		}
		if host == "localhost" {
			continue
		}
		if !hostedDomain(host) || !regexp.MustCompile(`[a-z]`).MatchString(host) {
			return invalid
		}
	}
	return nil
}

// Native Keycloak 26.8.2 policies apply to anonymous creation and the issued
// registration token's updates, including the default (non-OIDC) endpoint.
func configureRegistration(r *realmImport, cfg Config) {
	// Realm import only ADDS defaults. The administrator must remove inherited
	// default/optional scope assignments separately; policies reject registrations
	// while broader defaults remain. Existing builtin client assignments survive.
	r.DefaultOptionalClientScopes = []string{"mcp"}
	component := func(id string, config map[string][]string) registrationComponent {
		return registrationComponent{Name: "Toolbox " + id, ProviderID: id, SubType: "anonymous", Config: config}
	}
	r.Components = map[string][]registrationComponent{"org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy": {
		component("trusted-hosts", map[string][]string{"trusted-hosts": cfg.DynamicRegistrationTrustedHosts, "host-sending-registration-request-must-match": {"false"}, "client-uris-must-match": {"true"}}),
		component("allowed-client-templates", map[string][]string{"allowed-client-scopes": {"basic", "mcp", "openid"}, "allow-default-scopes": {"false"}}),
		component("allowed-protocol-mappers", map[string][]string{"allowed-protocol-mapper-types": {}}),
		component("scope", map[string][]string{}), component("consent-required", map[string][]string{}), component("max-clients", map[string][]string{"max-clients": {"128"}}),
	}}
	// Importing components suppresses Keycloak's automatic policy defaults for
	// both chains. Keep the authenticated chain restricted as well.
	key := "org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy"
	r.Components[key] = append(r.Components[key], component("default-roles", map[string][]string{}), component("registration-web-origins", map[string][]string{"web-origins": {}}))
	for _, c := range append([]registrationComponent{}, r.Components[key]...) {
		c.Name += " authenticated"
		c.SubType = "authenticated"
		r.Components[key] = append(r.Components[key], c)
	}
	patterns := []string{}
	for _, host := range cfg.DynamicRegistrationTrustedHosts {
		scheme := "https://"
		authority := host
		if ip := net.ParseIP(host); ip != nil {
			if ip.IsLoopback() {
				scheme = "https?://"
			}
			if strings.Contains(host, ":") {
				authority = "[" + host + "]"
			}
		} else if host == "localhost" {
			scheme = "https?://"
		}
		// Narrow literal URI grammar: no userinfo, wildcard, fragment, percent escapes
		// or DNS-derived loopback exceptions. A client registers each callback exactly.
		patterns = append(patterns, scheme+regexp.QuoteMeta(authority)+`(?::[0-9]{1,5})?/[A-Za-z0-9._~/-]*(?:\?[A-Za-z0-9._~=&-]*)?`)
	}
	executor := func(id string, config map[string]any) map[string]any {
		return map[string]any{"executor": id, "configuration": config}
	}
	r.ClientProfiles = map[string]any{"profiles": []any{
		map[string]any{"name": "toolbox-dcr", "executors": []any{
			executor("pkce-enforcer", map[string]any{"auto-configure": true}),
			executor("reject-implicit-grant", map[string]any{"auto-configure": true}),
			executor("reject-ropc-grant", map[string]any{"auto-configure": true}),
			executor("secure-client-authenticator", map[string]any{"allowed-client-authenticators": []string{}}),
			executor("secure-client-uris-pattern", map[string]any{"allowed-patterns": patterns, "client-uri-fields": []string{"redirectUris"}}),
		}},
		map[string]any{"name": "toolbox-dcr-no-remote-metadata", "executors": []any{
			executor("secure-client-uris-pattern", map[string]any{"allowed-patterns": []string{}, "client-uri-fields": []string{"rootUrl", "adminUrl", "baseUrl", "webOrigins", "jwksUri", "requestUris", "backchannelLogoutUrl", "frontChannelLogoutUrl", "postLogoutRedirectUris", "cibaClientNotificationEndpoint", "logoUri", "policyUri", "tosUri", "sectorIdentifierUri"}}),
		}},
	}}
	r.ClientPolicies = map[string]any{"policies": []any{
		map[string]any{"name": "toolbox-dcr-crud", "enabled": true, "mode": "STRICT", "conditions": []any{map[string]any{"condition": "client-updater-context", "configuration": map[string]any{"update-client-source": []string{"ByAnonymous", "ByRegistrationAccessToken"}}}}, "profiles": []string{"toolbox-dcr", "toolbox-dcr-no-remote-metadata"}},
	}}
	rejectProfile := map[string]any{"name": "toolbox-mcp-reject-grant", "executors": []any{executor("reject-request", map[string]any{})}}
	r.ClientProfiles["profiles"] = append(r.ClientProfiles["profiles"].([]any), rejectProfile)
	condition := func(id string, config map[string]any) map[string]any {
		return map[string]any{"condition": id, "configuration": config}
	}
	policies := r.ClientPolicies["policies"].([]any)
	// Keep anonymous registration closed until the administrator has restricted
	// realm defaults. This also blocks requests which omit scope entirely.
	policies = append(policies, map[string]any{"name": "toolbox-dcr-setup-required", "enabled": true, "mode": "STRICT", "conditions": []any{
		condition("client-updater-context", map[string]any{"update-client-source": []string{"ByAnonymous", "ByRegistrationAccessToken"}}),
	}, "profiles": []string{"toolbox-mcp-reject-grant"}})

	policies = append(policies, map[string]any{"name": "toolbox-mcp-code-only", "enabled": true, "mode": "STRICT", "conditions": []any{
		condition("client-scopes", map[string]any{"type": "Any", "scopes": []string{"mcp"}}),
		condition("grant-type", map[string]any{"grant_types": []string{"implicit", "password", "client_credentials", "urn:ietf:params:oauth:grant-type:device_code", "urn:openid:params:grant-type:ciba", "urn:ietf:params:oauth:grant-type:token-exchange", "urn:ietf:params:oauth:grant-type:jwt-bearer"}}),
	}, "profiles": []string{"toolbox-mcp-reject-grant"}})
	for _, attribute := range []string{"oauth2.device.authorization.grant.enabled", "oidc.ciba.grant.enabled", "standard.token.exchange.enabled", "oauth2.jwt.authorization.grant.enabled"} {
		policies = append(policies, map[string]any{"name": "toolbox-dcr-deny-" + attribute, "enabled": true, "mode": "STRICT", "conditions": []any{
			condition("client-updater-context", map[string]any{"update-client-source": []string{"ByAnonymous", "ByRegistrationAccessToken"}}),
			condition("client-attributes", map[string]any{"attributes": `[{"key":"` + attribute + `","value":"true"}]`}),
		}, "profiles": []string{"toolbox-mcp-reject-grant"}})
	}
	r.ClientPolicies["policies"] = policies

}
