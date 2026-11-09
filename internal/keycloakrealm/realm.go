// Package keycloakrealm renders a trusted operator configuration as a Keycloak
// realm import. The result contains client secrets and must be kept private.
package keycloakrealm

import (
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
)

// Config is the operator-controlled configuration for a new broker realm.
// MCPClients maps client IDs to display names. MCPRedirectURIs must register
// explicit redirect URLs for exactly those clients. An upstream provider is
// enabled only when all of its fields are supplied.
type Config struct {
	DynamicClientRegistration                              bool
	DynamicRegistrationTrustedHosts                        []string
	Realm, OwnerClientID, OwnerClientSecret, Origin        string
	OktaIssuer, OktaClientID, OktaClientSecret             string
	GoogleClientID, GoogleClientSecret, GoogleHostedDomain string
	MCPClients                                             map[string]string
	MCPRedirectURIs                                        map[string][]string
}

// Render returns Keycloak 26.8.2 realm-import JSON. It performs no network or
// filesystem operations. Validation errors never include configured values.
func Render(cfg Config) ([]byte, error) {
	if err := validate(cfg); err != nil {
		return nil, err
	}
	realm := realmImport{
		Realm: cfg.Realm, Enabled: true, SSLRequired: "external", DefaultSignatureAlgorithm: "RS256", FirstBrokerLoginFlow: firstBrokerFlow,
		DuplicateEmailsAllowed: true,
		BrowserFlow:            "toolbox-upstream-only",
		RequiredActions: []requiredActionImport{
			{Alias: "UPDATE_PASSWORD", ProviderID: "UPDATE_PASSWORD"},
			{Alias: "CONFIGURE_TOTP", ProviderID: "CONFIGURE_TOTP"},
			{Alias: "webauthn-register", ProviderID: "webauthn-register"},
			{Alias: "webauthn-register-passwordless", ProviderID: "webauthn-register-passwordless"},
			{Alias: "CONFIGURE_RECOVERY_AUTHN_CODES", ProviderID: "CONFIGURE_RECOVERY_AUTHN_CODES"},
		},
		// Use Keycloak's official factory so its built-in account/Admin clients
		// receive the normal scopes. Application clients explicitly replace
		// inherited scopes with basic (and optional mcp) below.
		Attributes: map[string]string{"CreateDefaultClientScopes": "true"},
		Clients:    []clientImport{newClient(cfg.OwnerClientID, "Toolbox owner", false, []string{cfg.Origin + "/auth/oidc/callback"})},
		ClientScopes: []scopeImport{{
			Name: "mcp", Description: "Toolbox MCP access", Protocol: "openid-connect",
			Attributes: map[string]string{"include.in.token.scope": "true", "display.on.consent.screen": "true"},
			ProtocolMappers: []protocolMapper{{
				Name: "Toolbox MCP audience", Protocol: "openid-connect", ProtocolMapper: "oidc-audience-mapper",
				Config: map[string]string{"included.custom.audience": cfg.Origin + "/mcp", "access.token.claim": "true", "id.token.claim": "false", "introspection.token.claim": "false"},
			}},
		}},
		IdentityProviders:       []providerImport{},
		IdentityProviderMappers: []providerMapper{},
		AuthenticationFlows: []flowImport{{
			Alias: firstBrokerFlow, Description: "Create a separate account for each upstream subject; never link by email", ProviderID: "basic-flow", TopLevel: true,
			AuthenticationExecutions: []executionImport{{Authenticator: "idp-create-user-if-unique", Requirement: "REQUIRED", Priority: 10}},
		}, {
			Alias: "toolbox-upstream-only", ProviderID: "basic-flow", TopLevel: true,
			AuthenticationExecutions: []executionImport{
				{Authenticator: "identity-provider-redirector", Requirement: "ALTERNATIVE", Priority: 10},
				{FlowAlias: "toolbox-provider-selection", AuthenticatorFlow: true, Requirement: "ALTERNATIVE", Priority: 20},
			},
		}, {
			// The built-in username screen renders provider choices. Its local
			// submission must always terminate in denial; it is never authentication.
			Alias: "toolbox-provider-selection", ProviderID: "basic-flow",
			AuthenticationExecutions: []executionImport{
				{Authenticator: "auth-username-form", Requirement: "REQUIRED", Priority: 10},
				{Authenticator: "deny-access-authenticator", Requirement: "REQUIRED", Priority: 20},
			},
		}},
	}
	realm.Clients[0].Secret = cfg.OwnerClientSecret
	// Toolbox accepts only state/code/iss in its strict OIDC callback.
	realm.Clients[0].Attributes["exclude.session.state.from.auth.response"] = "true"
	ids := make([]string, 0, len(cfg.MCPClients))
	for id := range cfg.MCPClients {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		client := newClient(id, cfg.MCPClients[id], true, slices.Clone(cfg.MCPRedirectURIs[id]))
		client.OptionalClientScopes = []string{"mcp"}
		realm.Clients = append(realm.Clients, client)
	}
	if cfg.OktaIssuer != "" {
		base := cfg.OktaIssuer + "/v1/"
		issuer, _ := url.Parse(cfg.OktaIssuer)
		if issuer.Path == "" {
			base = cfg.OktaIssuer + "/oauth2/v1/"
		}
		provider := newProvider("okta", "Okta", "oidc", cfg.OktaClientID, cfg.OktaClientSecret)
		provider.Config["issuer"] = cfg.OktaIssuer
		provider.Config["authorizationUrl"] = base + "authorize"
		provider.Config["tokenUrl"] = base + "token"
		provider.Config["jwksUrl"] = base + "keys"
		provider.Config["userInfoUrl"] = base + "userinfo"
		provider.Config["clientAuthMethod"] = "client_secret_basic"
		provider.Config["userIDClaim"] = "sub"
		provider.Config["useJwksUrl"] = "true"
		provider.Config["pkceEnabled"] = "true"
		provider.Config["pkceMethod"] = "S256"
		realm.IdentityProviders = append(realm.IdentityProviders, provider)
		realm.IdentityProviderMappers = append(realm.IdentityProviderMappers, usernameMapper("okta"))
	}
	if cfg.GoogleClientID != "" {
		provider := newProvider("google", "Google", "google", cfg.GoogleClientID, cfg.GoogleClientSecret)
		// The builtin Google provider pins endpoints/JWKS and validates the hd
		// claim when a domain is configured. Keep its exact fixed issuer.
		provider.Config["issuer"] = "https://accounts.google.com"
		if cfg.GoogleHostedDomain != "" {
			provider.Config["hostedDomain"] = cfg.GoogleHostedDomain
		}
		provider.Config["offlineAccess"] = "false"
		realm.IdentityProviders = append(realm.IdentityProviders, provider)
		realm.IdentityProviderMappers = append(realm.IdentityProviderMappers, usernameMapper("google"))
	}
	if cfg.DynamicClientRegistration {
		configureRegistration(&realm, cfg)
	}
	data, err := json.MarshalIndent(realm, "", "  ")
	if err != nil {
		return nil, errors.New("cannot encode Keycloak realm import")
	}
	return append(data, '\n'), nil
}

const firstBrokerFlow = "toolbox-first-broker-login"

var realmName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

func validate(cfg Config) error {
	if err := validateRegistration(cfg); err != nil {
		return err
	}
	if !realmName.MatchString(cfg.Realm) || cfg.Realm == "master" {
		return errors.New("invalid Keycloak realm name")
	}
	if !clientID(cfg.OwnerClientID) || !value(cfg.OwnerClientSecret, 4096) {
		return errors.New("invalid Keycloak owner client configuration")
	}
	origin, err := parseURL(cfg.Origin)
	if err != nil || !loopbackHTTP(origin) || origin.Path != "" || origin.RawQuery != "" || origin.ForceQuery {
		return errors.New("Toolbox origin must be an exact loopback HTTP origin with an explicit port")
	}
	okta := cfg.OktaIssuer != "" || cfg.OktaClientID != "" || cfg.OktaClientSecret != ""
	google := cfg.GoogleClientID != "" || cfg.GoogleClientSecret != "" || cfg.GoogleHostedDomain != ""
	if !okta && !google {
		return errors.New("at least one upstream identity provider is required")
	}
	if okta {
		issuer, err := parseURL(cfg.OktaIssuer)
		if err != nil || issuer.Scheme != "https" || issuer.RawQuery != "" || issuer.ForceQuery || strings.HasSuffix(cfg.OktaIssuer, "/") || strings.Contains(cfg.OktaIssuer, ",") || issuer.RawPath != "" || !value(cfg.OktaClientID, 2048) || !value(cfg.OktaClientSecret, 4096) {
			return errors.New("Okta requires an exact HTTPS issuer, client ID and client secret")
		}
	}
	if google && (!value(cfg.GoogleClientID, 2048) || !value(cfg.GoogleClientSecret, 4096) || (cfg.GoogleHostedDomain != "" && !hostedDomain(cfg.GoogleHostedDomain))) {
		return errors.New("Google requires a client ID, client secret and an optional exact Workspace hosted domain")
	}
	if len(cfg.MCPClients) > 128 {
		return errors.New("too many MCP client registrations")
	}
	for id, name := range cfg.MCPClients {
		redirects := cfg.MCPRedirectURIs[id]
		if !clientID(id) || id == cfg.OwnerClientID || id == cfg.Origin+"/mcp" || !value(name, 256) || len(redirects) == 0 {
			return errors.New("invalid MCP client registration")
		}
		for _, raw := range redirects {
			u, err := parseURL(raw)
			if err != nil || (u.Scheme != "https" && !loopbackHTTP(u)) || strings.ContainsAny(u.Path+u.RawQuery, "*") {
				return errors.New("MCP redirects must be exact HTTPS or loopback HTTP URLs without wildcards")
			}
		}
	}
	for id := range cfg.MCPRedirectURIs {
		if _, ok := cfg.MCPClients[id]; !ok {
			return errors.New("MCP redirect registration has no matching client")
		}
	}
	return nil
}

func value(v string, limit int) bool {
	return v != "" && len(v) <= limit && strings.TrimSpace(v) == v && !strings.ContainsFunc(v, unicode.IsControl)
}

func clientID(id string) bool {
	if !value(id, 256) || strings.ContainsFunc(id, unicode.IsSpace) {
		return false
	}
	switch id {
	case "account", "account-console", "admin-cli", "broker", "realm-management", "security-admin-console":
		return false
	}
	return true
}

func parseURL(raw string) (*url.URL, error) {
	if !value(raw, 8192) || strings.ContainsAny(raw, "*\\#") {
		return nil, errors.New("invalid URL")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil || u.Opaque != "" || u.Fragment != "" || strings.ContainsAny(u.Hostname(), ", \t") {
		return nil, errors.New("invalid URL")
	}
	if u.Port() != "" {
		port, err := strconv.Atoi(u.Port())
		if err != nil || port < 1 || port > 65535 {
			return nil, errors.New("invalid URL")
		}
	}
	return u, nil
}

func loopbackHTTP(u *url.URL) bool {
	if u == nil || u.Scheme != "http" || u.Port() == "" {
		return false
	}
	ip := net.ParseIP(u.Hostname())
	return u.Hostname() == "localhost" || (ip != nil && ip.IsLoopback())
}

func hostedDomain(domain string) bool {
	if !value(domain, 253) || !strings.Contains(domain, ".") || net.ParseIP(domain) != nil {
		return false
	}
	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, ch := range label {
			if (ch < 'a' || ch > 'z') && (ch < 'A' || ch > 'Z') && (ch < '0' || ch > '9') && ch != '-' {
				return false
			}
		}
	}
	return true
}

func newClient(id, name string, public bool, redirects []string) clientImport {
	return clientImport{
		ClientID: id, Name: name, Enabled: true, Protocol: "openid-connect", PublicClient: public,
		ClientAuthenticatorType: "client-secret", StandardFlowEnabled: true,
		RedirectURIs: redirects, WebOrigins: []string{},
		DefaultClientScopes: []string{"basic"}, OptionalClientScopes: []string{},
		Attributes: map[string]string{"pkce.code.challenge.method": "S256", "oauth2.device.authorization.grant.enabled": "false", "oidc.ciba.grant.enabled": "false"},
	}
}

func newProvider(alias, name, providerID, id, secret string) providerImport {
	return providerImport{
		Alias: alias, DisplayName: name, ProviderID: providerID, Enabled: true, FirstBrokerLoginFlowAlias: firstBrokerFlow,
		Config: map[string]string{"clientId": id, "clientSecret": secret, "syncMode": "IMPORT", "validateSignature": "true", "disableNonce": "false", "defaultScope": "openid profile email"},
	}
}

func usernameMapper(alias string) providerMapper {
	return providerMapper{
		Name: "Provider subject username", IdentityProviderAlias: alias, IdentityProviderMapper: "oidc-username-idp-mapper",
		Config: map[string]string{"template": "${ALIAS}.${CLAIM.sub}", "target": "LOCAL", "syncMode": "IMPORT"},
	}
}

// These are Keycloak 26.8.2 representation fields. Explicit false/empty values
// prevent import defaults from enabling extra flows or inherited client scopes.
// Field names and mapper keys are verified against the 26.8.2 upstream source:
// core/.../representations/idm, services/.../broker/oidc,
// services/.../social/google and services/.../protocol/oidc/mappers.
type realmImport struct {
	Components                  map[string][]registrationComponent `json:"components,omitempty"`
	ClientProfiles              map[string]any                     `json:"clientProfiles,omitempty"`
	ClientPolicies              map[string]any                     `json:"clientPolicies,omitempty"`
	DefaultOptionalClientScopes []string                           `json:"defaultOptionalClientScopes,omitempty"`
	BrowserFlow                 string                             `json:"browserFlow"`
	RequiredActions             []requiredActionImport             `json:"requiredActions"`
	Realm                       string                             `json:"realm"`
	Enabled                     bool                               `json:"enabled"`
	SSLRequired                 string                             `json:"sslRequired"`
	DefaultSignatureAlgorithm   string                             `json:"defaultSignatureAlgorithm"`
	FirstBrokerLoginFlow        string                             `json:"firstBrokerLoginFlow"`
	RegistrationAllowed         bool                               `json:"registrationAllowed"`
	RegistrationEmailAsUsername bool                               `json:"registrationEmailAsUsername"`
	DuplicateEmailsAllowed      bool                               `json:"duplicateEmailsAllowed"`
	LoginWithEmailAllowed       bool                               `json:"loginWithEmailAllowed"`
	ResetPasswordAllowed        bool                               `json:"resetPasswordAllowed"`
	EditUsernameAllowed         bool                               `json:"editUsernameAllowed"`
	Attributes                  map[string]string                  `json:"attributes"`
	Clients                     []clientImport                     `json:"clients"`
	ClientScopes                []scopeImport                      `json:"clientScopes"`
	IdentityProviders           []providerImport                   `json:"identityProviders"`
	IdentityProviderMappers     []providerMapper                   `json:"identityProviderMappers"`
	AuthenticationFlows         []flowImport                       `json:"authenticationFlows"`
}

type clientImport struct {
	ClientID                  string            `json:"clientId"`
	Name                      string            `json:"name"`
	Secret                    string            `json:"secret,omitempty"`
	Enabled                   bool              `json:"enabled"`
	Protocol                  string            `json:"protocol"`
	PublicClient              bool              `json:"publicClient"`
	ClientAuthenticatorType   string            `json:"clientAuthenticatorType"`
	StandardFlowEnabled       bool              `json:"standardFlowEnabled"`
	ImplicitFlowEnabled       bool              `json:"implicitFlowEnabled"`
	DirectAccessGrantsEnabled bool              `json:"directAccessGrantsEnabled"`
	ServiceAccountsEnabled    bool              `json:"serviceAccountsEnabled"`
	FullScopeAllowed          bool              `json:"fullScopeAllowed"`
	RedirectURIs              []string          `json:"redirectUris"`
	WebOrigins                []string          `json:"webOrigins"`
	DefaultClientScopes       []string          `json:"defaultClientScopes"`
	OptionalClientScopes      []string          `json:"optionalClientScopes"`
	Attributes                map[string]string `json:"attributes"`
}

type scopeImport struct {
	Name            string            `json:"name"`
	Description     string            `json:"description"`
	Protocol        string            `json:"protocol"`
	Attributes      map[string]string `json:"attributes"`
	ProtocolMappers []protocolMapper  `json:"protocolMappers"`
}

type protocolMapper struct {
	Name           string            `json:"name"`
	Protocol       string            `json:"protocol"`
	ProtocolMapper string            `json:"protocolMapper"`
	Config         map[string]string `json:"config"`
}

type providerImport struct {
	Alias                     string            `json:"alias"`
	DisplayName               string            `json:"displayName"`
	ProviderID                string            `json:"providerId"`
	Enabled                   bool              `json:"enabled"`
	TrustEmail                bool              `json:"trustEmail"`
	StoreToken                bool              `json:"storeToken"`
	AddReadTokenRoleOnCreate  bool              `json:"addReadTokenRoleOnCreate"`
	AuthenticateByDefault     bool              `json:"authenticateByDefault"`
	LinkOnly                  bool              `json:"linkOnly"`
	FirstBrokerLoginFlowAlias string            `json:"firstBrokerLoginFlowAlias"`
	Config                    map[string]string `json:"config"`
}

type providerMapper struct {
	Name                   string            `json:"name"`
	IdentityProviderAlias  string            `json:"identityProviderAlias"`
	IdentityProviderMapper string            `json:"identityProviderMapper"`
	Config                 map[string]string `json:"config"`
}

type flowImport struct {
	Alias                    string            `json:"alias"`
	Description              string            `json:"description"`
	ProviderID               string            `json:"providerId"`
	TopLevel                 bool              `json:"topLevel"`
	BuiltIn                  bool              `json:"builtIn"`
	AuthenticationExecutions []executionImport `json:"authenticationExecutions"`
}

type executionImport struct {
	FlowAlias         string `json:"flowAlias,omitempty"`
	Authenticator     string `json:"authenticator"`
	AuthenticatorFlow bool   `json:"authenticatorFlow"`
	Requirement       string `json:"requirement"`
	Priority          int    `json:"priority"`
	UserSetupAllowed  bool   `json:"userSetupAllowed"`
}

type requiredActionImport struct {
	Alias         string `json:"alias"`
	ProviderID    string `json:"providerId"`
	Enabled       bool   `json:"enabled"`
	DefaultAction bool   `json:"defaultAction"`
}
