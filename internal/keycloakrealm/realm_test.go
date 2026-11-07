package keycloakrealm

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

type importedRealm struct {
	Realm                       string
	Enabled                     bool
	DefaultSignatureAlgorithm   string
	FirstBrokerLoginFlow        string
	Attributes                  map[string]string
	RegistrationAllowed         bool
	RegistrationEmailAsUsername bool
	DuplicateEmailsAllowed      bool
	LoginWithEmailAllowed       bool
	Users                       []json.RawMessage
	Clients                     []importedClient
	ClientScopes                []struct {
		Name, Protocol  string
		Attributes      map[string]string
		ProtocolMappers []struct {
			Protocol, ProtocolMapper string
			Config                   map[string]string
		}
	}
	IdentityProviders []struct {
		Alias, ProviderID, FirstBrokerLoginFlowAlias string
		Enabled, TrustEmail, StoreToken, LinkOnly    bool
		Config                                       map[string]string
	}
	IdentityProviderMappers []struct {
		IdentityProviderAlias, IdentityProviderMapper string
		Config                                        map[string]string
	}
	AuthenticationFlows []struct {
		Alias, ProviderID        string
		TopLevel, BuiltIn        bool
		AuthenticationExecutions []struct {
			Authenticator, Requirement string
			AuthenticatorFlow          bool
		}
	}
}

type importedClient struct {
	ClientID, Name, Secret, Protocol, ClientAuthenticatorType string
	Enabled, PublicClient, StandardFlowEnabled                bool
	ImplicitFlowEnabled, DirectAccessGrantsEnabled            bool
	ServiceAccountsEnabled, FullScopeAllowed                  bool
	RedirectURIs, DefaultClientScopes, OptionalClientScopes   []string
	Attributes                                                map[string]string
}

func validConfig() Config {
	return Config{
		Realm: "toolbox", Origin: "http://127.0.0.1:8080",
		OwnerClientID: "toolbox-owner", OwnerClientSecret: "private-owner-secret",
		OktaIssuer: "https://example.okta.com", OktaClientID: "okta-client", OktaClientSecret: "private-okta-secret",
		GoogleClientID: "google-client", GoogleClientSecret: "private-google-secret", GoogleHostedDomain: "example.com",
		MCPClients: map[string]string{"toolbox-agent": "Local agent", "second-agent": "Second agent"},
		MCPRedirectURIs: map[string][]string{
			"toolbox-agent": {"http://127.0.0.1:49152/callback"},
			"second-agent":  {"https://agent.example.com/callback"},
		},
	}
}

func renderRealm(t *testing.T, cfg Config) importedRealm {
	t.Helper()
	raw, err := Render(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var realm importedRealm
	if err := json.Unmarshal(raw, &realm); err != nil {
		t.Fatalf("invalid import JSON: %v", err)
	}
	return realm
}

func TestRenderSeparatesOwnerAndMCPTokenAudiences(t *testing.T) {
	r := renderRealm(t, validConfig())
	if r.Realm != "toolbox" || !r.Enabled || r.DefaultSignatureAlgorithm != "RS256" {
		t.Fatalf("incorrect realm identity/signing policy: %+v", r)
	}
	if len(r.Clients) != 3 {
		t.Fatalf("got %d application clients", len(r.Clients))
	}
	for _, c := range r.Clients {
		if !c.Enabled || !c.StandardFlowEnabled || c.Protocol != "openid-connect" || c.ImplicitFlowEnabled || c.DirectAccessGrantsEnabled || c.ServiceAccountsEnabled || c.FullScopeAllowed || c.Attributes["pkce.code.challenge.method"] != "S256" {
			t.Errorf("client %q permits an unexpected authentication flow", c.ClientID)
		}
		if !slices.Equal(c.DefaultClientScopes, []string{"basic"}) {
			t.Errorf("client %q inherits unwanted scopes: %v", c.ClientID, c.DefaultClientScopes)
		}
		if c.ClientID == "toolbox-owner" {
			if c.Attributes["exclude.session.state.from.auth.response"] != "true" {
				t.Error("owner authorization response contains unsupported session_state")
			}
			if c.PublicClient || c.Secret != "private-owner-secret" || c.ClientAuthenticatorType != "client-secret" || !slices.Equal(c.RedirectURIs, []string{"http://127.0.0.1:8080/auth/oidc/callback"}) || len(c.OptionalClientScopes) != 0 {
				t.Errorf("owner client policy permits API audience or wrong callback: %+v", c)
			}
		} else {
			if !c.PublicClient || c.Secret != "" || !slices.Equal(c.OptionalClientScopes, []string{"mcp"}) || !slices.Equal(c.RedirectURIs, validConfig().MCPRedirectURIs[c.ClientID]) {
				t.Errorf("MCP client policy is not an exact public PKCE registration: %+v", c)
			}
		}
	}
	var foundMCP bool
	for _, scope := range r.ClientScopes {
		if scope.Name != "mcp" {
			continue
		}
		foundMCP = true
		if scope.Protocol != "openid-connect" || scope.Attributes["include.in.token.scope"] != "true" || len(scope.ProtocolMappers) != 1 {
			t.Fatalf("MCP scope does not issue an explicit scoped audience: %+v", scope)
		}
		mapper := scope.ProtocolMappers[0]
		if mapper.Protocol != "openid-connect" || mapper.ProtocolMapper != "oidc-audience-mapper" || mapper.Config["included.custom.audience"] != "http://127.0.0.1:8080/mcp" || mapper.Config["access.token.claim"] != "true" || mapper.Config["id.token.claim"] != "false" || mapper.Config["included.client.audience"] != "" {
			t.Fatalf("MCP audience is absent from access tokens or leaks into ID tokens: %+v", mapper)
		}
	}
	if !foundMCP {
		t.Fatal("MCP scope missing")
	}
}

func TestRenderKeepsUpstreamAccountsDistinct(t *testing.T) {
	r := renderRealm(t, validConfig())
	if r.RegistrationAllowed || r.RegistrationEmailAsUsername || !r.DuplicateEmailsAllowed || r.LoginWithEmailAllowed || len(r.Users) != 0 {
		t.Fatal("realm can register local credentials or identify people by email")
	}
	if len(r.AuthenticationFlows) != 1 {
		t.Fatalf("unexpected first-broker flows: %+v", r.AuthenticationFlows)
	}
	flow := r.AuthenticationFlows[0]
	if r.FirstBrokerLoginFlow != "toolbox-first-broker-login" {
		t.Fatal("realm-wide broker flow permits fallback account linking")
	}
	if flow.Alias != "toolbox-first-broker-login" || flow.ProviderID != "basic-flow" || !flow.TopLevel || flow.BuiltIn || len(flow.AuthenticationExecutions) != 1 {
		t.Fatalf("unexpected broker flow: %+v", flow)
	}
	execution := flow.AuthenticationExecutions[0]
	if execution.Authenticator != "idp-create-user-if-unique" || execution.Requirement != "REQUIRED" || execution.AuthenticatorFlow {
		t.Fatalf("broker flow can link an existing account: %+v", execution)
	}
	if len(r.IdentityProviders) != 2 || len(r.IdentityProviderMappers) != 2 {
		t.Fatal("missing configured providers or username isolation mappers")
	}
	for _, provider := range r.IdentityProviders {
		if !provider.Enabled || provider.TrustEmail || provider.StoreToken || provider.LinkOnly || provider.FirstBrokerLoginFlowAlias != "toolbox-first-broker-login" || provider.Config["syncMode"] != "IMPORT" {
			t.Errorf("provider %q has unsafe linking/token policy", provider.Alias)
		}
	}
	for _, mapper := range r.IdentityProviderMappers {
		if (mapper.IdentityProviderAlias != "okta" && mapper.IdentityProviderAlias != "google") || mapper.IdentityProviderMapper != "oidc-username-idp-mapper" || mapper.Config["template"] != "${ALIAS}.${CLAIM.sub}" || mapper.Config["target"] != "LOCAL" || mapper.Config["syncMode"] != "IMPORT" {
			t.Errorf("username mapper can collide across providers: %+v", mapper)
		}
	}
}

func TestRenderUsesOfficialDefaultScopeFactory(t *testing.T) {
	r := renderRealm(t, validConfig())
	if r.Attributes["CreateDefaultClientScopes"] != "true" {
		t.Fatal("Keycloak cannot provision normal builtin scopes and console assignments")
	}
	if len(r.ClientScopes) != 1 || r.ClientScopes[0].Name != "mcp" {
		t.Fatal("custom scope definitions collide with Keycloak's official default scopes")
	}
}

func TestRenderKeepsFactoryConsoleAndAdminScopesOffApplicationClients(t *testing.T) {
	r := renderRealm(t, validConfig())
	if r.Attributes["CreateDefaultClientScopes"] != "true" {
		t.Fatal("official builtin scope factory is disabled")
	}
	for _, client := range r.Clients {
		wantOptional := []string{}
		if client.PublicClient {
			wantOptional = []string{"mcp"}
		}
		if !slices.Equal(client.DefaultClientScopes, []string{"basic"}) || !slices.Equal(client.OptionalClientScopes, wantOptional) {
			t.Errorf("Toolbox client %q can acquire builtin console/Admin audiences", client.ClientID)
		}
	}
}

func TestRenderPinsUpstreamIssuerEndpointsAndWorkspace(t *testing.T) {
	for _, issuer := range []string{"https://example.okta.com", "https://example.okta.com/oauth2/default"} {
		t.Run(issuer, func(t *testing.T) {
			cfg := validConfig()
			cfg.OktaIssuer = issuer
			r := renderRealm(t, cfg)
			for _, p := range r.IdentityProviders {
				switch p.Alias {
				case "okta":
					base := "https://example.okta.com/oauth2/v1/"
					if strings.HasSuffix(issuer, "/default") {
						base = "https://example.okta.com/oauth2/default/v1/"
					}
					want := map[string]string{"issuer": issuer, "authorizationUrl": base + "authorize", "tokenUrl": base + "token", "jwksUrl": base + "keys", "userInfoUrl": base + "userinfo", "clientId": "okta-client", "clientSecret": "private-okta-secret", "clientAuthMethod": "client_secret_basic", "validateSignature": "true", "useJwksUrl": "true", "disableNonce": "false", "pkceEnabled": "true", "pkceMethod": "S256"}
					if p.ProviderID != "oidc" {
						t.Fatalf("Okta is not configured as generic OIDC")
					}
					for key, value := range want {
						if p.Config[key] != value {
							t.Errorf("Okta %s = %q; want %q", key, p.Config[key], value)
						}
					}
				case "google":
					if p.ProviderID != "google" || p.Config["issuer"] != "https://accounts.google.com" || p.Config["hostedDomain"] != "example.com" || p.Config["clientId"] != "google-client" || p.Config["clientSecret"] != "private-google-secret" || p.Config["validateSignature"] != "true" {
						t.Errorf("Google provider does not enforce a Workspace account: %+v", p)
					}
				default:
					t.Fatalf("unexpected provider alias %q", p.Alias)
				}
			}
		})
	}
}

func TestRenderRejectsUnsafeConfiguration(t *testing.T) {
	tests := []struct {
		name   string
		change func(*Config)
	}{
		{"empty realm", func(c *Config) { c.Realm = "" }},
		{"realm path", func(c *Config) { c.Realm = "../master" }},
		{"owner ID missing", func(c *Config) { c.OwnerClientID = "" }},
		{"owner secret missing", func(c *Config) { c.OwnerClientSecret = "" }},
		{"owner ID control", func(c *Config) { c.OwnerClientID = "bad\nclient" }},
		{"owner secret control", func(c *Config) { c.OwnerClientSecret = "bad\x00secret" }},
		{"external HTTP origin", func(c *Config) { c.Origin = "http://example.com:8080" }},
		{"HTTPS origin unsupported", func(c *Config) { c.Origin = "https://127.0.0.1:8080" }},
		{"origin needs port", func(c *Config) { c.Origin = "http://localhost" }},
		{"origin path", func(c *Config) { c.Origin += "/" }},
		{"origin query", func(c *Config) { c.Origin += "?" }},
		{"origin credentials", func(c *Config) { c.Origin = "http://user@127.0.0.1:8080" }},
		{"partial Okta", func(c *Config) { c.OktaClientSecret = "" }},
		{"HTTP Okta", func(c *Config) { c.OktaIssuer = "http://example.okta.com" }},
		{"query Okta", func(c *Config) { c.OktaIssuer += "?issuer=other" }},
		{"trailing slash issuer", func(c *Config) { c.OktaIssuer += "/" }},
		{"empty issuer fragment", func(c *Config) { c.OktaIssuer += "#" }},
		{"issuer list", func(c *Config) { c.OktaIssuer += ",https://attacker.example.com" }},
		{"partial Google", func(c *Config) { c.GoogleClientSecret = "" }},
		{"missing Workspace domain", func(c *Config) { c.GoogleHostedDomain = "" }},
		{"wildcard Workspace domain", func(c *Config) { c.GoogleHostedDomain = "*" }},
		{"Workspace list", func(c *Config) { c.GoogleHostedDomain = "example.com,attacker.com" }},
		{"no providers", func(c *Config) {
			c.OktaIssuer, c.OktaClientID, c.OktaClientSecret, c.GoogleClientID, c.GoogleClientSecret, c.GoogleHostedDomain = "", "", "", "", "", ""
		}},
		{"owner and MCP client collide", func(c *Config) {
			c.MCPClients[c.OwnerClientID] = "Owner impostor"
			c.MCPRedirectURIs[c.OwnerClientID] = []string{"https://attacker.example.com/callback"}
		}},
		{"built-in client collision", func(c *Config) { c.OwnerClientID = "account" }},
		{"MCP name missing", func(c *Config) { c.MCPClients["toolbox-agent"] = "" }},
		{"MCP redirects missing", func(c *Config) { delete(c.MCPRedirectURIs, "toolbox-agent") }},
		{"unknown redirect registration", func(c *Config) { c.MCPRedirectURIs["unknown"] = []string{"https://agent.example.com/callback"} }},
		{"wildcard redirect", func(c *Config) { c.MCPRedirectURIs["toolbox-agent"] = []string{"https://agent.example.com/*"} }},
		{"encoded wildcard redirect", func(c *Config) { c.MCPRedirectURIs["toolbox-agent"] = []string{"https://agent.example.com/%2a"} }},
		{"external HTTP redirect", func(c *Config) { c.MCPRedirectURIs["toolbox-agent"] = []string{"http://agent.example.com/callback"} }},
		{"redirect fragment", func(c *Config) {
			c.MCPRedirectURIs["toolbox-agent"] = []string{"https://agent.example.com/callback#fragment"}
		}},
		{"empty redirect fragment", func(c *Config) { c.MCPRedirectURIs["toolbox-agent"] = []string{"https://agent.example.com/callback#"} }},
		{"redirect credentials", func(c *Config) {
			c.MCPRedirectURIs["toolbox-agent"] = []string{"https://user:password@agent.example.com/callback"}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			tt.change(&cfg)
			got, err := Render(cfg)
			if err == nil || len(got) != 0 {
				t.Fatal("unsafe configuration produced realm import JSON")
			}
			if strings.Contains(err.Error(), "private-") || strings.Contains(err.Error(), "password@") {
				t.Fatal("validation error includes a secret")
			}
		})
	}
}

func TestRenderAllowsSingleProviderAndNoMCPClients(t *testing.T) {
	cfg := validConfig()
	cfg.GoogleClientID, cfg.GoogleClientSecret, cfg.GoogleHostedDomain = "", "", ""
	cfg.MCPClients, cfg.MCPRedirectURIs = nil, nil
	r := renderRealm(t, cfg)
	if len(r.IdentityProviders) != 1 || r.IdentityProviders[0].Alias != "okta" || len(r.Clients) != 1 {
		t.Fatal("disabled optional providers/clients were generated")
	}
	cfg = validConfig()
	cfg.OktaIssuer, cfg.OktaClientID, cfg.OktaClientSecret = "", "", ""
	cfg.Origin = "http://[::1]:8080"
	r = renderRealm(t, cfg)
	if len(r.IdentityProviders) != 1 || r.IdentityProviders[0].Alias != "google" || r.Clients[0].RedirectURIs[0] != "http://[::1]:8080/auth/oidc/callback" {
		t.Fatal("Google-only or IPv6 loopback configuration failed")
	}
}

func TestRenderIsDeterministicAndDoesNotMutateConfig(t *testing.T) {
	cfg := validConfig()
	before, _ := json.Marshal(cfg)
	first, err := Render(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for range 10 {
		next, err := Render(cfg)
		if err != nil || !bytes.Equal(first, next) {
			t.Fatal("map iteration makes realm import non-deterministic")
		}
	}
	after, _ := json.Marshal(cfg)
	if !bytes.Equal(before, after) {
		t.Fatal("Render mutated operator configuration")
	}
}
