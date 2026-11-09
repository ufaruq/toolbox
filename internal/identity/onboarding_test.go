package identity

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestKeycloakOnboardingUnknownIdentityRequiresExplicitPath(t *testing.T) {
	f := newKeycloakFixture(t)
	cfg := f.config()
	cfg.DynamicClientOnboarding = true
	s, err := NewAccess(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	api := s
	if !api.DynamicClientOnboarding() {
		t.Fatal("explicit onboarding option was not enabled")
	}
	c := f.claims()
	c["azp"] = "dynamically-registered-client"
	raw := f.sign(t, c)
	if got, err := s.VerifyAccess(context.Background(), raw); err == nil || got != (Claims{}) {
		t.Fatalf("static verifier admitted unknown client: %#v %v", got, err)
	}
	got, err := api.VerifyOnboardingAccess(context.Background(), raw)
	if err != nil || got.Issuer != f.issuer() || got.UserID != "realm-immutable-user" || got.ClientID != "dynamically-registered-client" || got.ExpiresAt.Unix() != c["exp"] {
		t.Fatalf("verified identity: %#v %v", got, err)
	}
	if _, ok := s.Clients()[got.ClientID]; ok {
		t.Fatal("verification changed static authorization policy")
	}
	if got, err := s.VerifyAccess(context.Background(), f.sign(t, f.claims())); err != nil || got.ClientID != "agent-client" {
		t.Fatalf("static behavior changed: %#v %v", got, err)
	}
	static := keycloakService(t, f)
	api = static
	if api.DynamicClientOnboarding() {
		t.Fatal("onboarding enabled by default")
	}
	if got, err := api.VerifyOnboardingAccess(context.Background(), raw); err == nil || got != (Claims{}) {
		t.Fatalf("disabled onboarding admitted identity: %#v %v", got, err)
	}
}
func TestKeycloakOnboardingAllowsNoStaticClients(t *testing.T) {
	f := newKeycloakFixture(t)
	cfg := f.config()
	cfg.Clients = nil
	cfg.DynamicClientOnboarding = true
	s, err := NewAccess(context.Background(), cfg)
	if err != nil {
		t.Fatalf("onboarding required a preconfigured static client: %v", err)
	}
	if got, err := s.VerifyOnboardingAccess(context.Background(), f.sign(t, f.claims())); err != nil || got.ClientID != "agent-client" {
		t.Fatalf("unknown client identity denied: %#v %v", got, err)
	}
}
func TestOnboardingRejectsOktaConfigurationAndPath(t *testing.T) {
	f := newTestIssuer(t)
	for _, provider := range []string{"", "okta"} {
		t.Run("provider "+provider, func(t *testing.T) {
			cfg := AccessConfig{Provider: provider, Issuer: f.server.URL + "/oauth2/default", OwnerIssuer: f.server.URL, Audience: "api://toolbox-mcp", OwnerClientID: "owner-client", Clients: map[string]string{"agent-client": "Agent"}, AllowLoopbackHTTP: true}
			cfg.DynamicClientOnboarding = true
			if _, err := NewAccess(context.Background(), cfg); err == nil {
				t.Fatal("Okta accepted onboarding configuration")
			}
			// An ordinary Okta service must also deny the onboarding API.
			cfg.DynamicClientOnboarding = false
			s, err := NewAccess(context.Background(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			c := f.claims()
			c["iss"] = cfg.Issuer
			if got, err := s.VerifyOnboardingAccess(context.Background(), f.sign(t, c)); err == nil || got != (Claims{}) {
				t.Fatalf("Okta onboarding admitted identity: %#v %v", got, err)
			}
		})
	}
}
func TestKeycloakOnboardingPreservesFullSignedClaimValidation(t *testing.T) {
	f := newKeycloakFixture(t)
	cfg := f.config()
	cfg.DynamicClientOnboarding = true
	s, err := NewAccess(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	api := s
	cases := []struct {
		name, key string
		value     any
		remove    bool
	}{
		{"issuer", "iss", "https://wrong.example/realms/toolbox", false}, {"audience", "aud", "other", false}, {"multi audience", "aud", []string{cfg.Audience, "other"}, false},
		{"scope", "scope", "openid not-mcp", false}, {"type", "typ", "ID", false}, {"expired", "exp", 1, false}, {"future issue", "iat", 9999999999, false},
		{"missing user", "sub", nil, true}, {"missing session", "sid", nil, true}, {"blank session", "sid", " ", false}, {"missing client", "azp", nil, true},
		{"client credentials", "grant_type", "client_credentials", false}, {"service account identifier", "service_account_id", "account-id", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := f.claims()
			c["azp"] = "new-client"
			if tc.remove {
				delete(c, tc.key)
			} else {
				c[tc.key] = tc.value
			}
			if got, err := api.VerifyOnboardingAccess(context.Background(), f.sign(t, c)); err == nil || got != (Claims{}) {
				t.Fatalf("invalid token admitted: %#v %v", got, err)
			}
		})
	}
	c := f.claims()
	c["azp"] = "new-client"
	parts := strings.Split(f.sign(t, c), ".")
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	sig[0] ^= 1
	parts[2] = base64.RawURLEncoding.EncodeToString(sig)
	if got, err := api.VerifyOnboardingAccess(context.Background(), strings.Join(parts, ".")); err == nil || got != (Claims{}) {
		t.Fatalf("invalid signature admitted: %#v %v", got, err)
	}
	b, _ := json.Marshal(c)
	ambiguous := strings.Replace(string(b), `"sub":`, `"SUB":"attacker","sub":`, 1)
	if _, err := api.VerifyOnboardingAccess(context.Background(), f.signRaw(t, `{"alg":"RS256","kid":"key-1"}`, ambiguous)); err == nil {
		t.Fatal("ambiguous JSON admitted")
	}
	// User-controlled presentation names are not proof of account type.
	c["preferred_username"] = "service-account-human-chosen-name"
	if _, err := api.VerifyOnboardingAccess(context.Background(), f.sign(t, c)); err != nil {
		t.Fatalf("display name replaced session identity: %v", err)
	}
}
func TestKeycloakReservedClientsRejectedOnBothPaths(t *testing.T) {
	f := newKeycloakFixture(t)
	for _, id := range []string{"owner-client", f.config().Audience, "account", "account-console", "admin-cli", "broker", "realm-management", "security-admin-console"} {
		t.Run(id, func(t *testing.T) {
			cfg := f.config()
			cfg.DynamicClientOnboarding = true
			s, err := NewAccess(context.Background(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			c := f.claims()
			c["azp"] = id
			if got, err := s.VerifyAccess(context.Background(), f.sign(t, c)); err == nil || got != (Claims{}) {
				t.Fatalf("static reserved client admitted: %#v %v", got, err)
			}
			if got, err := s.VerifyOnboardingAccess(context.Background(), f.sign(t, c)); err == nil || got != (Claims{}) {
				t.Fatalf("onboarding reserved client admitted: %#v %v", got, err)
			}
			cfg.Clients[id] = "Reserved"
			if _, err := NewAccess(context.Background(), cfg); err == nil {
				t.Fatal("reserved client configured as eligible")
			}
		})
	}
}
