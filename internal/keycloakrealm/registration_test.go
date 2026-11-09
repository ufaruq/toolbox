package keycloakrealm

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDynamicRegistrationPolicy(t *testing.T) {
	cfg := validConfig()
	cfg.DynamicClientRegistration = true
	cfg.DynamicRegistrationTrustedHosts = []string{"127.0.0.1", "agent.example.com"}
	raw, err := Render(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var r map[string]any
	if json.Unmarshal(raw, &r) != nil {
		t.Fatal("invalid import")
	}
	if r["components"] == nil || r["clientPolicies"] == nil || r["clientProfiles"] == nil {
		t.Fatal("registration hardening missing")
	}
	for _, want := range []string{`"trusted-hosts"`, `"max-clients"`, `"128"`, `"pkce-enforcer"`, `"secure-client-uris-pattern"`, `"allowed-protocol-mappers"`, `"consent-required"`, `"ByRegistrationAccessToken"`, `"STRICT"`, `"toolbox-dcr-setup-required"`, `"allowed-protocol-mapper-types"`} {
		if !strings.Contains(string(raw), want) {
			t.Fatal("missing", want)
		}
	}
	cfg.DynamicClientRegistration = false
	cfg.DynamicRegistrationTrustedHosts = nil
	raw, err = Render(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"components"`) {
		t.Fatal("default registration changed")
	}
}
func TestDynamicRegistrationRequiresExactHosts(t *testing.T) {
	for _, hosts := range [][]string{nil, {}, {"*"}, {"*.example.com"}, {"https://example.com"}, {"example.com:443"}, {"example.com/path"}, {"127.1"}, {"2130706433"}, {"example.com\n"}, {"example.com", "example.com"}} {
		cfg := validConfig()
		cfg.DynamicClientRegistration = true
		cfg.DynamicRegistrationTrustedHosts = hosts
		if _, err := Render(cfg); err == nil {
			t.Fatalf("unsafe hosts accepted: %q", hosts)
		}
	}
}
