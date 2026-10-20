package identity

import (
	"context"
	"testing"
)

func TestAccessOnlyVerifierPreservesOrganizationUIDBinding(t *testing.T) {
	f := newTestIssuer(t)
	cfg := AccessConfig{Issuer: f.server.URL + "/oauth2/default", OwnerIssuer: f.server.URL, Audience: "api://toolbox-mcp", OwnerClientID: "owner-client", Clients: map[string]string{"agent-client": "Local client"}, AllowLoopbackHTTP: true}
	service, err := NewAccess(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	c := f.claims()
	c["iss"] = cfg.Issuer
	claims, err := service.VerifyAccess(context.Background(), f.sign(t, c))
	if err != nil || claims.UserID != "00uImmutable" || service.OwnerIssuer() != f.server.URL {
		t.Fatalf("signed uid/org binding lost: %+v %v", claims, err)
	}
	if _, err := service.AuthorizationURL("state", "nonce", "verifier"); err == nil {
		t.Fatal("access verifier exposed a second owner login")
	}
}

func TestOktaOwnerBindingRequiresExactTenantAndCustomServer(t *testing.T) {
	for _, tc := range []struct {
		owner, access string
		valid         bool
	}{
		{"https://tenant.okta.example", "https://tenant.okta.example/oauth2/default", true},
		{"https://tenant.okta.example", "https://other.okta.example/oauth2/default", false},
		{"https://tenant.okta.example", "https://tenant.okta.example", false},
		{"https://tenant.okta.example/oauth2/other", "https://tenant.okta.example/oauth2/default", false},
		{"https://tenant.okta.example", "https://tenant.okta.example/oauth2/default/extra", false},
		{"https://tenant.okta.example", "https://tenant.okta.example/oauth2/default?claim=uid", false},
		{"https://tenant.okta.example", "https://user@tenant.okta.example/oauth2/default", false},
		{"https://tenant.okta.example", "http://tenant.okta.example/oauth2/default", false},
	} {
		if got := ValidOwnerBinding(tc.owner, tc.access, false); got != tc.valid {
			t.Errorf("unexpected binding result for %q / %q: %t", tc.owner, tc.access, got)
		}
	}
}
