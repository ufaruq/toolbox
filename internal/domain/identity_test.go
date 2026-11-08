package domain

import "testing"

func TestIdentityAliasesResolveOnlyExactBindings(t *testing.T) {
	s := NewState()
	s.Users["legacy"] = User{ID: "legacy", Issuer: "https://okta.example", Subject: "old-sub", Status: "active"}
	a := IdentityAlias{Issuer: "https://keycloak.example/realms/toolbox", Subject: "kc-sub", OwnerID: "legacy"}
	s.IdentityAliases[IdentityKey(a.Issuer, a.Subject)] = a
	for _, v := range []IdentityAlias{{Issuer: "https://okta.example", Subject: "old-sub"}, a} {
		u, ok := ResolveIdentity(s, v.Issuer, v.Subject)
		if !ok || u.ID != "legacy" {
			t.Fatalf("binding did not resolve: %+v %v", u, ok)
		}
	}
	if _, ok := ResolveIdentity(s, "https://google.example", "kc-sub"); ok {
		t.Fatal("foreign issuer resolved")
	}
	if got, ok := IdentityForOwner(s, "legacy", a.Issuer); !ok || got != a {
		t.Fatalf("alias = %+v %v", got, ok)
	}
	other := a
	other.Subject = "second"
	s.IdentityAliases[IdentityKey(other.Issuer, other.Subject)] = other
	if _, ok := IdentityForOwner(s, "legacy", a.Issuer); ok {
		t.Fatal("ambiguous owner identity accepted")
	}
}

func TestIdentityKeyPreservesPairBoundaries(t *testing.T) {
	if IdentityKey("a", "bc") == IdentityKey("ab", "c") || IdentityKey("a\x00b", "c") == IdentityKey("a", "b\x00c") {
		t.Fatal("identity keys collide")
	}
}
