package ownerlogin

import (
	"context"
	"github.com/ufaruq/toolbox/internal/domain"
	"github.com/ufaruq/toolbox/internal/security"
	"testing"
)

func TestOwnerLoginVerifiedAliasPreservesLegacyOwner(t *testing.T) {
	f := newLoginFixture(t)
	err := f.repo.Transact(context.Background(), func(st *domain.State) error {
		st.Users["legacy"] = domain.User{ID: "legacy", Issuer: "https://old-okta.example", Subject: "immutable-old-sub", Status: "active"}
		a := domain.IdentityAlias{Issuer: f.cfg.Issuer, Subject: "owner-1", OwnerID: "legacy"}
		st.IdentityAliases[domain.IdentityKey(a.Issuer, a.Subject)] = a
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	result := f.complete(t, "")
	if result.UserID != "legacy" {
		t.Fatalf("alias created another account: %s", result.UserID)
	}
	st := f.snapshot(t)
	if len(st.Users) != 1 || st.Users["legacy"].Issuer != "https://old-okta.example" || st.Users["legacy"].Subject != "immutable-old-sub" {
		t.Fatal("primary identity changed")
	}
	if !f.service.SessionBound(st, security.Hash(result.SessionToken)) {
		t.Fatal("verified alias session rejected")
	}
	// An issuer switch still invalidates the old configuration's sessions.
	cfg := f.cfg
	cfg.Issuer = "https://old-okta.example"
	old, err := NewService(f.repo, f.secrets, f.provider, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if old.SessionBound(st, security.Hash(result.SessionToken)) {
		t.Fatal("session configuration crossed issuer boundary")
	}
}

func TestOwnerLoginDisabledAliasedOwnerDenied(t *testing.T) {
	f := newLoginFixture(t)
	if err := f.repo.Transact(context.Background(), func(st *domain.State) error {
		st.Users["legacy"] = domain.User{ID: "legacy", Issuer: "https://old-okta.example", Subject: "old-sub", Status: "disabled"}
		a := domain.IdentityAlias{Issuer: f.cfg.Issuer, Subject: "owner-1", OwnerID: "legacy"}
		st.IdentityAliases[domain.IdentityKey(a.Issuer, a.Subject)] = a
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	start, state := f.start(t, "")
	if _, err := f.service.Complete(context.Background(), state, "code", start.BrowserToken); err != domain.ErrDenied {
		t.Fatalf("disabled alias: %v", err)
	}
}
