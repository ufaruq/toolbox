package server

import (
	"context"
	"encoding/json"
	"github.com/ufaruq/toolbox/internal/domain"
	"github.com/ufaruq/toolbox/internal/identity"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCallerApprovalUsesVerifiedAliasWithoutReassigningLegacyProfile(t *testing.T) {
	idp := &testIdentity{}
	s, repo, _ := invocationFixture(t, domain.User{ID: "owner", Issuer: "https://old-okta.example", Subject: "old-sub", Status: "active"})
	s.Identity = idp
	if err := repo.Transact(context.Background(), func(st *domain.State) error {
		a := domain.IdentityAlias{Issuer: idp.Issuer(), Subject: "uid-owner", OwnerID: "owner"}
		st.IdentityAliases[domain.IdentityKey(a.Issuer, a.Subject)] = a
		st.CallerProfiles["old-profile"] = domain.CallerProfile{ID: "old-profile", OwnerID: "owner", AgentID: "agent", Issuer: "https://old-okta.example", UserID: "old-sub", ClientID: "web", Status: "active", ApprovedAt: st.Now, ExpiresAt: st.Now.Add(time.Hour)}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	claims := identity.Claims{Issuer: idp.Issuer(), UserID: "uid-owner", ClientID: "web", ExpiresAt: time.Now().Add(time.Hour)}
	if _, err := s.resolveCaller(context.Background(), claims); err == nil {
		t.Fatal("old approval silently reused after issuer change")
	}
	cookie, csrf := ownerCookie(t, s, "owner")
	r := httptest.NewRequest("GET", "/v1/callers", nil)
	r.AddCookie(cookie)
	listed := httptest.NewRecorder()
	s.ServeHTTP(listed, r)
	var listing struct {
		OwnerIssuer string                 `json:"owner_issuer"`
		Callers     []domain.CallerProfile `json:"-"`
	}
	if err := json.Unmarshal(listed.Body.Bytes(), &listing); err != nil || listed.Code != 200 || listing.OwnerIssuer != idp.Issuer() {
		t.Fatal("caller listing did not distinguish the current issuer from a legacy approval")
	}
	w := ownerPost(s, "/v1/callers", `{"client_id":"web","label":"Broker","tools":[],"duration_seconds":3600}`, cookie, csrf)
	if w.Code != 201 {
		t.Fatalf("alias approval=%d %s", w.Code, w.Body)
	}
	var view struct {
		ID      string `json:"id"`
		AgentID string `json:"agent_id"`
		Issuer  string `json:"issuer"`
		UserID  string `json:"user_id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if view.Issuer != idp.Issuer() || view.UserID != "uid-owner" || view.AgentID == "agent" {
		t.Fatal("incorrect new approval binding")
	}
	access, err := s.resolveCaller(context.Background(), claims)
	if err != nil || access.AgentID != view.AgentID {
		t.Fatalf("alias caller denied: %v", err)
	}
	if err := repo.Transact(context.Background(), func(st *domain.State) error {
		if st.CallerProfiles["old-profile"].Issuer != "https://old-okta.example" || st.Users["owner"].Subject != "old-sub" {
			t.Fatal("legacy identity mutated")
		}
		u := st.Users["owner"]
		u.Status = "disabled"
		st.Users[u.ID] = u
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.resolveCaller(context.Background(), claims); err == nil {
		t.Fatal("disabled aliased owner authenticated")
	}
}
