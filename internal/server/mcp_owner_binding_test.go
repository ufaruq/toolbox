package server

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/ufaruq/toolbox/internal/domain"
	"github.com/ufaruq/toolbox/internal/identity"
)

type boundIdentity struct {
	*testIdentity
	ownerIssuer string
}

func (i boundIdentity) OwnerIssuer() string { return i.ownerIssuer }

func TestMCPRetainsOrganizationOwnerAndGoogleConnection(t *testing.T) {
	api, _, cookie, csrf := newWorkspaceHTTP(t)
	api.Identity = boundIdentity{testIdentity: &testIdentity{}, ownerIssuer: api.OwnerLogin.Issuer()}
	var before domain.Connection
	var owner domain.User
	if err := api.Repository.Transact(context.Background(), func(st *domain.State) error {
		before = st.Connections["own"]
		owner = st.Users[before.OwnerID]
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	response := ownerRequest(api, "POST", "/v1/callers", `{"client_id":"code","label":"Local MCP client","tools":["google_drive.read_document.v1"],"duration_seconds":3600}`, api.Origin, csrf, cookie)
	if response.Code != 201 {
		t.Fatalf("existing organization owner cannot approve MCP client: %d %s", response.Code, response.Body)
	}
	var profile struct {
		AgentID string `json:"agent_id"`
		Issuer  string `json:"issuer"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &profile); err != nil {
		t.Fatal(err)
	}
	if profile.Issuer != owner.Issuer {
		t.Fatal("owner issuer was replaced by MCP issuer")
	}
	claims := identity.Claims{Issuer: api.Identity.Issuer(), UserID: owner.Subject, ClientID: "code", ExpiresAt: time.Now().Add(time.Hour)}
	access, err := api.resolveCaller(context.Background(), claims)
	if err != nil || access.AgentID != profile.AgentID {
		t.Fatalf("verified MCP uid did not resolve to existing owner profile: %v", err)
	}
	for _, invalid := range []identity.Claims{
		{Issuer: "https://other-tenant.example/oauth2/default", UserID: owner.Subject, ClientID: "code", ExpiresAt: claims.ExpiresAt},
		{Issuer: claims.Issuer, UserID: "another-user", ClientID: "code", ExpiresAt: claims.ExpiresAt},
		{Issuer: claims.Issuer, UserID: owner.Subject, ClientID: "unknown", ExpiresAt: claims.ExpiresAt},
	} {
		if _, err := api.resolveCaller(context.Background(), invalid); err == nil {
			t.Fatal("wrong tenant, user or client reused owner profile")
		}
	}
	if err := api.Repository.Transact(context.Background(), func(st *domain.State) error {
		c := st.Connections["own"]
		if c.OwnerID != before.OwnerID || c.Subject != before.Subject || c.Epoch != before.Epoch || st.Users[owner.ID] != owner || len(st.Users) != 2 {
			t.Fatal("MCP approval replaced existing owner or Google connection")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
