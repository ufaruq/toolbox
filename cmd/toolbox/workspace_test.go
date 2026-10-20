package main

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/ufaruq/toolbox/internal/domain"
	"github.com/ufaruq/toolbox/internal/store"
	"github.com/ufaruq/toolbox/internal/tokens"
)

func TestWorkspaceFactoryRequiresValidatedRealGoogleAndNeverFixtures(t *testing.T) {
	cfg := runtimeConfig{origin: "http://127.0.0.1:8080", workspace: workspaceConfig{googleClientID: "client", googleClientSecret: "secret"}}
	repo, secrets := store.NewMemory(), tokens.NewMemorySecretStore()
	if _, err := newWorkspaceIntegration(cfg, repo, secrets); err == nil {
		t.Fatal("factory bypassed actual-client PKCE gate")
	}
	cfg.workspace.pkceValidated = true
	i, err := newWorkspaceIntegration(cfg, repo, secrets)
	if err != nil {
		t.Fatal(err)
	}
	if i.Fixture != nil {
		t.Fatal("runtime selected fixture provider")
	}
	if err := repo.Transact(context.Background(), func(st *domain.State) error {
		st.Users["owner"] = domain.User{ID: "owner", Issuer: "https://idp.example.test", Subject: "owner", Status: "active"}
		st.Sessions["session"] = domain.Session{ID: "session", UserID: "owner", CSRFHash: "csrf", ExpiresAt: st.Now.Add(time.Hour)}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	start, err := i.Start(context.Background(), "owner", "session")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(start)
	if u.Scheme != "https" || u.Host != "accounts.google.com" || u.Query().Get("scope") != "openid email "+domain.DriveScope || u.Query().Get("redirect_uri") != cfg.origin+"/oauth/callback" || u.Query().Has("client_secret") || u.Query().Get("code_challenge_method") != "S256" {
		t.Fatal("incorrect real Google wiring")
	}
}
