package recovery

import (
	"context"
	"github.com/ufaruq/toolbox/internal/domain"
	"github.com/ufaruq/toolbox/internal/store"
	"testing"
	"time"
)

func TestInvalidateRestoredAuthorityIsIdempotent(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemory()
	err := repo.Transact(ctx, func(st *domain.State) error {
		st.Users["u"] = domain.User{ID: "u", Issuer: "fixture", Subject: "u", Status: "active"}
		st.Agents["a"] = domain.Agent{ID: "a", OwnerID: "u", Status: "active"}
		st.Credentials["k"] = domain.Credential{ID: "k", AgentID: "a", Hash: "hash", Status: "active", ExpiresAt: st.Now.Add(time.Hour)}
		st.Sessions["s"] = domain.Session{ID: "s", UserID: "u", CSRFHash: "hash", ExpiresAt: st.Now.Add(time.Hour)}
		st.Connections["c"] = domain.Connection{ID: "c", OwnerID: "u", Provider: "google_drive", Status: "active", Epoch: 1}
		st.Resources["c:f"] = domain.Resource{ConnectionID: "c", FileID: "f"}
		st.Grants["g"] = domain.Grant{ID: "g", OwnerID: "u", AgentID: "a", ConnectionID: "c", Tool: domain.Tool, Action: domain.Action, FileID: "f", Epoch: 1, Version: 1, NotBefore: st.Now, ExpiresAt: st.Now.Add(time.Hour)}
		st.OAuth["o"] = domain.OAuthTransaction{ID: "o", OwnerID: "u", SessionID: "s", StateHash: "hash", NonceHash: "hash", SecretRef: "oauth-transactions/o", ConnectionID: "c", ExpiresAt: st.Now.Add(time.Minute)}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	r, err := Invalidate(ctx, repo)
	if err != nil || r.Connections != 1 || r.Credentials != 1 {
		t.Fatal(r, err)
	}
	r, err = Invalidate(ctx, repo)
	if err != nil || r.Connections != 0 || r.Credentials != 0 {
		t.Fatal(r, err)
	}
	_ = repo.Transact(ctx, func(st *domain.State) error {
		if st.Connections["c"].Epoch != 2 || st.Connections["c"].Status != "disconnecting" || st.Grants["g"].RevokedAt == nil || st.Credentials["k"].Status != "revoked" || st.Sessions["s"].ExpiresAt.After(st.Now) || len(st.Cleanup) != 1 || len(st.OAuth) != 1 {
			t.Fatal("authority restored or references destroyed")
		}
		return nil
	})
}
