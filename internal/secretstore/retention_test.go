package secretstore

import (
	"context"
	"github.com/jackc/pgx/v5"
	"github.com/ufaruq/toolbox/internal/domain"
	"github.com/ufaruq/toolbox/internal/store"
	"github.com/ufaruq/toolbox/internal/tokens"
	"testing"
	"time"
)

func TestRetentionProtectsUnknownCurrentAndCreationFence(t *testing.T) {
	s := testPostgres(t)
	ctx := context.Background()
	repo := store.NewMemory()
	if err := repo.Transact(ctx, func(st *domain.State) error {
		st.Users["u"] = domain.User{ID: "u", Issuer: "fixture", Subject: "u", Status: "active"}
		st.Connections["c"] = domain.Connection{ID: "c", OwnerID: "u", Provider: "google_drive", Subject: "subject", ClientID: "client", Status: "active", Epoch: 1, SecretVersion: 2}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	b := tokens.Bundle{ConnectionID: "c", Subject: "subject", ClientID: "client", Epoch: 1, Generation: 1, State: tokens.StateActive, RefreshToken: "synthetic"}
	if _, err := s.Put(ctx, "connections/c", b, 0); err != nil {
		t.Fatal(err)
	}
	b.State = tokens.StateRefreshing
	if _, err := s.Put(ctx, "connections/c", b, 1); err != nil {
		t.Fatal(err)
	}
	_, _ = s.pool.Exec(ctx, "UPDATE "+s.history+" SET created_at=clock_timestamp()-interval '10 days'")
	r, err := s.RunRetention(ctx, repo, RetentionPolicy{})
	if err != nil || r.Deleted != 0 || r.Blocked == 0 {
		t.Fatal(r, err)
	}
	b.State = tokens.StateActive
	b.Generation = 2
	if _, err = s.Put(ctx, "connections/c", b, 2); err != nil {
		t.Fatal(err)
	}
	_ = repo.Transact(ctx, func(st *domain.State) error {
		c := st.Connections["c"]
		c.SecretVersion = 3
		st.Connections["c"] = c
		return nil
	})
	r, err = s.RunRetention(ctx, repo, RetentionPolicy{})
	if err != nil || r.Deleted != 2 {
		t.Fatal(r, err)
	}
	if _, v, err := s.Get(ctx, "connections/c"); err != nil || v != 3 {
		t.Fatal(v, err)
	}
	if _, err = s.pool.Exec(ctx, "DELETE FROM "+s.history+" WHERE version=3"); err == nil {
		t.Fatal("current generation deleted")
	}
	r, err = s.RunRetention(ctx, repo, RetentionPolicy{})
	if err != nil || r.Deleted != 0 {
		t.Fatal(r, err)
	}
}

func TestOAuthRetentionHidesVerifierKeepsFence(t *testing.T) {
	s := testPostgres(t)
	ctx := context.Background()
	repo := store.NewMemory()
	if err := repo.Transact(ctx, func(st *domain.State) error {
		st.Users["u"] = domain.User{ID: "u", Issuer: "fixture", Subject: "u", Status: "active"}
		st.Sessions["session"] = domain.Session{ID: "session", UserID: "u", CSRFHash: "hash", ExpiresAt: st.Now.Add(time.Hour)}
		st.Connections["c"] = domain.Connection{ID: "c", OwnerID: "u", Provider: "google_drive", Status: "disconnected", Epoch: 2, SecretVersion: 1}
		st.OAuth["o"] = domain.OAuthTransaction{ID: "o", OwnerID: "u", SessionID: "session", StateHash: "hash", NonceHash: "hash", SecretRef: "oauth-transactions/o", ConnectionID: "c", Consumed: true, ExpiresAt: st.Now.Add(-2 * time.Hour)}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put(ctx, "connections/c", tokens.Bundle{ConnectionID: "c", Epoch: 2, State: tokens.StateTombstoned}, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PutJSON(ctx, "oauth-transactions/o", map[string]string{"verifier": "synthetic"}, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(ctx, "UPDATE "+s.history+" SET created_at=clock_timestamp()-interval '2 hours'"); err != nil {
		t.Fatal(err)
	}
	r, err := s.RunRetention(ctx, repo, RetentionPolicy{})
	if err != nil || r.Deleted != 1 {
		t.Fatal(r, err)
	}
	var out map[string]string
	if _, err = s.GetJSON(ctx, "oauth-transactions/o", &out); err != tokens.ErrNotFound {
		t.Fatal(err)
	}
	if _, err = s.PutJSON(ctx, "oauth-transactions/o", map[string]string{}, 0); err != tokens.ErrCAS {
		t.Fatal("OAuth fence removed", err)
	}
}

func TestRetentionMissingBundlePreservesVerifierAndAdvancesCursor(t *testing.T) {
	s := testPostgres(t)
	ctx := context.Background()
	repo := store.NewMemory()
	if err := repo.Transact(ctx, func(st *domain.State) error {
		st.Users["u"] = domain.User{ID: "u", Issuer: "fixture", Subject: "u", Status: "active"}
		st.Sessions["session"] = domain.Session{ID: "session", UserID: "u", CSRFHash: "hash", ExpiresAt: st.Now.Add(time.Hour)}
		for _, id := range []string{"a", "b"} {
			st.Connections[id] = domain.Connection{ID: id, OwnerID: "u", Provider: "google_drive", Status: "disconnected", Epoch: 2}
			st.OAuth[id] = domain.OAuthTransaction{ID: id, OwnerID: "u", SessionID: "session", StateHash: id, NonceHash: id, SecretRef: "oauth-transactions/" + id, ConnectionID: id, Consumed: true, ExpiresAt: st.Now.Add(-2 * time.Hour)}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"a", "b"} {
		if _, err := s.PutJSON(ctx, "oauth-transactions/"+id, map[string]string{"verifier": "synthetic"}, 0); err != nil {
			t.Fatal(err)
		}
	}
	// Neither attempt reached the exchange that creates a connection bundle.
	for _, id := range []string{"a", "b"} {
		report, err := s.RunRetention(ctx, repo, RetentionPolicy{Limit: 1})
		if err != nil || report.Scanned != 1 || report.Blocked != 1 || report.Deleted != 0 {
			t.Fatalf("missing bundle blocked the entire scan: %+v %v", report, err)
		}
		var cursor string
		if err := s.pool.QueryRow(ctx, "SELECT path FROM "+pgx.Identifier{s.envelope.schema}.Sanitize()+".retention_cursor WHERE id").Scan(&cursor); err != nil {
			t.Fatal(err)
		}
		if cursor != "oauth-transactions/"+id {
			t.Fatalf("retention did not progress: cursor=%q", cursor)
		}
		var verifier map[string]string
		if _, err := s.GetJSON(ctx, "oauth-transactions/"+id, &verifier); err != nil || verifier["verifier"] != "synthetic" {
			t.Fatal("uncertain verifier was destroyed", err)
		}
	}
}
