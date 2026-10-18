package secretstore

import (
	"context"
	"github.com/ufaruq/toolbox/internal/domain"
	"github.com/ufaruq/toolbox/internal/store"
	"github.com/ufaruq/toolbox/internal/tokens"
	"testing"
	"time"
)

type lostCommit struct {
	*Postgres
	at, calls int
}

func (s *lostCommit) Put(ctx context.Context, path string, b tokens.Bundle, cas int64) (int64, error) {
	v, err := s.Postgres.Put(ctx, path, b, cas)
	s.calls++
	if err == nil && s.calls == s.at {
		return 0, tokens.ErrUnavailable
	}
	return v, err
}

type refreshBoundary struct {
	calls   int
	unknown bool
}

func (p *refreshBoundary) Refresh(context.Context, string) (tokens.RefreshResult, error) {
	p.calls++
	if p.unknown {
		return tokens.RefreshResult{}, tokens.ErrUnavailable
	}
	return tokens.RefreshResult{AccessToken: "synthetic-new", RefreshToken: "synthetic-rotated", Scopes: []string{domain.DriveScope}, Expiry: time.Now().Add(time.Hour)}, nil
}
func (p *refreshBoundary) Revoke(context.Context, string) error { return nil }
func TestEncryptedRefreshLostCommitAndUnknownOutcome(t *testing.T) {
	for _, kind := range []string{"intent-response-lost", "result-response-lost", "provider-outcome-unknown"} {
		t.Run(kind, func(t *testing.T) {
			s := testPostgres(t)
			repo := store.NewMemory()
			ctx := context.Background()
			if err := repo.Transact(ctx, func(st *domain.State) error {
				st.Users["u"] = domain.User{ID: "u", Issuer: "fixture", Subject: "u", Status: "active"}
				st.Connections["c"] = domain.Connection{ID: "c", OwnerID: "u", Provider: "google_drive", Status: "active", Subject: "subject", ClientID: "client", Epoch: 1, SecretVersion: 1, Scopes: []string{domain.DriveScope}}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			b := tokens.Bundle{ConnectionID: "c", Subject: "subject", ClientID: "client", Epoch: 1, Generation: 1, OperationID: "initial", State: tokens.StateActive, AccessToken: "synthetic-expired", RefreshToken: "synthetic-old", Scopes: []string{domain.DriveScope}, Expiry: time.Now().Add(-time.Hour)}
			if _, err := s.Put(ctx, tokens.Path("c"), b, 0); err != nil {
				t.Fatal(err)
			}
			lost := &lostCommit{Postgres: s, at: 1}
			if kind == "result-response-lost" {
				lost.at = 2
			}
			p := &refreshBoundary{unknown: kind == "provider-outcome-unknown"}
			manager := &tokens.Manager{Repository: repo, Secrets: lost, Provider: p}
			lease, err := manager.AccessLease(ctx, "c", func(context.Context) error { return nil })
			if p.calls != 1 {
				t.Fatal("refresh replay", p.calls)
			}
			if p.unknown {
				if err == nil || lease.Token != "" {
					t.Fatal("unknown response released authority")
				}
				current, _, err := s.Get(ctx, tokens.Path("c"))
				if err != nil || current.State != tokens.StateRefreshing {
					t.Fatal("lost uncertainty fence", err)
				}
				r, err := s.RunRetention(ctx, repo, RetentionPolicy{})
				if err != nil || r.Deleted != 0 {
					t.Fatal("uncertain material deleted", r, err)
				}
			} else if err != nil || lease.Token != "synthetic-new" || lease.Generation != 2 {
				t.Fatal(lease.Generation, err)
			}
		})
	}
}
