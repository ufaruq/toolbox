package oauth

import (
	"context"
	"errors"
	"testing"

	"github.com/ufaruq/toolbox/internal/domain"
	"github.com/ufaruq/toolbox/internal/tokens"
)

// Only the post-exchange acquisition fails. The database can be wholly lost
// while the independent credential store is still available for cleanup.
type failedExchangeLockRepo struct {
	domain.Repository
	locks int
	lost  bool
	wait  bool
}

func (r *failedExchangeLockRepo) LockConnection(ctx context.Context, id string) (func() error, error) {
	r.locks++
	if r.locks == 2 {
		r.lost = true
		if r.wait {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return nil, errors.New("database session unavailable")
	}
	return r.Repository.LockConnection(ctx, id)
}
func (r *failedExchangeLockRepo) Transact(ctx context.Context, fn func(*domain.State) error) error {
	if r.lost {
		return errors.New("database unavailable")
	}
	return r.Repository.Transact(ctx, fn)
}

type hookExchangeProvider struct {
	Provider
	result ExchangeResult
	after  func()
}

func (p *hookExchangeProvider) Exchange(context.Context, string, string, string) (ExchangeResult, error) {
	if p.after != nil {
		p.after()
	}
	return p.result, nil
}

func TestExchangeLockFailurePersistsCleanupWithoutDatabase(t *testing.T) {
	for _, mode := range []string{"lost database", "cancelled caller", "access only", "expired lock context", "committed write timeout"} {
		t.Run(mode, func(t *testing.T) {
			h := newHarness(t)
			start, state, code := h.begin(t)
			repo := &failedExchangeLockRepo{Repository: h.repo, wait: mode == "expired lock context"}
			h.service.repo = repo
			provider := &hookExchangeProvider{Provider: h.provider, result: validExchangeResult(h)}
			h.service.provider = provider
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "cancelled caller" {
				provider.after = cancel
			}
			if mode == "access only" {
				provider.result.RefreshToken = ""
			}
			if mode == "committed write timeout" {
				h.service.secrets = &failResolvedExchangeStore{MemorySecretStore: h.secrets, commit: true}
			}
			if _, err := h.service.Complete(ctx, "owner", "session", state, code); !errors.Is(err, ErrPersistence) {
				t.Fatal("lost database lock was not reported", err)
			}
			bundle, version, err := h.secrets.Get(context.Background(), tokens.Path(start.ConnectionID))
			if err != nil || version != 2 || bundle.State != tokens.StateCleanup || bundle.Generation != 1 || bundle.OperationID == "" || bundle.ConnectionID != start.ConnectionID || bundle.ClientID != h.provider.ClientID() || bundle.Subject != provider.result.Subject || bundle.Epoch != 1 || !bundle.Expiry.IsZero() {
				t.Fatal("known exchange response did not resolve its intent as cleanup-only", err)
			}
			wantToken := provider.result.RefreshToken
			if wantToken != "" {
				if bundle.AccessToken != "" || bundle.RefreshToken != wantToken {
					t.Fatal("refresh cleanup credential was lost or dispatchable")
				}
			} else {
				wantToken = provider.result.AccessToken
				if bundle.AccessToken != wantToken || bundle.RefreshToken != "" {
					t.Fatal("access-only cleanup credential was lost")
				}
			}
			if h.connection(t, start.ConnectionID).Status != "pending" {
				t.Fatal("failed lock activated the connection")
			}
			disconnectPending(t, h, start.ConnectionID)
			revocations := 0
			revoker := &recordExchangeRevocation{Provider: h.provider, revoke: func(token string) error {
				revocations++
				if token != wantToken {
					t.Error("cleanup revoked a different credential")
				}
				if revocations == 1 {
					return ErrProvider
				}
				return nil
			}}
			manager := &tokens.Manager{Repository: h.repo, Secrets: h.secrets, Provider: revoker}
			if err := manager.Tombstone(context.Background(), start.ConnectionID, 2); !errors.Is(err, tokens.ErrUnavailable) {
				t.Fatal("revocation failure was not retained for retry", err)
			}
			if err := manager.Tombstone(context.Background(), start.ConnectionID, 2); err != nil || revocations != 2 {
				t.Fatal("known response cleanup could not finish on retry", err)
			}
		})
	}
}

type recordExchangeRevocation struct {
	tokens.Provider
	revoke func(string) error
}

func (p *recordExchangeRevocation) Revoke(_ context.Context, token string) error {
	return p.revoke(token)
}

func TestExchangeLockFailureDoesNotOverwriteCompetingGeneration(t *testing.T) {
	h := newHarness(t)
	start, state, code := h.begin(t)
	h.service.repo = &failedExchangeLockRepo{Repository: h.repo}
	var winner tokens.Bundle
	var winnerVersion int64
	h.service.provider = &hookExchangeProvider{Provider: h.provider, result: validExchangeResult(h), after: func() {
		intent, version, err := h.secrets.Get(context.Background(), tokens.Path(start.ConnectionID))
		if err != nil {
			t.Fatal(err)
		}
		winner = intent
		winner.OperationID, winner.Generation, winner.State = "concurrent-operation", 7, tokens.StateCleanup
		winner.Subject, winner.RefreshToken = "other-subject", "other-generation"
		winnerVersion, err = h.secrets.Put(context.Background(), tokens.Path(start.ConnectionID), winner, version)
		if err != nil {
			t.Fatal(err)
		}
	}}
	if _, err := h.service.Complete(context.Background(), "owner", "session", state, code); !errors.Is(err, ErrPersistence) {
		t.Fatal("lock failure accepted", err)
	}
	observed, version, err := h.secrets.Get(context.Background(), tokens.Path(start.ConnectionID))
	if err != nil || version != winnerVersion || !sameInitialBundle(observed, winner) {
		t.Fatal("response overwrote a competing operation", err)
	}
}

func TestExchangeLockFailurePersistenceFailureKeepsIntentUnresolved(t *testing.T) {
	h := newHarness(t)
	start, state, code := h.begin(t)
	h.service.repo = &failedExchangeLockRepo{Repository: h.repo}
	h.service.secrets = &failResolvedExchangeStore{MemorySecretStore: h.secrets}
	if _, err := h.service.Complete(context.Background(), "owner", "session", state, code); !errors.Is(err, ErrPersistence) {
		t.Fatal("failed cleanup persistence accepted", err)
	}
	bundle, version, err := h.secrets.Get(context.Background(), tokens.Path(start.ConnectionID))
	if err != nil || version != 1 || bundle.State != tokens.StateRefreshing {
		t.Fatal("unpersisted response must remain fenced", err)
	}
	disconnectPending(t, h, start.ConnectionID)
	manager := &tokens.Manager{Repository: h.repo, Secrets: h.secrets, Provider: h.provider}
	if err := manager.Tombstone(context.Background(), start.ConnectionID, 2); !errors.Is(err, tokens.ErrRefreshUncertain) {
		t.Fatal("unresolved cleanup was reported complete", err)
	}
}
