package oauth

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/ufaruq/toolbox/internal/tokens"
)

type initialRejectProvider struct {
	Provider
	err   error
	after func()
	calls int
}

func (p *initialRejectProvider) Exchange(context.Context, string, string, string) (ExchangeResult, error) {
	p.calls++
	if p.after != nil {
		p.after()
	}
	return ExchangeResult{}, p.err
}

func TestInitialInvalidGrantResolvesIntentAndAllowsDisconnectCleanup(t *testing.T) {
	for _, mode := range []string{"invalid grant", "wrapped rejection", "cancelled caller", "already disconnected", "committed write timeout"} {
		t.Run(mode, func(t *testing.T) {
			h := newHarness(t)
			start, state, code := h.begin(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var intent tokens.Bundle
			provider := &initialRejectProvider{Provider: h.provider, err: tokens.ErrInvalidGrant}
			if mode == "wrapped rejection" {
				provider.err = fmt.Errorf("authorization code rejected: %w", tokens.ErrInvalidGrant)
			}
			provider.after = func() {
				var err error
				intent, _, err = h.secrets.Get(context.Background(), tokens.Path(start.ConnectionID))
				if err != nil || intent.State != tokens.StateRefreshing {
					t.Fatal("exchange was not fenced before provider request", err)
				}
				if mode == "cancelled caller" {
					cancel()
				}
				if mode == "already disconnected" {
					disconnectPending(t, h, start.ConnectionID)
				}
			}
			h.service.provider = provider
			if mode == "committed write timeout" {
				h.service.secrets = &failResolvedExchangeStore{MemorySecretStore: h.secrets, commit: true}
			}
			connection, err := h.service.Complete(ctx, "owner", "session", state, code)
			if !errors.Is(err, tokens.ErrInvalidGrant) || connection.ID != "" {
				t.Fatal("definitive rejection was not returned", err)
			}
			bundle, version, err := h.secrets.Get(context.Background(), tokens.Path(start.ConnectionID))
			want := intent
			want.Generation, want.State = 1, tokens.StateCleanup
			if err != nil || version != 2 || !sameInitialBundle(bundle, want) {
				t.Fatal("definitive initial rejection left unresolved intent or changed its identity", err)
			}
			if h.connection(t, start.ConnectionID).Status == "active" {
				t.Fatal("rejected initial exchange activated connection")
			}
			if mode != "already disconnected" {
				disconnectPending(t, h, start.ConnectionID)
			}
			manager := &tokens.Manager{Repository: h.repo, Secrets: h.secrets, Provider: &recordExchangeRevocation{Provider: h.provider, revoke: func(string) error {
				t.Error("definitive empty rejection must not invent a credential to revoke")
				return nil
			}}}
			for attempt := 0; attempt < 2; attempt++ {
				if err := manager.Tombstone(context.Background(), start.ConnectionID, 2); err != nil {
					t.Fatal("known initial rejection prevented disconnect cleanup", err)
				}
			}
			bundle, _, err = h.secrets.Get(context.Background(), tokens.Path(start.ConnectionID))
			if err != nil || bundle.State != tokens.StateTombstoned || bundle.AccessToken != "" || bundle.RefreshToken != "" {
				t.Fatal("cleanup did not leave an empty tombstone", err)
			}
			if _, err := h.service.Complete(context.Background(), "owner", "session", state, code); !errors.Is(err, ErrCallback) || provider.calls != 1 {
				t.Fatal("rejected authorization code was replayed", err)
			}
		})
	}
}

func TestInitialUnknownExchangeOutcomeKeepsDisconnectFenced(t *testing.T) {
	for _, outcome := range []error{context.DeadlineExceeded, ErrProvider, errors.New("malformed exchange response")} {
		t.Run(outcome.Error(), func(t *testing.T) {
			h := newHarness(t)
			start, state, code := h.begin(t)
			provider := &initialRejectProvider{Provider: h.provider, err: outcome}
			h.service.provider = provider
			if _, err := h.service.Complete(context.Background(), "owner", "session", state, code); !errors.Is(err, outcome) {
				t.Fatal("unknown outcome was not returned", err)
			}
			bundle, version, err := h.secrets.Get(context.Background(), tokens.Path(start.ConnectionID))
			if err != nil || version != 1 || bundle.State != tokens.StateRefreshing || bundle.Generation != 0 {
				t.Fatal("unknown exchange result lost its intent fence", err)
			}
			disconnectPending(t, h, start.ConnectionID)
			manager := &tokens.Manager{Repository: h.repo, Secrets: h.secrets, Provider: h.provider}
			if err := manager.Tombstone(context.Background(), start.ConnectionID, 2); !errors.Is(err, tokens.ErrRefreshUncertain) {
				t.Fatal("unknown exchange outcome was declared cleaned", err)
			}
			if _, err := h.service.Complete(context.Background(), "owner", "session", state, code); !errors.Is(err, ErrCallback) || provider.calls != 1 {
				t.Fatal("uncertain exchange was replayed", err)
			}
		})
	}
}

func TestInitialInvalidGrantPersistenceFailureKeepsDisconnectFenced(t *testing.T) {
	h := newHarness(t)
	start, state, code := h.begin(t)
	h.service.provider = &initialRejectProvider{Provider: h.provider, err: tokens.ErrInvalidGrant}
	h.service.secrets = &failResolvedExchangeStore{MemorySecretStore: h.secrets}
	if _, err := h.service.Complete(context.Background(), "owner", "session", state, code); !errors.Is(err, ErrPersistence) {
		t.Fatal("unpersisted rejection did not report persistence failure", err)
	}
	bundle, version, err := h.secrets.Get(context.Background(), tokens.Path(start.ConnectionID))
	if err != nil || version != 1 || bundle.State != tokens.StateRefreshing {
		t.Fatal("failed rejection resolution lost original intent", err)
	}
	disconnectPending(t, h, start.ConnectionID)
	manager := &tokens.Manager{Repository: h.repo, Secrets: h.secrets, Provider: h.provider}
	if err := manager.Tombstone(context.Background(), start.ConnectionID, 2); !errors.Is(err, tokens.ErrRefreshUncertain) {
		t.Fatal("failed resolution allowed cleanup to complete", err)
	}
}

func TestInitialInvalidGrantCannotReplaceConcurrentGeneration(t *testing.T) {
	h := newHarness(t)
	start, state, code := h.begin(t)
	var winner tokens.Bundle
	var winnerVersion int64
	h.service.provider = &initialRejectProvider{Provider: h.provider, err: tokens.ErrInvalidGrant, after: func() {
		intent, version, err := h.secrets.Get(context.Background(), tokens.Path(start.ConnectionID))
		if err != nil {
			t.Fatal(err)
		}
		winner = intent
		winner.Subject, winner.RefreshToken = "concurrent-subject", "concurrent-credential"
		winner.State, winner.Generation, winner.OperationID = tokens.StateCleanup, 9, "concurrent-operation"
		winnerVersion, err = h.secrets.Put(context.Background(), tokens.Path(start.ConnectionID), winner, version)
		if err != nil {
			t.Fatal(err)
		}
	}}
	if _, err := h.service.Complete(context.Background(), "owner", "session", state, code); !errors.Is(err, ErrPersistence) {
		t.Fatal("concurrent generation was reconciled as this rejection", err)
	}
	bundle, version, err := h.secrets.Get(context.Background(), tokens.Path(start.ConnectionID))
	if err != nil || version != winnerVersion || !sameInitialBundle(bundle, winner) {
		t.Fatal("initial rejection overwrote another operation", err)
	}
}

type mismatchedInitialRejectStore struct {
	*tokens.MemorySecretStore
	mutate func(*tokens.Bundle)
}

func (s *mismatchedInitialRejectStore) Put(ctx context.Context, path string, bundle tokens.Bundle, cas int64) (int64, error) {
	if bundle.State == tokens.StateCleanup {
		s.mutate(&bundle)
		_, _ = s.MemorySecretStore.Put(ctx, path, bundle, cas)
		return 0, tokens.ErrUnavailable
	}
	return s.MemorySecretStore.Put(ctx, path, bundle, cas)
}

func TestInitialInvalidGrantReconciliationRequiresExactOperationAndIdentity(t *testing.T) {
	for _, field := range []string{"connection", "client", "subject", "epoch", "generation", "operation", "state", "credential"} {
		t.Run(field, func(t *testing.T) {
			h := newHarness(t)
			_, state, code := h.begin(t)
			h.service.provider = &initialRejectProvider{Provider: h.provider, err: tokens.ErrInvalidGrant}
			h.service.secrets = &mismatchedInitialRejectStore{MemorySecretStore: h.secrets, mutate: func(bundle *tokens.Bundle) {
				switch field {
				case "connection":
					bundle.ConnectionID = "another-connection"
				case "client":
					bundle.ClientID = "another-client"
				case "subject":
					bundle.Subject = "another-subject"
				case "epoch":
					bundle.Epoch++
				case "generation":
					bundle.Generation++
				case "operation":
					bundle.OperationID = "another-operation"
				case "state":
					bundle.State = tokens.StateRefreshing
				case "credential":
					bundle.RefreshToken = "another-credential"
				}
			}}
			if _, err := h.service.Complete(context.Background(), "owner", "session", state, code); !errors.Is(err, ErrPersistence) {
				t.Fatal("different response reconciled as rejected operation", err)
			}
		})
	}
}
