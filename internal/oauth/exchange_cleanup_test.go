package oauth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ufaruq/toolbox/internal/domain"
	"github.com/ufaruq/toolbox/internal/tokens"
)

func disconnectPending(t *testing.T, h *harness, id string) {
	t.Helper()
	if err := h.repo.Transact(context.Background(), func(st *domain.State) error {
		c := st.Connections[id]
		c.Status, c.Epoch = "disconnecting", c.Epoch+1
		st.Connections[id] = c
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestExchangeDisconnectKeepsCleanupPendingUntilLateResponse(t *testing.T) {
	h := newHarness(t)
	start, state, code := h.begin(t)
	paused := &pausedProvider{Provider: h.provider, entered: make(chan struct{}), release: make(chan struct{})}
	h.service.provider = paused
	done := make(chan error, 1)
	go func() {
		_, err := h.service.Complete(context.Background(), "owner", "session", state, code)
		done <- err
	}()
	<-paused.entered
	disconnectPending(t, h, start.ConnectionID)
	manager := &tokens.Manager{Repository: h.repo, Secrets: h.secrets, Provider: h.provider}
	cleanupErr := manager.Tombstone(context.Background(), start.ConnectionID, 2)
	close(paused.release)
	if err := <-done; !errors.Is(err, domain.ErrDenied) {
		t.Fatal("disconnected exchange activated", err)
	}
	if !errors.Is(cleanupErr, tokens.ErrRefreshUncertain) {
		t.Fatal("cleanup completed while exchange could still issue credentials", cleanupErr)
	}
	bundle, _, err := h.secrets.Get(context.Background(), tokens.Path(start.ConnectionID))
	if err != nil || bundle.State != tokens.StateCleanup || bundle.RefreshToken == "" || bundle.AccessToken != "" || bundle.Epoch != 1 || bundle.OperationID == "" {
		t.Fatal("late credential was not retained exclusively for cleanup", err)
	}
	if err := manager.Tombstone(context.Background(), start.ConnectionID, 2); err != nil {
		t.Fatal("late credential cleanup failed", err)
	}
	h.provider.mu.Lock()
	outstanding := len(h.provider.refresh)
	h.provider.mu.Unlock()
	if outstanding != 0 || h.connection(t, start.ConnectionID).Status != "disconnecting" {
		t.Fatal("late exchange was not revoked, or connection reactivated")
	}
}

type returningExchangeProvider struct {
	Provider
	entered, release chan struct{}
	result           ExchangeResult
	err              error
}

func (p *returningExchangeProvider) Exchange(context.Context, string, string, string) (ExchangeResult, error) {
	if p.entered != nil {
		close(p.entered)
		<-p.release
	}
	return p.result, p.err
}

func validExchangeResult(h *harness) ExchangeResult {
	return ExchangeResult{Subject: "google-account-123", ClientID: h.provider.ClientID(), AccessToken: "known-access", RefreshToken: "known-refresh", Expiry: h.now.Add(time.Hour), Scopes: []string{"openid", domain.DriveScope}}
}

func TestExchangeKnownCredentialsSurviveCancelledOrLostSession(t *testing.T) {
	for _, cancelCaller := range []bool{true, false} {
		t.Run(map[bool]string{true: "caller cancelled", false: "owner session lost"}[cancelCaller], func(t *testing.T) {
			h := newHarness(t)
			start, state, code := h.begin(t)
			provider := &returningExchangeProvider{Provider: h.provider, entered: make(chan struct{}), release: make(chan struct{}), result: validExchangeResult(h)}
			h.service.provider = provider
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { _, err := h.service.Complete(ctx, "owner", "session", state, code); done <- err }()
			<-provider.entered
			if cancelCaller {
				cancel()
			} else if err := h.repo.Transact(context.Background(), func(st *domain.State) error {
				session := st.Sessions["session"]
				session.ExpiresAt = st.Now
				st.Sessions["session"] = session
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			close(provider.release)
			if err := <-done; err == nil {
				t.Fatal("invalid caller activated connection")
			}
			bundle, _, err := h.secrets.Get(context.Background(), tokens.Path(start.ConnectionID))
			if err != nil || bundle.State != tokens.StateCleanup || bundle.RefreshToken != "known-refresh" || bundle.AccessToken != "" || h.connection(t, start.ConnectionID).Status == "active" {
				t.Fatal("known credential was lost or remained usable", err)
			}
		})
	}
}

func TestExchangeRejectedResultRetainsCredentialsForCleanup(t *testing.T) {
	for _, failure := range []string{"scope", "identity", "provider error", "missing refresh"} {
		t.Run(failure, func(t *testing.T) {
			h := newHarness(t)
			start, state, code := h.begin(t)
			provider := &returningExchangeProvider{Provider: h.provider, result: validExchangeResult(h)}
			wantErr := ErrScope
			switch failure {
			case "scope":
				provider.result.Scopes = []string{"openid"}
			case "identity":
				provider.result.Subject, wantErr = "", ErrIdentity
			case "provider error":
				provider.err, wantErr = ErrProvider, ErrProvider
			case "missing refresh":
				provider.result.RefreshToken, wantErr = "", ErrReauth
			}
			h.service.provider = provider
			if _, err := h.service.Complete(context.Background(), "owner", "session", state, code); !errors.Is(err, wantErr) {
				t.Fatal("unexpected rejection", err)
			}
			bundle, _, err := h.secrets.Get(context.Background(), tokens.Path(start.ConnectionID))
			if err != nil || bundle.State != tokens.StateCleanup || bundle.RefreshToken != provider.result.RefreshToken || bundle.OperationID == "" || h.connection(t, start.ConnectionID).Status == "active" {
				t.Fatal("rejected credential lost or usable", err)
			}
			if failure == "missing refresh" && bundle.AccessToken != "known-access" {
				t.Fatal("access-only credential must remain available for revocation")
			}
		})
	}
}

type failResolvedExchangeStore struct {
	*tokens.MemorySecretStore
	commit bool
}

func (s *failResolvedExchangeStore) Put(ctx context.Context, path string, b tokens.Bundle, cas int64) (int64, error) {
	if b.State == tokens.StateRefreshing {
		return s.MemorySecretStore.Put(ctx, path, b, cas)
	}
	if s.commit {
		_, _ = s.MemorySecretStore.Put(ctx, path, b, cas)
	}
	return 0, tokens.ErrUnavailable
}

func TestExchangeResponsePersistenceFailureLeavesDurableFence(t *testing.T) {
	h := newHarness(t)
	start, state, code := h.begin(t)
	h.service.secrets = &failResolvedExchangeStore{MemorySecretStore: h.secrets}
	if _, err := h.service.Complete(context.Background(), "owner", "session", state, code); !errors.Is(err, ErrPersistence) {
		t.Fatal("failed persistence accepted", err)
	}
	disconnectPending(t, h, start.ConnectionID)
	manager := &tokens.Manager{Repository: h.repo, Secrets: h.secrets, Provider: h.provider}
	if err := manager.Tombstone(context.Background(), start.ConnectionID, 2); !errors.Is(err, tokens.ErrRefreshUncertain) {
		t.Fatal("uncertain credential issuance reported cleaned", err)
	}
}

func TestExchangeCleanupReconcilesCommittedResponseAndRetriesRevocation(t *testing.T) {
	h := newHarness(t)
	start, state, code := h.begin(t)
	h.service.secrets = &failResolvedExchangeStore{MemorySecretStore: h.secrets, commit: true}
	paused := &pausedProvider{Provider: h.provider, entered: make(chan struct{}), release: make(chan struct{})}
	h.service.provider = paused
	done := make(chan error, 1)
	go func() {
		_, err := h.service.Complete(context.Background(), "owner", "session", state, code)
		done <- err
	}()
	<-paused.entered
	disconnectPending(t, h, start.ConnectionID)
	close(paused.release)
	if err := <-done; !errors.Is(err, domain.ErrDenied) {
		t.Fatal("committed cleanup outcome was not reconciled", err)
	}
	provider := &retryExchangeRevocation{Provider: h.provider, fail: true}
	manager := &tokens.Manager{Repository: h.repo, Secrets: h.secrets, Provider: provider}
	if err := manager.Tombstone(context.Background(), start.ConnectionID, 2); err == nil {
		t.Fatal("provider revoke failure ignored")
	}
	bundle, _, err := h.secrets.Get(context.Background(), tokens.Path(start.ConnectionID))
	if err != nil || bundle.State != tokens.StateTombstoned || bundle.RefreshToken == "" {
		t.Fatal("failed revoke discarded credential", err)
	}
	provider.fail = false
	if err := manager.Tombstone(context.Background(), start.ConnectionID, 2); err != nil {
		t.Fatal("revoke retry failed", err)
	}
	h.provider.mu.Lock()
	outstanding := len(h.provider.refresh)
	h.provider.mu.Unlock()
	if outstanding != 0 || provider.calls != 2 {
		t.Fatal("retry did not revoke original exchange credential")
	}
}

type retryExchangeRevocation struct {
	tokens.Provider
	fail  bool
	calls int
}

func (p *retryExchangeRevocation) Revoke(ctx context.Context, token string) error {
	p.calls++
	if p.fail {
		return ErrProvider
	}
	return p.Provider.Revoke(ctx, token)
}

func TestExchangeDoesNotDispatchWithoutDurableFence(t *testing.T) {
	h := newHarness(t)
	_, state, code := h.begin(t)
	h.service.secrets = &failingStore{MemorySecretStore: h.secrets}
	if _, err := h.service.Complete(context.Background(), "owner", "session", state, code); !errors.Is(err, ErrPersistence) {
		t.Fatal("missing intent accepted", err)
	}
	if h.provider.ExchangeCalls() != 0 {
		t.Fatal("provider exchange dispatched without durable intent")
	}
}

type replaceExchangeIntentStore struct {
	*tokens.MemorySecretStore
	mutate func(*tokens.Bundle)
}

func (s *replaceExchangeIntentStore) Put(ctx context.Context, path string, b tokens.Bundle, cas int64) (int64, error) {
	if b.State == tokens.StateRefreshing {
		s.mutate(&b)
		_, _ = s.MemorySecretStore.Put(ctx, path, b, cas)
		return 0, tokens.ErrUnavailable
	}
	return s.MemorySecretStore.Put(ctx, path, b, cas)
}

func TestExchangeIntentReconciliationRequiresExactIdentityAndOperation(t *testing.T) {
	for _, field := range []string{"connection", "client", "epoch", "operation"} {
		t.Run(field, func(t *testing.T) {
			h := newHarness(t)
			_, state, code := h.begin(t)
			h.service.secrets = &replaceExchangeIntentStore{MemorySecretStore: h.secrets, mutate: func(b *tokens.Bundle) {
				switch field {
				case "connection":
					b.ConnectionID = "other-connection"
				case "client":
					b.ClientID = "other-client"
				case "epoch":
					b.Epoch++
				case "operation":
					b.OperationID = "other-operation"
				}
			}}
			if _, err := h.service.Complete(context.Background(), "owner", "session", state, code); !errors.Is(err, ErrPersistence) {
				t.Fatal("different intent accepted as durable success", err)
			}
			if h.provider.ExchangeCalls() != 0 {
				t.Fatal("provider exchange dispatched for another intent")
			}
		})
	}
}
