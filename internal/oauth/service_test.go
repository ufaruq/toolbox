package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ufaruq/toolbox/internal/domain"
	"github.com/ufaruq/toolbox/internal/security"
	"github.com/ufaruq/toolbox/internal/store"
	"github.com/ufaruq/toolbox/internal/tokens"
)

type harness struct {
	service  *Service
	repo     *store.Memory
	secrets  *tokens.MemorySecretStore
	provider *FixtureProvider
	now      time.Time
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{now: time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC), secrets: tokens.NewMemorySecretStore()}
	h.repo = store.NewMemoryWithClock(func() time.Time { return h.now })
	err := h.repo.Transact(context.Background(), func(st *domain.State) error {
		for _, id := range []string{"owner", "other"} {
			st.Users[id] = domain.User{ID: id, Issuer: "fixture", Subject: id, Status: "active"}
		}
		for _, session := range []struct{ id, owner string }{{"session", "owner"}, {"session-2", "owner"}, {"other-session", "other"}} {
			st.Sessions[session.id] = domain.Session{ID: session.id, UserID: session.owner, CSRFHash: security.Hash(session.id), ExpiresAt: h.now.Add(time.Hour)}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	h.provider, err = NewFixtureProvider("fixture-client", "http://127.0.0.1:8080/oauth/callback")
	if err != nil {
		t.Fatal(err)
	}
	h.provider.now = func() time.Time { return h.now }
	h.service, err = NewService(h.repo, h.secrets, h.provider)
	if err != nil {
		t.Fatal(err)
	}
	return h
}
func (h *harness) begin(t *testing.T) (StartResult, string, string) {
	t.Helper()
	result, err := h.service.Start(context.Background(), "owner", "session")
	if err != nil {
		t.Fatal(err)
	}
	callback, err := h.provider.Authorize(context.Background(), result.AuthorizationURL, "google-account-123")
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := url.Parse(callback)
	return result, parsed.Query().Get("state"), parsed.Query().Get("code")
}
func (h *harness) connection(t *testing.T, id string) domain.Connection {
	t.Helper()
	var result domain.Connection
	if err := h.repo.Transact(context.Background(), func(st *domain.State) error { result = st.Connections[id]; return nil }); err != nil {
		t.Fatal(err)
	}
	return result
}
func TestCompleteDurableAndReplay(t *testing.T) {
	h := newHarness(t)
	start, state, code := h.begin(t)
	parsed, _ := url.Parse(start.AuthorizationURL)
	verifierPath := transactionPath(strings.Split(state, ".")[0])
	var secret transactionSecret
	if _, err := h.secrets.GetJSON(context.Background(), verifierPath, &secret); err != nil {
		t.Fatal(err)
	}
	if challengeFor(secret.Verifier) != parsed.Query().Get("code_challenge") {
		t.Fatal("PKCE not bound")
	}
	if err := h.repo.Transact(context.Background(), func(st *domain.State) error {
		tx := st.OAuth[strings.Split(state, ".")[0]]
		if tx.Consumed || tx.StateHash != security.Hash(state) || tx.NonceHash != security.Hash(parsed.Query().Get("nonce")) || !tx.ExpiresAt.Equal(h.now.Add(10*time.Minute)) {
			t.Fatal("wrong transaction binding")
		}
		raw, _ := json.Marshal(st)
		for _, s := range []string{state, secret.Verifier, code, parsed.Query().Get("nonce")} {
			if strings.Contains(string(raw), s) {
				t.Fatal("secret persisted in relational state")
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	connection, err := h.service.Complete(context.Background(), "owner", "session", state, code)
	if err != nil {
		t.Fatal(err)
	}
	if connection.Status != "active" || connection.Subject != "google-account-123" || connection.SecretVersion != 1 {
		t.Fatalf("unexpected connection: %+v", connection)
	}
	bundle, version, err := h.secrets.Get(context.Background(), tokens.Path(connection.ID))
	if err != nil || version != 1 || bundle.OperationID == "" || bundle.Generation != 1 || bundle.State != "active" || bundle.RefreshToken == "" || bundle.Subject != connection.Subject {
		t.Fatal("missing durable bundle", err)
	}
	if _, err := h.secrets.GetJSON(context.Background(), verifierPath, &secret); !errors.Is(err, tokens.ErrNotFound) {
		t.Fatal("verifier not deleted")
	}
	if _, err := h.service.Complete(context.Background(), "owner", "session", state, code); !errors.Is(err, ErrCallback) {
		t.Fatal("replay accepted", err)
	}
	if h.provider.ExchangeCalls() != 1 {
		t.Fatal("replay dispatched provider exchange")
	}
}
func TestBadBindingsDoNotConsumeOrExchange(t *testing.T) {
	cases := []struct {
		name, owner, session string
		mutate               func(string) string
	}{
		{"wrong session", "owner", "session-2", func(s string) string { return s }},
		{"wrong owner", "other", "other-session", func(s string) string { return s }},
		{"wrong state", "owner", "session", func(s string) string { return strings.Split(s, ".")[0] + "." + security.Random() }},
		{"malformed state", "owner", "session", func(string) string { return "../../hostile" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			_, state, code := h.begin(t)
			if _, err := h.service.Complete(context.Background(), tc.owner, tc.session, tc.mutate(state), code); !errors.Is(err, ErrCallback) {
				t.Fatal("bad binding accepted", err)
			}
			if h.provider.ExchangeCalls() != 0 {
				t.Fatal("unauthorized provider exchange")
			}
			if _, err := h.service.Complete(context.Background(), "owner", "session", state, code); err != nil {
				t.Fatal("bad binding consumed legitimate transaction", err)
			}
		})
	}
}
func TestNonceFailureConsumesBeforeExchange(t *testing.T) {
	h := newHarness(t)
	start, state, code := h.begin(t)
	record := h.provider.codes[code]
	record.nonce = security.Random()
	h.provider.codes[code] = record
	if _, err := h.service.Complete(context.Background(), "owner", "session", state, code); !errors.Is(err, ErrIdentity) {
		t.Fatal("wrong nonce accepted", err)
	}
	if h.connection(t, start.ConnectionID).Status != "pending" {
		t.Fatal("unverified identity activated")
	}
	if _, err := h.service.Complete(context.Background(), "owner", "session", state, code); !errors.Is(err, ErrCallback) {
		t.Fatal("failed exchange replay accepted", err)
	}
	if h.provider.ExchangeCalls() != 1 {
		t.Fatal("unexpected exchange calls")
	}
}
func TestExpiredTransactionFailsAtBoundary(t *testing.T) {
	h := newHarness(t)
	_, state, code := h.begin(t)
	h.now = h.now.Add(TransactionLifetime)
	if _, err := h.service.Complete(context.Background(), "owner", "session", state, code); !errors.Is(err, ErrCallback) {
		t.Fatal("expired callback accepted", err)
	}
	if h.provider.ExchangeCalls() != 0 {
		t.Fatal("expired transaction dispatched")
	}
}
func TestMissingRefreshTokenNeverActive(t *testing.T) {
	h := newHarness(t)
	start, state, code := h.begin(t)
	record := h.provider.codes[code]
	record.noRefresh = true
	h.provider.codes[code] = record
	connection, err := h.service.Complete(context.Background(), "owner", "session", state, code)
	if !errors.Is(err, ErrReauth) || connection.Status != "needs_reauth" || h.connection(t, start.ConnectionID).Status != "needs_reauth" {
		t.Fatal("missing refresh token activated", err)
	}
	if _, _, err := h.secrets.Get(context.Background(), tokens.Path(start.ConnectionID)); !errors.Is(err, tokens.ErrNotFound) {
		t.Fatal("incomplete bundle stored")
	}
}
func TestScopeMismatchNeverActive(t *testing.T) {
	h := newHarness(t)
	start, state, code := h.begin(t)
	record := h.provider.codes[code]
	record.scopes = []string{"openid", "https://www.googleapis.com/auth/drive.readonly"}
	h.provider.codes[code] = record
	if _, err := h.service.Complete(context.Background(), "owner", "session", state, code); !errors.Is(err, ErrScope) {
		t.Fatal("scope escalation accepted", err)
	}
	if h.connection(t, start.ConnectionID).Status != "pending" {
		t.Fatal("scope mismatch active")
	}
}

type failingStore struct {
	*tokens.MemorySecretStore
	commit bool
}

func (s *failingStore) Put(ctx context.Context, path string, b tokens.Bundle, cas int64) (int64, error) {
	if s.commit {
		_, _ = s.MemorySecretStore.Put(ctx, path, b, cas)
	}
	return 0, tokens.ErrUnavailable
}
func TestInitialPersistenceFailureAndUncertainCommit(t *testing.T) {
	for _, commit := range []bool{false, true} {
		t.Run(map[bool]string{false: "not committed", true: "committed response lost"}[commit], func(t *testing.T) {
			h := newHarness(t)
			h.service.secrets = &failingStore{MemorySecretStore: h.secrets, commit: commit}
			start, state, code := h.begin(t)
			connection, err := h.service.Complete(context.Background(), "owner", "session", state, code)
			if commit {
				if err != nil || connection.Status != "active" {
					t.Fatal("did not reconcile known durable outcome", err)
				}
			} else {
				if !errors.Is(err, ErrPersistence) || h.connection(t, start.ConnectionID).Status != "pending" {
					t.Fatal("activated before durability", err)
				}
			}
		})
	}
}
func TestReconnectAllocatesNewConnection(t *testing.T) {
	h := newHarness(t)
	start, state, code := h.begin(t)
	if _, err := h.service.Complete(context.Background(), "owner", "session", state, code); err != nil {
		t.Fatal(err)
	}
	if err := h.repo.Transact(context.Background(), func(st *domain.State) error {
		c := st.Connections[start.ConnectionID]
		c.Status = "disconnected"
		c.Epoch++
		st.Connections[c.ID] = c
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	second, state, code := h.begin(t)
	if second.ConnectionID == start.ConnectionID {
		t.Fatal("reconnect reused identity")
	}
	if _, err := h.service.Complete(context.Background(), "owner", "session", state, code); err != nil {
		t.Fatal(err)
	}
	if h.connection(t, start.ConnectionID).Status != "disconnected" {
		t.Fatal("reconnect revived old identity")
	}
}
func TestConcurrentCallbackExchangesOnce(t *testing.T) {
	h := newHarness(t)
	_, state, code := h.begin(t)
	var wg sync.WaitGroup
	errorsSeen := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := h.service.Complete(context.Background(), "owner", "session", state, code)
			errorsSeen <- err
		}()
	}
	wg.Wait()
	close(errorsSeen)
	successes := 0
	for err := range errorsSeen {
		if err == nil {
			successes++
		} else if !errors.Is(err, ErrCallback) {
			t.Fatal(err)
		}
	}
	if successes != 1 || h.provider.ExchangeCalls() != 1 {
		t.Fatal("callback race dispatched more than once")
	}
}
func TestStartRejectsUntrustedOrExpiredOwnerSession(t *testing.T) {
	h := newHarness(t)
	if _, err := h.service.Start(context.Background(), "owner", "other-session"); !errors.Is(err, domain.ErrDenied) {
		t.Fatal("cross-owner session accepted")
	}
	h.now = h.now.Add(time.Hour)
	if _, err := h.service.Start(context.Background(), "owner", "session"); !errors.Is(err, domain.ErrDenied) {
		t.Fatal("expired session accepted")
	}
}
func TestFixturePKCEMissingAndMismatch(t *testing.T) {
	for _, verifier := range []string{"", security.Random()} {
		h := newHarness(t)
		start, _, code := h.begin(t)
		parsed, _ := url.Parse(start.AuthorizationURL)
		if _, err := h.provider.Exchange(context.Background(), code, verifier, security.Hash(parsed.Query().Get("nonce"))); !errors.Is(err, ErrIdentity) {
			t.Fatal("fixture PKCE negative failed", err)
		}
	}
}

type lostLockRepository struct{ domain.Repository }

func (r lostLockRepository) LockConnection(ctx context.Context, id string) (func() error, error) {
	unlock, err := r.Repository.LockConnection(ctx, id)
	if err != nil {
		return nil, err
	}
	return func() error { _ = unlock(); return errors.New("lock session lost") }, nil
}
func TestLostConnectionLockNeverReturnsSuccess(t *testing.T) {
	h := newHarness(t)
	h.service.repo = lostLockRepository{h.repo}
	_, state, code := h.begin(t)
	connection, err := h.service.Complete(context.Background(), "owner", "session", state, code)
	if !errors.Is(err, ErrPersistence) || connection.ID != "" {
		t.Fatal("lost lock returned success", err)
	}
	if h.provider.ExchangeCalls() != 1 {
		t.Fatal("exchange count changed")
	}
	if _, err = h.service.Complete(context.Background(), "owner", "session", state, code); !errors.Is(err, ErrCallback) {
		t.Fatal("lost lock made code replayable", err)
	}
}

type pausedProvider struct {
	Provider
	entered, release chan struct{}
}

func (p *pausedProvider) Exchange(ctx context.Context, code, verifier, nonceHash string) (ExchangeResult, error) {
	close(p.entered)
	select {
	case <-p.release:
	case <-ctx.Done():
		return ExchangeResult{}, ctx.Err()
	}
	return p.Provider.Exchange(ctx, code, verifier, nonceHash)
}
func TestCallbackAlreadyConsumedWhileExchangeInFlight(t *testing.T) {
	h := newHarness(t)
	_, state, code := h.begin(t)
	paused := &pausedProvider{Provider: h.provider, entered: make(chan struct{}), release: make(chan struct{})}
	h.service.provider = paused
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	finished := make(chan error, 1)
	go func() { _, err := h.service.Complete(ctx, "owner", "session", state, code); finished <- err }()
	select {
	case <-paused.entered:
	case <-ctx.Done():
		t.Fatal("exchange not entered")
	}
	_, err := h.service.Complete(ctx, "owner", "session", state, code)
	close(paused.release)
	if !errors.Is(err, ErrCallback) {
		t.Fatal("in-flight transaction was not atomically consumed", err)
	}
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	if h.provider.ExchangeCalls() != 1 {
		t.Fatal("multiple code exchanges")
	}
}
func TestCrossTransactionCodeSubstitutionFails(t *testing.T) {
	h := newHarness(t)
	first, state, _ := h.begin(t)
	_, _, secondCode := h.begin(t)
	if _, err := h.service.Complete(context.Background(), "owner", "session", state, secondCode); !errors.Is(err, ErrIdentity) {
		t.Fatal("substituted account/code accepted", err)
	}
	if h.connection(t, first.ConnectionID).Status != "pending" {
		t.Fatal("substituted code activated connection")
	}
}

type failActivationRepository struct{ domain.Repository }

func (r failActivationRepository) Transact(ctx context.Context, fn func(*domain.State) error) error {
	return r.Repository.Transact(ctx, func(st *domain.State) error {
		if err := fn(st); err != nil {
			return err
		}
		for _, connection := range st.Connections {
			if connection.Status == "active" {
				return errors.New("injected DB activation failure")
			}
		}
		return nil
	})
}
func TestDBActivationFailureLeavesDurableBlockedOrphan(t *testing.T) {
	h := newHarness(t)
	h.service.repo = failActivationRepository{h.repo}
	start, state, code := h.begin(t)
	if _, err := h.service.Complete(context.Background(), "owner", "session", state, code); err == nil {
		t.Fatal("activation failure ignored")
	}
	if h.connection(t, start.ConnectionID).Status != "pending" {
		t.Fatal("failed DB activation committed")
	}
	bundle, version, err := h.secrets.Get(context.Background(), tokens.Path(start.ConnectionID))
	if err != nil || version != 1 || bundle.RefreshToken == "" {
		t.Fatal("durable outcome lost", err)
	}
	if _, err := h.service.Complete(context.Background(), "owner", "session", state, code); !errors.Is(err, ErrCallback) {
		t.Fatal("DB failure reopened transaction", err)
	}
	if h.provider.ExchangeCalls() != 1 {
		t.Fatal("DB failure repeated provider exchange")
	}
}
