package tokens

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ufaruq/toolbox/internal/domain"
)

type testRepo struct {
	mu          sync.Mutex
	state       *domain.State
	lockMu      sync.Mutex
	locks       map[string]chan struct{}
	unlockError bool
	failRepair  atomic.Bool
	failReauth  atomic.Bool
}

func (r *testRepo) Transact(ctx context.Context, fn func(*domain.State) error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	old := r.state.Connections["c"]
	if e := fn(r.state); e != nil {
		return e
	}
	current := r.state.Connections["c"]
	if (r.failRepair.Load() && current.SecretVersion != old.SecretVersion) || (r.failReauth.Load() && current.Status == "needs_reauth") {
		r.state.Connections["c"] = old
		return ErrUnavailable
	}
	return nil
}
func (r *testRepo) LockConnection(ctx context.Context, id string) (func() error, error) {
	r.lockMu.Lock()
	ch := r.locks[id]
	if ch == nil {
		ch = make(chan struct{}, 1)
		r.locks[id] = ch
	}
	r.lockMu.Unlock()
	select {
	case ch <- struct{}{}:
		return func() error {
			<-ch
			if r.unlockError {
				return ErrUnavailable
			}
			return nil
		}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (r *testRepo) Ping(context.Context) error { return nil }
func (r *testRepo) connection() domain.Connection {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.state.Connections["c"]
}

type testProvider struct {
	calls   atomic.Int32
	refresh func(context.Context, string) (RefreshResult, error)
	revoke  func(context.Context, string) error
}

func (p *testProvider) Refresh(ctx context.Context, s string) (RefreshResult, error) {
	p.calls.Add(1)
	return p.refresh(ctx, s)
}
func (p *testProvider) Revoke(ctx context.Context, s string) error {
	if p.revoke != nil {
		return p.revoke(ctx, s)
	}
	return nil
}

type spyStore struct {
	*MemorySecretStore
	gets atomic.Int32
	put  func(context.Context, string, Bundle, int64) (int64, error)
}

func (s *spyStore) Get(ctx context.Context, p string) (Bundle, int64, error) {
	s.gets.Add(1)
	return s.MemorySecretStore.Get(ctx, p)
}
func (s *spyStore) Put(ctx context.Context, p string, b Bundle, v int64) (int64, error) {
	if s.put != nil {
		return s.put(ctx, p, b, v)
	}
	return s.MemorySecretStore.Put(ctx, p, b, v)
}
func fixture(t *testing.T) (*Manager, *testRepo, *spyStore, *testProvider) {
	t.Helper()
	now := time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)
	repo := &testRepo{state: domain.NewState(), locks: map[string]chan struct{}{}}
	repo.state.Connections["c"] = domain.Connection{ID: "c", OwnerID: "owner", Provider: "google_drive", Subject: "subject", ClientID: "client", Status: "active", Epoch: 1, SecretVersion: 1, Scopes: []string{domain.DriveScope}}
	store := &spyStore{MemorySecretStore: NewMemorySecretStore()}
	_, e := store.Put(context.Background(), Path("c"), Bundle{ConnectionID: "c", Subject: "subject", ClientID: "client", Epoch: 1, Generation: 1, OperationID: "initial", AccessToken: "CANARY-OLD-ACCESS", RefreshToken: "CANARY-OLD-REFRESH", Expiry: now.Add(-time.Minute), Scopes: []string{domain.DriveScope}, State: StateActive}, 0)
	if e != nil {
		t.Fatal(e)
	}
	provider := &testProvider{refresh: func(context.Context, string) (RefreshResult, error) {
		return RefreshResult{AccessToken: "CANARY-NEW-ACCESS", Expiry: now.Add(time.Hour)}, nil
	}}
	return &Manager{Repository: repo, Secrets: store, Provider: provider, Now: func() time.Time { return now }}, repo, store, provider
}
func allow(context.Context) error { return nil }
func TestRefreshCoordinatedAcrossManagers(t *testing.T) {
	m, r, s, p := fixture(t)
	second := &Manager{Repository: r, Secrets: s, Provider: p, Now: m.Now}
	var wg sync.WaitGroup
	errs := make(chan error, 40)
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			manager := m
			if i%2 == 1 {
				manager = second
			}
			token, e := manager.Access(context.Background(), "c", allow)
			if e != nil {
				errs <- e
			} else if token != "CANARY-NEW-ACCESS" {
				errs <- errors.New("wrong token")
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
	if p.calls.Load() != 1 {
		t.Fatalf("refreshes=%d", p.calls.Load())
	}
	b, v, e := s.Get(context.Background(), Path("c"))
	if e != nil || b.RefreshToken != "CANARY-OLD-REFRESH" || b.Generation != 2 || v != 3 || b.State != StateActive || r.connection().SecretVersion != v {
		t.Fatal("generation, preserved rotation or advisory metadata incorrect")
	}
}
func TestRotationStoredAndWrongIdentityDenied(t *testing.T) {
	m, r, s, p := fixture(t)
	p.refresh = func(context.Context, string) (RefreshResult, error) {
		return RefreshResult{AccessToken: "access2", RefreshToken: "refresh2", Expiry: m.now().Add(time.Hour)}, nil
	}
	if _, e := m.Access(context.Background(), "c", allow); e != nil {
		t.Fatal(e)
	}
	b, v, _ := s.Get(context.Background(), Path("c"))
	if b.RefreshToken != "refresh2" {
		t.Fatal("rotation discarded")
	}
	b.Subject = "other-owner"
	_, _ = s.Put(context.Background(), Path("c"), b, v)
	token, e := m.Access(context.Background(), "c", allow)
	if e != ErrReauth || token != "" || r.connection().Status != "needs_reauth" {
		t.Fatal("cross-account bundle accepted")
	}
}
func TestDeniedBeforeSecretAccess(t *testing.T) {
	m, _, s, p := fixture(t)
	_, e := m.Access(context.Background(), "c", func(context.Context) error { return domain.ErrDenied })
	if e != domain.ErrDenied || s.gets.Load() != 0 || p.calls.Load() != 0 {
		t.Fatal("denial crossed secret boundary")
	}
}
func TestRevokedWhileRefreshKeepsRotationButDeniesCaller(t *testing.T) {
	m, r, s, p := fixture(t)
	var revoked atomic.Bool
	p.refresh = func(context.Context, string) (RefreshResult, error) {
		revoked.Store(true)
		return RefreshResult{AccessToken: "new", RefreshToken: "rotated", Expiry: m.now().Add(time.Hour)}, nil
	}
	auth := func(context.Context) error {
		if revoked.Load() {
			return domain.ErrDenied
		}
		return nil
	}
	token, e := m.Access(context.Background(), "c", auth)
	if token != "" || e != domain.ErrDenied {
		t.Fatal("revoked caller received token")
	}
	b, _, _ := s.Get(context.Background(), Path("c"))
	if b.RefreshToken != "rotated" || b.State != StateActive || r.connection().Status != "active" {
		t.Fatal("rotation lost for other grants")
	}
}
func TestQueuedCallerRechecksAfterLock(t *testing.T) {
	m, r, s, p := fixture(t)
	started := make(chan struct{})
	finish := make(chan struct{})
	p.refresh = func(context.Context, string) (RefreshResult, error) {
		close(started)
		<-finish
		return RefreshResult{AccessToken: "new", Expiry: m.now().Add(time.Hour)}, nil
	}
	done := make(chan error, 1)
	go func() { _, e := m.Access(context.Background(), "c", allow); done <- e }()
	<-started
	var denied atomic.Bool
	authCalled := make(chan struct{})
	var once sync.Once
	auth := func(context.Context) error {
		once.Do(func() { close(authCalled) })
		if denied.Load() {
			return domain.ErrDenied
		}
		return nil
	}
	second := &Manager{Repository: r, Secrets: s, Provider: p, Now: m.Now}
	secondDone := make(chan error, 1)
	go func() { _, e := second.Access(context.Background(), "c", auth); secondDone <- e }()
	<-authCalled
	denied.Store(true)
	close(finish)
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	if e := <-secondDone; e != domain.ErrDenied {
		t.Fatal("queued revoked caller not denied")
	}
	if s.gets.Load() != 1 {
		t.Fatal("queued denied caller read secrets")
	}
}
func TestWriteTimeoutReconcilesOperation(t *testing.T) {
	m, _, s, _ := fixture(t)
	s.put = func(ctx context.Context, p string, b Bundle, v int64) (int64, error) {
		version, e := s.MemorySecretStore.Put(ctx, p, b, v)
		if e == nil && b.State == StateActive && b.Generation == 2 {
			return 0, ErrUnavailable
		}
		return version, e
	}
	token, e := m.Access(context.Background(), "c", allow)
	if e != nil || token != "CANARY-NEW-ACCESS" {
		t.Fatal("known committed operation was not reconciled", e)
	}
}
func TestUncertainCommitBlocksAndDoesNotRetry(t *testing.T) {
	m, r, s, p := fixture(t)
	s.put = func(ctx context.Context, path string, b Bundle, v int64) (int64, error) {
		if b.State == StateActive && b.Generation == 2 {
			return 0, ErrCAS
		}
		return s.MemorySecretStore.Put(ctx, path, b, v)
	}
	if _, e := m.Access(context.Background(), "c", allow); e != ErrReauth {
		t.Fatal(e)
	}
	if r.connection().Status != "needs_reauth" {
		t.Fatal("not blocked")
	}
	_, _ = m.Access(context.Background(), "c", allow)
	if p.calls.Load() != 1 {
		t.Fatal("uncertain refresh replayed")
	}
}
func TestCrashIntentFencesEvenWhenDatabaseMarkFails(t *testing.T) {
	m, r, s, p := fixture(t)
	r.failReauth.Store(true)
	p.refresh = func(context.Context, string) (RefreshResult, error) { return RefreshResult{}, ErrRefreshUncertain }
	if _, e := m.Access(context.Background(), "c", allow); e != ErrReauth {
		t.Fatal(e)
	}
	b, _, _ := s.Get(context.Background(), Path("c"))
	if b.State != StateRefreshing {
		t.Fatal("no durable refresh intent")
	}
	if _, e := m.Access(context.Background(), "c", allow); e != ErrReauth {
		t.Fatal(e)
	}
	if p.calls.Load() != 1 {
		t.Fatal("uncertain rotating token retried")
	}
}
func TestDatabaseRepairAfterCommittedSecret(t *testing.T) {
	m, r, _, p := fixture(t)
	r.failRepair.Store(true)
	token, e := m.Access(context.Background(), "c", allow)
	if e == nil || token != "" {
		t.Fatal("DB failure did not fail closed")
	}
	r.failRepair.Store(false)
	token, e = m.Access(context.Background(), "c", allow)
	if e != nil || token != "CANARY-NEW-ACCESS" || p.calls.Load() != 1 || r.connection().SecretVersion != 3 {
		t.Fatal("DB advisory recovery failed", e)
	}
}
func TestDisconnectDuringRefreshDoesNotResurrect(t *testing.T) {
	m, r, s, p := fixture(t)
	p.refresh = func(context.Context, string) (RefreshResult, error) {
		_ = r.Transact(context.Background(), func(st *domain.State) error {
			c := st.Connections["c"]
			c.Status = "disconnected"
			c.Epoch++
			st.Connections["c"] = c
			return nil
		})
		return RefreshResult{AccessToken: "new", RefreshToken: "new-refresh", Expiry: m.now().Add(time.Hour)}, nil
	}
	token, e := m.Access(context.Background(), "c", allow)
	if e == nil || token != "" {
		t.Fatal("disconnected token returned")
	}
	b, _, _ := s.Get(context.Background(), Path("c"))
	if b.State == StateActive || b.AccessToken == "new" || r.connection().Status != "disconnected" {
		t.Fatal("disconnected epoch resurrected")
	}
}
func TestLockReleaseFailureReturnsNoToken(t *testing.T) {
	m, r, _, _ := fixture(t)
	r.unlockError = true
	token, e := m.Access(context.Background(), "c", allow)
	if e != ErrUnavailable || token != "" {
		t.Fatal("lost lock returned credentials")
	}
}
func TestTombstoneRetainsFailedRevocationForRetry(t *testing.T) {
	m, r, s, p := fixture(t)
	_ = r.Transact(context.Background(), func(st *domain.State) error {
		c := st.Connections["c"]
		c.Status = "disconnected"
		c.Epoch = 2
		st.Connections["c"] = c
		return nil
	})
	p.revoke = func(context.Context, string) error { return ErrUnavailable }
	if e := m.Tombstone(context.Background(), "c", 2); e == nil {
		t.Fatal("failed revoke reported success")
	}
	b, _, _ := s.Get(context.Background(), Path("c"))
	if b.State != StateTombstoned || b.RefreshToken == "" {
		t.Fatal("revocation material lost")
	}
	p.revoke = func(context.Context, string) error { return nil }
	if e := m.Tombstone(context.Background(), "c", 2); e != nil {
		t.Fatal(e)
	}
	b, _, _ = s.Get(context.Background(), Path("c"))
	if b.RefreshToken != "" || b.AccessToken != "" {
		t.Fatal("completed tombstone retained live credentials")
	}
}

func TestConcurrent401RefreshesRejectedGenerationOnce(t *testing.T) {
	m, r, s, p := fixture(t)
	b, v, _ := s.Get(context.Background(), Path("c"))
	b.Expiry = m.now().Add(time.Hour)
	_, _ = s.Put(context.Background(), Path("c"), b, v)
	second := &Manager{Repository: r, Secrets: s, Provider: p, Now: m.Now}
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			manager := m
			if i%2 == 1 {
				manager = second
			}
			lease, e := manager.ForceRefreshAfter(context.Background(), "c", 1, allow)
			if e != nil {
				errs <- e
			} else if lease.Token != "CANARY-NEW-ACCESS" || lease.Generation != 2 {
				errs <- errors.New("reused rejected generation")
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
	if p.calls.Load() != 1 {
		t.Fatalf("401 recovery refreshes=%d", p.calls.Load())
	}
}
