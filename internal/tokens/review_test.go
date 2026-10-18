package tokens

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/ufaruq/toolbox/internal/domain"
)

// A refresh response received after disconnect still contains credential material
// that must be retired. It must not become an active connection or be forgotten.
func TestReviewDisconnectDuringRotationRevokesNewCredential(t *testing.T) {
	m, repo, secrets, provider := fixture(t)
	provider.refresh = func(context.Context, string) (RefreshResult, error) {
		if err := repo.Transact(context.Background(), func(st *domain.State) error {
			c := st.Connections["c"]
			c.Status = "disconnecting"
			c.Epoch++
			st.Connections[c.ID] = c
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return RefreshResult{AccessToken: "NEW-ACCESS-AFTER-DISCONNECT", RefreshToken: "NEW-REFRESH-AFTER-DISCONNECT", Expiry: m.now().Add(time.Hour)}, nil
	}
	var revoked []string
	provider.revoke = func(_ context.Context, token string) error {
		revoked = append(revoked, token)
		return nil // Includes already-invalid old tokens, as the Google adapter does.
	}
	if token, err := m.Access(context.Background(), "c", allow); err == nil || token != "" {
		t.Fatal("disconnect must block credential use")
	}
	if err := m.Tombstone(context.Background(), "c", 2); err != nil {
		t.Fatal(err)
	}
	for _, token := range revoked {
		if token == "NEW-REFRESH-AFTER-DISCONNECT" {
			bundle, _, err := secrets.Get(context.Background(), Path("c"))
			if err != nil || bundle.State != StateTombstoned || bundle.AccessToken != "" || bundle.RefreshToken != "" {
				t.Fatal("cleanup did not leave an empty tombstone", err)
			}
			return
		}
	}
	t.Fatalf("cleanup never revoked the known rotated credential; revoked only %q", revoked)
}

func disconnect(t *testing.T, r *testRepo) {
	t.Helper()
	if err := r.Transact(context.Background(), func(s *domain.State) error {
		c := s.Connections["c"]
		c.Status = "disconnecting"
		c.Epoch++
		s.Connections[c.ID] = c
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestRejectedRotationRetainsCleanupForRetry(t *testing.T) {
	for _, mode := range []string{"disconnect", "scope-loss", "expired", "missing-access", "cancelled", "lost-lock", "write-timeout", "write-failure"} {
		t.Run(mode, func(t *testing.T) {
			m, r, s, p := fixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			p.refresh = func(context.Context, string) (RefreshResult, error) {
				result := RefreshResult{AccessToken: "new-access", RefreshToken: "rotated", Expiry: m.now().Add(time.Hour)}
				switch mode {
				case "scope-loss":
					result.Scopes = []string{"other-scope"}
				case "expired":
					result.Expiry = m.now()
				case "missing-access":
					result.AccessToken = ""
				default:
					disconnect(t, r)
				}
				if mode == "cancelled" {
					cancel()
				}
				if mode == "lost-lock" {
					r.unlockError = true
				}
				return result, nil
			}
			if mode == "write-timeout" || mode == "write-failure" {
				s.put = func(ctx context.Context, path string, b Bundle, v int64) (int64, error) {
					if b.State == StateCleanup {
						if mode == "write-timeout" {
							_, _ = s.MemorySecretStore.Put(ctx, path, b, v)
						}
						return 0, ErrUnavailable
					}
					return s.MemorySecretStore.Put(ctx, path, b, v)
				}
			}
			if token, err := m.Access(ctx, "c", allow); err == nil || token != "" {
				t.Fatal("rejected rotation released credentials")
			}
			b, _, err := s.Get(context.Background(), Path("c"))
			if err != nil {
				t.Fatal(err)
			}
			r.unlockError = false
			if mode == "write-failure" {
				if b.State != StateRefreshing {
					t.Fatal("uncertain intent lost")
				}
				if err := m.Tombstone(context.Background(), "c", 2); err != ErrRefreshUncertain {
					t.Fatal("unresolved cleanup completed", err)
				}
				return
			}
			if b.State != StateCleanup || b.RefreshToken != "rotated" || b.Epoch != 1 || b.Generation != 2 || b.OperationID == "initial" || b.AccessToken != "" {
				t.Fatal("cleanup generation not retained")
			}
			if r.connection().Status == "active" {
				t.Fatal("rejected connection remains active")
			}
			epoch := r.connection().Epoch
			p.revoke = func(_ context.Context, token string) error {
				if token != "rotated" {
					t.Error("cleanup revoked wrong generation")
				}
				return ErrUnavailable
			}
			if err := m.Tombstone(context.Background(), "c", epoch); err == nil {
				t.Fatal("failed revocation completed")
			}
			b, _, _ = s.Get(context.Background(), Path("c"))
			if b.State != StateTombstoned || b.RefreshToken != "rotated" {
				t.Fatal("retry material lost")
			}
			p.revoke = func(_ context.Context, token string) error {
				if token != "rotated" {
					t.Error("retry revoked wrong generation")
				}
				return nil
			}
			if err := m.Tombstone(context.Background(), "c", epoch); err != nil {
				t.Fatal(err)
			}
			if token, err := m.Access(context.Background(), "c", allow); err == nil || token != "" {
				t.Fatal("cleanup reactivated connection")
			}
		})
	}
}

// Simulate a second worker acquiring a DB session lock after the first worker's
// lock was lost while the provider operation remained in flight.
type lostSessionRepo struct{ *testRepo }

func (r lostSessionRepo) LockConnection(context.Context, string) (func() error, error) {
	return func() error { return nil }, nil
}

func TestCleanupWaitsForLateRefreshAfterLockLoss(t *testing.T) {
	m, r, s, p := fixture(t)
	started, finish := make(chan struct{}), make(chan struct{})
	p.refresh = func(context.Context, string) (RefreshResult, error) {
		close(started)
		<-finish
		return RefreshResult{AccessToken: "late-access", RefreshToken: "late-refresh", Expiry: m.now().Add(time.Hour)}, nil
	}
	done := make(chan error, 1)
	go func() {
		token, err := m.Access(context.Background(), "c", allow)
		if token != "" {
			done <- ErrUnavailable
			return
		}
		done <- err
	}()
	<-started
	disconnect(t, r)
	second := &Manager{Repository: lostSessionRepo{r}, Secrets: s, Provider: p, Now: m.Now}
	before, v, _ := s.Get(context.Background(), Path("c"))
	if err := second.Tombstone(context.Background(), "c", 2); err != ErrRefreshUncertain {
		t.Error("in-flight cleanup not pending", err)
	}
	after, version, _ := s.Get(context.Background(), Path("c"))
	if version != v || after.OperationID != before.OperationID || after.State != StateRefreshing {
		t.Error("cleanup overwrote pending intent")
	}
	close(finish)
	if err := <-done; err == nil {
		t.Fatal("late refresh activated")
	}
	var revoked string
	p.revoke = func(_ context.Context, token string) error { revoked = token; return nil }
	if err := second.Tombstone(context.Background(), "c", 2); err != nil {
		t.Fatal(err)
	}
	if revoked != "late-refresh" {
		t.Fatal("late credential not revoked")
	}
}

// This opt-in test uses a disposable, loopback-only OpenBao dev instance. It
// validates the lifecycle against real KV-v2 CAS rather than a protocol mock.
func TestRotationCleanupOpenBao(t *testing.T) {
	address := os.Getenv("TOOLBOX_TEST_OPENBAO_ADDR")
	if address == "" {
		t.Skip("set TOOLBOX_TEST_OPENBAO_ADDR and TOOLBOX_TEST_OPENBAO_TOKEN for disposable OpenBao integration")
	}
	secrets, err := NewOpenBaoFixture(OpenBaoConfig{Address: address, Mount: "secret", Token: os.Getenv("TOOLBOX_TEST_OPENBAO_TOKEN")})
	if err != nil {
		t.Fatal(err)
	}
	m, r, memory, p := fixture(t)
	id, err := operationID()
	if err != nil {
		t.Fatal(err)
	}
	b, _, _ := memory.Get(context.Background(), Path("c"))
	b.ConnectionID = id
	if _, err := secrets.Put(context.Background(), Path(id), b, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := secrets.DeleteJSON(context.Background(), Path(id)); err != nil {
			t.Error(err)
		}
	})
	c := r.state.Connections["c"]
	delete(r.state.Connections, "c")
	c.ID = id
	r.state.Connections[id] = c
	m.Secrets = secrets
	p.refresh = func(context.Context, string) (RefreshResult, error) {
		err := r.Transact(context.Background(), func(s *domain.State) error {
			c := s.Connections[id]
			c.Status = "disconnecting"
			c.Epoch++
			s.Connections[id] = c
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		return RefreshResult{AccessToken: "synthetic-access", RefreshToken: "synthetic-rotated", Expiry: m.now().Add(time.Hour)}, nil
	}
	if token, err := m.Access(context.Background(), id, allow); err == nil || token != "" {
		t.Fatal("disconnected rotation released token")
	}
	b, v, err := secrets.Get(context.Background(), Path(id))
	if err != nil || b.State != StateCleanup || b.RefreshToken != "synthetic-rotated" {
		t.Fatal("real KV lost cleanup generation", err)
	}
	if _, err := secrets.Put(context.Background(), Path(id), b, v-1); err != ErrCAS {
		t.Fatal("real KV failed to fence stale writer", err)
	}
	p.revoke = func(_ context.Context, token string) error {
		if token != "synthetic-rotated" {
			t.Error("wrong cleanup credential")
		}
		return ErrUnavailable
	}
	if err := m.Tombstone(context.Background(), id, 2); err == nil {
		t.Fatal("revoke failure completed")
	}
	p.revoke = func(_ context.Context, token string) error {
		if token != "synthetic-rotated" {
			t.Error("retry credential lost")
		}
		return nil
	}
	if err := m.Tombstone(context.Background(), id, 2); err != nil {
		t.Fatal(err)
	}
	b, _, err = secrets.Get(context.Background(), Path(id))
	if err != nil || b.State != StateTombstoned || b.RefreshToken != "" || b.AccessToken != "" {
		t.Fatal("real KV cleanup incomplete", err)
	}
}
