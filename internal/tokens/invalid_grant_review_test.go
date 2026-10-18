package tokens

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

func TestDefinitiveInvalidGrantResolvesIntentForCleanup(t *testing.T) {
	for _, mode := range []string{"invalid grant", "wrapped invalid grant", "cancelled caller", "disconnect", "committed write timeout"} {
		t.Run(mode, func(t *testing.T) {
			m, r, s, p := fixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			p.refresh = func(context.Context, string) (RefreshResult, error) {
				if mode == "cancelled caller" {
					cancel()
				}
				if mode == "disconnect" {
					disconnect(t, r)
				}
				if mode == "wrapped invalid grant" {
					return RefreshResult{}, fmt.Errorf("refresh rejected: %w", ErrInvalidGrant)
				}
				return RefreshResult{}, ErrInvalidGrant
			}
			if mode == "committed write timeout" {
				s.put = func(ctx context.Context, path string, b Bundle, cas int64) (int64, error) {
					v, err := s.MemorySecretStore.Put(ctx, path, b, cas)
					if err == nil && b.State == StateCleanup {
						return 0, ErrUnavailable
					}
					return v, err
				}
			}
			if lease, err := m.AccessLease(ctx, "c", allow); err == nil || lease != (Lease{}) {
				t.Fatal("invalid grant released credentials", err)
			}
			b, version, err := s.Get(context.Background(), Path("c"))
			if err != nil || b.State != StateCleanup || version != 3 || b.Generation != 2 || b.OperationID == "initial" || b.OperationID == "" || b.ConnectionID != "c" || b.Subject != "subject" || b.ClientID != "client" || b.Epoch != 1 || b.RefreshToken != "CANARY-OLD-REFRESH" || b.AccessToken != "" || !b.Expiry.IsZero() {
				t.Fatal("definitive rejection left unresolved intent or lost old cleanup material", err)
			}
			if r.connection().Status == "active" {
				t.Fatal("invalid grant left connection active")
			}
			if mode != "disconnect" {
				disconnect(t, r)
			}
			calls := 0
			p.revoke = func(_ context.Context, token string) error {
				calls++
				if token != "CANARY-OLD-REFRESH" {
					t.Error("cleanup revoked a different generation")
				}
				if calls == 1 {
					return ErrUnavailable
				}
				return nil
			}
			if err := m.Tombstone(context.Background(), "c", 2); !errors.Is(err, ErrUnavailable) {
				t.Fatal("failed revocation was not reported", err)
			}
			if err := m.Tombstone(context.Background(), "c", 2); err != nil || calls != 2 {
				t.Fatal("definitive rejection cleanup could not finish", err)
			}
			b, _, _ = s.Get(context.Background(), Path("c"))
			if b.State != StateTombstoned || b.AccessToken != "" || b.RefreshToken != "" {
				t.Fatal("successful cleanup did not clear retired credentials")
			}
			if lease, err := m.AccessLease(context.Background(), "c", allow); err == nil || lease != (Lease{}) || p.calls.Load() != 1 {
				t.Fatal("definitive rejection was replayed", err)
			}
		})
	}
}

func TestEmptyUnknownRefreshOutcomeRemainsFenced(t *testing.T) {
	for _, refreshErr := range []error{context.DeadlineExceeded, errors.New("malformed provider response"), ErrUnavailable} {
		t.Run(refreshErr.Error(), func(t *testing.T) {
			m, r, s, p := fixture(t)
			p.refresh = func(context.Context, string) (RefreshResult, error) { return RefreshResult{}, refreshErr }
			if _, err := m.AccessLease(context.Background(), "c", allow); !errors.Is(err, ErrReauth) {
				t.Fatal("unknown refresh accepted", err)
			}
			b, version, err := s.Get(context.Background(), Path("c"))
			if err != nil || b.State != StateRefreshing || b.Generation != 1 || version != 2 {
				t.Fatal("unknown result lost its uncertainty fence", err)
			}
			disconnect(t, r)
			if err := m.Tombstone(context.Background(), "c", 2); !errors.Is(err, ErrRefreshUncertain) {
				t.Fatal("unknown result declared cleaned", err)
			}
			if _, err := m.AccessLease(context.Background(), "c", allow); err == nil || p.calls.Load() != 1 {
				t.Fatal("uncertain refresh was replayed", err)
			}
		})
	}
}

func TestInvalidGrantPersistenceFailureKeepsIntentUnresolved(t *testing.T) {
	m, r, s, p := fixture(t)
	p.refresh = func(context.Context, string) (RefreshResult, error) { return RefreshResult{}, ErrInvalidGrant }
	s.put = func(ctx context.Context, path string, b Bundle, cas int64) (int64, error) {
		if b.State == StateCleanup {
			return 0, ErrUnavailable
		}
		return s.MemorySecretStore.Put(ctx, path, b, cas)
	}
	if lease, err := m.AccessLease(context.Background(), "c", allow); err == nil || lease != (Lease{}) {
		t.Fatal("unpersisted rejection released credentials", err)
	}
	b, version, err := s.Get(context.Background(), Path("c"))
	if err != nil || b.State != StateRefreshing || version != 2 {
		t.Fatal("failed resolution did not preserve durable intent", err)
	}
	disconnect(t, r)
	if err := m.Tombstone(context.Background(), "c", 2); !errors.Is(err, ErrRefreshUncertain) {
		t.Fatal("failed resolution declared cleaned", err)
	}
}

func TestInvalidGrantDoesNotOverwriteConcurrentGeneration(t *testing.T) {
	m, _, s, p := fixture(t)
	var winner Bundle
	var winnerVersion int64
	p.refresh = func(context.Context, string) (RefreshResult, error) {
		b, version, err := s.Get(context.Background(), Path("c"))
		if err != nil {
			t.Fatal(err)
		}
		winner = b
		winner.State, winner.Generation, winner.OperationID = StateCleanup, 9, "competing-operation"
		winner.Subject, winner.RefreshToken = "other-subject", "competing-credential"
		winnerVersion, err = s.MemorySecretStore.Put(context.Background(), Path("c"), winner, version)
		if err != nil {
			t.Fatal(err)
		}
		return RefreshResult{}, ErrInvalidGrant
	}
	if lease, err := m.AccessLease(context.Background(), "c", allow); err == nil || lease != (Lease{}) {
		t.Fatal("concurrent winner accepted as own refresh result", err)
	}
	b, version, err := s.Get(context.Background(), Path("c"))
	if err != nil || version != winnerVersion || b.OperationID != winner.OperationID || b.RefreshToken != winner.RefreshToken || b.Subject != winner.Subject || b.Generation != winner.Generation {
		t.Fatal("rejection overwrote competing generation", err)
	}
}

func TestInvalidGrantReconciliationRequiresExactResponse(t *testing.T) {
	for _, field := range []string{"connection", "subject", "client", "epoch", "generation", "operation", "refresh", "access", "state", "expiry", "scopes"} {
		t.Run(field, func(t *testing.T) {
			m, r, s, p := fixture(t)
			p.refresh = func(context.Context, string) (RefreshResult, error) {
				disconnect(t, r)
				return RefreshResult{}, ErrInvalidGrant
			}
			s.put = func(ctx context.Context, path string, b Bundle, cas int64) (int64, error) {
				if b.State != StateCleanup {
					return s.MemorySecretStore.Put(ctx, path, b, cas)
				}
				switch field {
				case "connection":
					b.ConnectionID = "another-connection"
				case "subject":
					b.Subject = "another-subject"
				case "client":
					b.ClientID = "another-client"
				case "epoch":
					b.Epoch++
				case "generation":
					b.Generation++
				case "operation":
					b.OperationID = "another-operation"
				case "refresh":
					b.RefreshToken = "another-refresh"
				case "access":
					b.AccessToken = "another-access"
				case "state":
					b.State = StateActive
				case "expiry":
					b.Expiry = m.now()
				case "scopes":
					b.Scopes = []string{"another-scope"}
				}
				_, _ = s.MemorySecretStore.Put(ctx, path, b, cas)
				return 0, ErrUnavailable
			}
			if lease, err := m.AccessLease(context.Background(), "c", allow); !errors.Is(err, ErrReauth) || lease != (Lease{}) {
				t.Fatal("different stored response accepted", err)
			}
			// Another identity or generation cannot be used to unblock this
			// operation. The failed write must block rather than activate access.
			if r.connection().Status != "disconnecting" || p.calls.Load() != 1 {
				t.Fatal("unreconciled result did not fail closed")
			}
			b, version, err := s.Get(context.Background(), Path("c"))
			if err != nil || version != 3 || b.State == StateRefreshing {
				t.Fatal("resolution was never attempted", err)
			}
		})
	}
}
