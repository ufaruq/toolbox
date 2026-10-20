package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/ufaruq/toolbox/internal/domain"
)

func ownerLoginRecord(now time.Time) domain.OwnerLoginTransaction {
	return domain.OwnerLoginTransaction{ID: "login1", StateHash: "state-hash", BrowserHash: "browser-hash", NonceHash: "nonce-hash", SecretRef: "owner-login/login1", Issuer: "https://issuer.example", ClientID: "owner-client", RedirectURI: "http://127.0.0.1:8080/auth/oidc/callback", PreviousSessionID: "s1", Status: "pending", ExpiresAt: now.Add(10 * time.Minute)}
}

func exerciseOwnerLoginRepository(t *testing.T, repo domain.Repository) {
	t.Helper()
	ctx := context.Background()
	seed(t, repo)
	var initial domain.OwnerLoginTransaction
	if err := repo.Transact(ctx, func(s *domain.State) error {
		initial = ownerLoginRecord(s.Now)
		s.OwnerLogins[initial.ID] = initial
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := repo.Transact(ctx, func(s *domain.State) error {
		if !reflect.DeepEqual(s.OwnerLogins[initial.ID], initial) {
			t.Fatalf("login metadata did not round trip: %+v", s.OwnerLogins[initial.ID])
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*domain.State){
		"duplicate state": func(s *domain.State) { v := initial; v.ID = "login2"; s.OwnerLogins[v.ID] = v },
		"missing binding": func(s *domain.State) {
			v := initial
			v.ID = "login2"
			v.StateHash = "different"
			v.BrowserHash = ""
			s.OwnerLogins[v.ID] = v
		},
		"missing previous session": func(s *domain.State) {
			v := initial
			v.ID = "login2"
			v.StateHash = "different"
			v.PreviousSessionID = "absent"
			s.OwnerLogins[v.ID] = v
		},
		"new row already exchanging": func(s *domain.State) {
			v := initial
			v.ID = "login2"
			v.StateHash = "different"
			v.Status = "exchanging"
			s.OwnerLogins[v.ID] = v
		},
		"mutated binding": func(s *domain.State) {
			v := s.OwnerLogins[initial.ID]
			v.ClientID = "other-client"
			s.OwnerLogins[v.ID] = v
		},
		"extended expiry": func(s *domain.State) {
			v := s.OwnerLogins[initial.ID]
			v.ExpiresAt = v.ExpiresAt.Add(time.Hour)
			s.OwnerLogins[v.ID] = v
		},
		"skipped exchange": func(s *domain.State) {
			v := s.OwnerLogins[initial.ID]
			v.Status = "complete"
			v.IssuedSessionID = "s1"
			s.OwnerLogins[v.ID] = v
		},
		"delete active login":  func(s *domain.State) { delete(s.OwnerLogins, initial.ID) },
		"user issuer changed":  func(s *domain.State) { v := s.Users["u1"]; v.Issuer = "https://other.example"; s.Users[v.ID] = v },
		"user subject changed": func(s *domain.State) { v := s.Users["u1"]; v.Subject = "different"; s.Users[v.ID] = v },
	} {
		t.Run(name, func(t *testing.T) {
			if err := repo.Transact(ctx, func(s *domain.State) error { mutate(s); return nil }); !errors.Is(err, ErrInvariant) {
				t.Fatalf("expected invariant rejection, got %v", err)
			}
		})
	}
	if err := repo.Transact(ctx, func(s *domain.State) error {
		v := s.OwnerLogins[initial.ID]
		v.Status = "exchanging"
		s.OwnerLogins[v.ID] = v
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for name, status := range map[string]string{"backwards status": "pending", "unknown status": "unknown"} {
		t.Run(name, func(t *testing.T) {
			if err := repo.Transact(ctx, func(s *domain.State) error {
				v := s.OwnerLogins[initial.ID]
				v.Status = status
				s.OwnerLogins[v.ID] = v
				return nil
			}); !errors.Is(err, ErrInvariant) {
				t.Fatalf("expected invariant rejection, got %v", err)
			}
		})
	}
	if err := repo.Transact(ctx, func(s *domain.State) error {
		v := s.OwnerLogins[initial.ID]
		v.Status, v.IssuedSessionID = "complete", "absent"
		s.OwnerLogins[v.ID] = v
		return nil
	}); !errors.Is(err, ErrInvariant) {
		t.Fatalf("missing issued session accepted: %v", err)
	}
	if err := repo.Transact(ctx, func(s *domain.State) error {
		v := s.OwnerLogins[initial.ID]
		v.Status, v.IssuedSessionID = "complete", "s-issued"
		s.Sessions[v.IssuedSessionID] = domain.Session{ID: v.IssuedSessionID, UserID: "u1", CSRFHash: "csrf-hash", ExpiresAt: s.Now.Add(time.Hour)}
		s.OwnerLogins[v.ID] = v
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*domain.State){
		"issued session rebound": func(s *domain.State) {
			v := s.OwnerLogins[initial.ID]
			v.IssuedSessionID = "s1"
			s.OwnerLogins[v.ID] = v
		},
		"issued session cleared":           func(s *domain.State) { v := s.OwnerLogins[initial.ID]; v.IssuedSessionID = ""; s.OwnerLogins[v.ID] = v },
		"completed login cancelled":        func(s *domain.State) { v := s.OwnerLogins[initial.ID]; v.Status = "cancelled"; s.OwnerLogins[v.ID] = v },
		"delete live session relationship": func(s *domain.State) { delete(s.OwnerLogins, initial.ID) },
	} {
		t.Run(name, func(t *testing.T) {
			if err := repo.Transact(ctx, func(s *domain.State) error { mutate(s); return nil }); !errors.Is(err, ErrInvariant) {
				t.Fatalf("expected invariant rejection, got %v", err)
			}
		})
	}
	if err := repo.Transact(ctx, func(s *domain.State) error {
		v := s.Sessions["s-issued"]
		v.ExpiresAt = s.Now
		s.Sessions[v.ID] = v
		delete(s.OwnerLogins, initial.ID)
		return nil
	}); err != nil {
		t.Fatalf("cleanup after issued-session revocation: %v", err)
	}
}

func TestOwnerLoginRepositoryParity(t *testing.T) {
	t.Run("memory", func(t *testing.T) { exerciseOwnerLoginRepository(t, NewMemory()) })
	t.Run("postgres", func(t *testing.T) { exerciseOwnerLoginRepository(t, testPostgres(t)) })
}

func TestOwnerLoginCleanupEligibility(t *testing.T) {
	for name, open := range map[string]func(*testing.T) domain.Repository{
		"memory":   func(*testing.T) domain.Repository { return NewMemory() },
		"postgres": func(t *testing.T) domain.Repository { return testPostgres(t) },
	} {
		t.Run(name, func(t *testing.T) {
			repo := open(t)
			ctx := context.Background()
			for _, target := range []string{"cancelled", "failed", "expired"} {
				if err := repo.Transact(ctx, func(s *domain.State) error {
					v := ownerLoginRecord(s.Now)
					v.ID, v.StateHash, v.PreviousSessionID = target, target, ""
					if target == "expired" {
						v.ExpiresAt = s.Now.Add(-time.Minute)
					}
					s.OwnerLogins[v.ID] = v
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				if target == "failed" {
					if err := repo.Transact(ctx, func(s *domain.State) error {
						v := s.OwnerLogins[target]
						v.Status = "exchanging"
						s.OwnerLogins[target] = v
						return nil
					}); err != nil {
						t.Fatal(err)
					}
				}
				if target != "expired" {
					if err := repo.Transact(ctx, func(s *domain.State) error {
						v := s.OwnerLogins[target]
						v.Status = target
						s.OwnerLogins[target] = v
						return nil
					}); err != nil {
						t.Fatal(err)
					}
				}
				if err := repo.Transact(ctx, func(s *domain.State) error { delete(s.OwnerLogins, target); return nil }); err != nil {
					t.Fatalf("cleanup %s: %v", target, err)
				}
			}
		})
	}
}

func TestExpireSessionWithPendingGoogleOAuth(t *testing.T) {
	for name, open := range map[string]func(*testing.T) domain.Repository{
		"memory":   func(*testing.T) domain.Repository { return NewMemory() },
		"postgres": func(t *testing.T) domain.Repository { return testPostgres(t) },
	} {
		t.Run(name, func(t *testing.T) {
			repo := open(t)
			seed(t, repo)
			if err := repo.Transact(context.Background(), func(s *domain.State) error {
				v := s.Sessions["s1"]
				v.ExpiresAt = s.Now
				s.Sessions[v.ID] = v
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if err := repo.Transact(context.Background(), func(s *domain.State) error {
				if s.Now.Before(s.Sessions["s1"].ExpiresAt) || s.OAuth["o1"].SessionID != "s1" {
					t.Fatal("session expiry or Google reference lost")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
	body, err := migrations.ReadFile("migrations/001_initial.sql")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	if got := hex.EncodeToString(sum[:]); got != "8c71d84424b2a63accc5d2fe1c31e1b8cbb4ab808c7356ff93a8f690b808f6eb" {
		t.Fatalf("initial migration changed: %s", got)
	}
}

func TestOwnerLoginDatabaseConstraints(t *testing.T) {
	p := testPostgres(t)
	seed(t, p)
	ctx := context.Background()
	v := ownerLoginRecord(time.Now().UTC())
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = p.pool.Exec(ctx, "INSERT INTO owner_login_transactions(payload) VALUES($1)", data); err != nil {
		t.Fatal(err)
	}
	for name, query := range map[string]string{
		"secret injection":  `UPDATE owner_login_transactions SET payload=payload || '{"Verifier":"secret-canary"}'::jsonb`,
		"binding mutation":  `UPDATE owner_login_transactions SET payload=jsonb_set(payload,'{ClientID}','"other"')`,
		"skipped exchange":  `UPDATE owner_login_transactions SET payload=jsonb_set(payload,'{Status}','"complete"')`,
		"early deletion":    `DELETE FROM owner_login_transactions`,
		"immutable issuer":  `UPDATE users SET payload=jsonb_set(payload,'{Issuer}','"https://other.example"') WHERE id='u1'`,
		"immutable subject": `UPDATE users SET payload=jsonb_set(payload,'{Subject}','"other"') WHERE id='u1'`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := p.pool.Exec(ctx, query)
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || len(pgErr.Code) < 2 || pgErr.Code[:2] != "23" {
				t.Fatalf("expected SQL integrity rejection, got %v", err)
			}
		})
	}
	for _, field := range []string{"Verifier", "BrowserHash", "PreviousSessionID"} {
		t.Run("insert invalid "+field, func(t *testing.T) {
			var payload map[string]any
			if err := json.Unmarshal(data, &payload); err != nil {
				t.Fatal(err)
			}
			payload["ID"], payload["StateHash"] = "invalid-"+field, "invalid-"+field
			switch field {
			case "Verifier":
				payload[field] = "secret-canary"
			case "BrowserHash":
				payload[field] = nil
			case "PreviousSessionID":
				payload[field] = "absent"
			}
			encoded, err := json.Marshal(payload)
			if err != nil {
				t.Fatal(err)
			}
			_, err = p.pool.Exec(ctx, "INSERT INTO owner_login_transactions(payload) VALUES($1)", encoded)
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || len(pgErr.Code) < 2 || pgErr.Code[:2] != "23" {
				t.Fatalf("expected SQL integrity rejection, got %v", err)
			}
		})
	}
}

func TestOwnerLoginDatabaseRetainsAncestorOfPendingReplacement(t *testing.T) {
	p := testPostgres(t)
	seed(t, p)
	ctx := context.Background()
	if err := p.Transact(ctx, func(s *domain.State) error {
		v := ownerLoginRecord(s.Now)
		v.PreviousSessionID = ""
		s.OwnerLogins[v.ID] = v
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, status := range []string{"exchanging", "complete"} {
		if err := p.Transact(ctx, func(s *domain.State) error {
			v := s.OwnerLogins["login1"]
			v.Status = status
			if status == "complete" {
				v.IssuedSessionID = "s1"
			}
			s.OwnerLogins[v.ID] = v
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.Transact(ctx, func(s *domain.State) error {
		session := s.Sessions["s1"]
		session.ExpiresAt = s.Now
		s.Sessions["s1"] = session
		child := ownerLoginRecord(s.Now)
		child.ID, child.StateHash = "child", "child-state"
		s.OwnerLogins[child.ID] = child
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	_, err := p.pool.Exec(ctx, "DELETE FROM owner_login_transactions WHERE id='login1'")
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23514" {
		t.Fatalf("ancestor deletion must preserve the pending replacement link, got %v", err)
	}
	if err := p.Transact(ctx, func(s *domain.State) error {
		child := s.OwnerLogins["child"]
		child.Status = "cancelled"
		s.OwnerLogins[child.ID] = child
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := p.pool.Exec(ctx, "DELETE FROM owner_login_transactions WHERE id='login1'"); err != nil {
		t.Fatal(err)
	}
}
