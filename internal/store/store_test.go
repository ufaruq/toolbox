package store

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/ufaruq/toolbox/internal/domain"
)

func seed(t *testing.T, r domain.Repository) {
	t.Helper()
	err := r.Transact(context.Background(), func(s *domain.State) error {
		for _, id := range []string{"u1", "u2"} {
			s.Users[id] = domain.User{ID: id, Issuer: "https://issuer.example", Subject: id, Status: "active"}
		}
		s.Agents["a1"] = domain.Agent{ID: "a1", OwnerID: "u1", Name: "Agent", Status: "active"}
		s.Agents["a2"] = domain.Agent{ID: "a2", OwnerID: "u2", Status: "active"}
		s.Connections["c1"] = domain.Connection{ID: "c1", OwnerID: "u1", Provider: "google_drive", Status: "active", Epoch: 1, Scopes: []string{domain.DriveScope}}
		s.Connections["c2"] = domain.Connection{ID: "c2", OwnerID: "u2", Provider: "google_drive", Status: "active", Epoch: 1}
		s.Resources[domain.ResourceKey("c1", "f1")] = domain.Resource{ConnectionID: "c1", FileID: "f1", MIME: "application/vnd.google-apps.document", VerifiedAt: s.Now}
		s.Grants["g1"] = domain.Grant{ID: "g1", OwnerID: "u1", AgentID: "a1", ConnectionID: "c1", Tool: domain.Tool, Action: domain.Action, FileID: "f1", Epoch: 1, Version: 1, NotBefore: s.Now, ExpiresAt: s.Now.Add(time.Hour)}
		s.Requests["r1"] = domain.Request{ID: "r1", AgentID: "a1", FileID: "f1", Tool: domain.Tool, Digest: "digest", Status: "approved", GrantID: "g1", Version: 1, DurationSeconds: 3600, ExpiresAt: s.Now.Add(time.Hour)}
		s.Credentials["k1"] = domain.Credential{ID: "k1", AgentID: "a1", Hash: "hash-only", Status: "active", ExpiresAt: s.Now.Add(time.Hour)}
		s.Sessions["s1"] = domain.Session{ID: "s1", UserID: "u1", CSRFHash: "hash-only", ExpiresAt: s.Now.Add(time.Hour)}
		s.OAuth["o1"] = domain.OAuthTransaction{ID: "o1", OwnerID: "u1", SessionID: "s1", StateHash: "state-hash", NonceHash: "nonce-hash", SecretRef: "oauth/o1", ConnectionID: "c1", ExpiresAt: s.Now.Add(time.Minute)}
		s.Cleanup["q1"] = domain.Cleanup{ID: "q1", ConnectionID: "c1", OwnerID: "u1", Status: "pending", Epoch: 1}
		s.Audits = append(s.Audits, domain.Audit{ID: "e1", At: s.Now, ActorType: "user", ActorID: "u1", SubjectID: "u1", Action: "grant.create", GrantID: "g1", Outcome: "success"})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func exerciseRepository(t *testing.T, r domain.Repository) {
	t.Helper()
	ctx := context.Background()
	seed(t, r)
	t.Run("rollback", func(t *testing.T) {
		sentinel := errors.New("rollback")
		err := r.Transact(ctx, func(s *domain.State) error {
			delete(s.Users, "u1")
			s.Connections["c1"] = domain.Connection{}
			return sentinel
		})
		if !errors.Is(err, sentinel) {
			t.Fatal(err)
		}
		err = r.Transact(ctx, func(s *domain.State) error {
			if s.Connections["c1"].ID != "c1" {
				t.Fatal("rollback leaked")
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	})
	t.Run("cancelled mutation rolls back", func(t *testing.T) {
		cancelCtx, cancel := context.WithCancel(ctx)
		err := r.Transact(cancelCtx, func(s *domain.State) error {
			v := s.Connections["c1"]
			v.SecretVersion = 999
			s.Connections["c1"] = v
			cancel()
			return nil
		})
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	})
	t.Run("ownership and immutability", func(t *testing.T) {
		cases := map[string]func(*domain.State){
			"cross-owner grant": func(s *domain.State) { g := s.Grants["g1"]; g.ID = "g2"; g.AgentID = "a2"; s.Grants[g.ID] = g },
			"missing resource":  func(s *domain.State) { g := s.Grants["g1"]; g.ID = "g2"; g.FileID = "f2"; s.Grants[g.ID] = g },
			"widen grant": func(s *domain.State) {
				g := s.Grants["g1"]
				g.ExpiresAt = g.ExpiresAt.Add(time.Hour)
				s.Grants[g.ID] = g
			},
			"delete grant":       func(s *domain.State) { delete(s.Grants, "g1") },
			"audit mutation":     func(s *domain.State) { s.Audits[0].Outcome = "changed" },
			"audit deletion":     func(s *domain.State) { s.Audits = nil },
			"duplicate approval": func(s *domain.State) { v := s.Requests["r1"]; v.ID = "r2"; s.Requests[v.ID] = v },
			"approval rebinding": func(s *domain.State) {
				v := s.Requests["r1"]
				v.GrantID = ""
				v.Status = "pending"
				s.Requests[v.ID] = v
			},
			"oauth owner mismatch":   func(s *domain.State) { v := s.OAuth["o1"]; v.OwnerID = "u2"; s.OAuth[v.ID] = v },
			"cleanup owner mismatch": func(s *domain.State) { v := s.Cleanup["q1"]; v.OwnerID = "u2"; s.Cleanup[v.ID] = v },
		}
		for name, mutate := range cases {
			t.Run(name, func(t *testing.T) {
				err := r.Transact(ctx, func(s *domain.State) error { mutate(s); return nil })
				if !errors.Is(err, ErrInvariant) {
					t.Fatalf("got %v", err)
				}
			})
		}
	})
	t.Run("serializable updates", func(t *testing.T) {
		var wg sync.WaitGroup
		errs := make(chan error, 16)
		for i := 0; i < 16; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < 8; j++ {
					err := r.Transact(ctx, func(s *domain.State) error {
						v := s.Connections["c1"]
						v.SecretVersion++
						s.Connections[v.ID] = v
						return nil
					})
					if err != nil {
						errs <- err
						return
					}
				}
			}()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Fatal(err)
		}
		err := r.Transact(ctx, func(s *domain.State) error {
			if s.Connections["c1"].SecretVersion != 128 {
				t.Fatalf("lost update: %d", s.Connections["c1"].SecretVersion)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	})
	t.Run("revocation one way", func(t *testing.T) {
		if err := r.Transact(ctx, func(s *domain.State) error {
			g := s.Grants["g1"]
			now := s.Now
			g.RevokedAt = &now
			s.Grants[g.ID] = g
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		err := r.Transact(ctx, func(s *domain.State) error { g := s.Grants["g1"]; g.RevokedAt = nil; s.Grants[g.ID] = g; return nil })
		if !errors.Is(err, ErrInvariant) {
			t.Fatal(err)
		}
	})
	t.Run("connection locks", func(t *testing.T) {
		unlock, err := r.LockConnection(ctx, "c1")
		if err != nil {
			t.Fatal(err)
		}
		defer unlock()
		short, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
		defer cancel()
		if _, err = r.LockConnection(short, "c1"); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("expected contention deadline, got %v", err)
		}
		other, err := r.LockConnection(ctx, "c2")
		if err != nil {
			t.Fatal(err)
		}
		if err = other(); err != nil {
			t.Fatal(err)
		}
		if err = unlock(); err != nil {
			t.Fatal(err)
		}
		if err = unlock(); err != nil {
			t.Fatal(err)
		}
		again, err := r.LockConnection(ctx, "c1")
		if err != nil {
			t.Fatal(err)
		}
		if err = again(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("cancelled lock session closes", func(t *testing.T) {
		leaseCtx, cancel := context.WithCancel(ctx)
		unlock, err := r.LockConnection(leaseCtx, "cancelled")
		if err != nil {
			t.Fatal(err)
		}
		cancel()
		if err = unlock(); !errors.Is(err, ErrLockLost) {
			t.Fatal(err)
		}
		next, err := r.LockConnection(ctx, "cancelled")
		if err != nil {
			t.Fatal(err)
		}
		if err = next(); err != nil {
			t.Fatal(err)
		}
	})
}
func TestMemoryRepository(t *testing.T) { exerciseRepository(t, NewMemory()) }
func TestMemoryDeepIsolation(t *testing.T) {
	r := NewMemory()
	seed(t, r)
	var retained *domain.State
	if err := r.Transact(context.Background(), func(s *domain.State) error { retained = s; return nil }); err != nil {
		t.Fatal(err)
	}
	retained.Connections["c1"].Scopes[0] = "modified"
	delete(retained.Users, "u1")
	retained.Audits[0].Action = "changed"
	if err := r.Transact(context.Background(), func(s *domain.State) error {
		if s.Connections["c1"].Scopes[0] != domain.DriveScope || s.Users["u1"].ID != "u1" || s.Audits[0].Action != "grant.create" {
			return fmt.Errorf("retained state leaked")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
func TestMemoryClock(t *testing.T) {
	at := time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)
	r := NewMemoryWithClock(func() time.Time { return at })
	if err := r.Transact(context.Background(), func(s *domain.State) error {
		if !s.Now.Equal(at) {
			t.Fatal(s.Now)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
func TestMemoryPanicRollback(t *testing.T) {
	r := NewMemory()
	seed(t, r)
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("expected panic")
			}
		}()
		_ = r.Transact(context.Background(), func(s *domain.State) error { delete(s.Users, "u1"); panic("callback") })
	}()
	if err := r.Transact(context.Background(), func(s *domain.State) error {
		if _, ok := s.Users["u1"]; !ok {
			t.Fatal("panic committed")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
