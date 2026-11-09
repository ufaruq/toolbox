package store

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/ufaruq/toolbox/internal/domain"
)

func candidateRecord(now time.Time) map[string]any {
	return map[string]any{"ID": "c1", "OwnerID": "u1", "Issuer": "https://issuer.example", "UserID": "u1", "ClientID": "new-client", "Status": "pending", "FirstSeenAt": now, "DecidedAt": time.Time{}}
}
func putCandidate(t *testing.T, s *domain.State, id string, c map[string]any) {
	t.Helper()
	records := recordState(t, s)
	candidates, _ := records["CallerCandidates"].(map[string]any)
	if candidates == nil {
		candidates = map[string]any{}
	}
	candidates[id] = c
	applyRecords(t, s, map[string]any{"CallerCandidates": candidates})
}
func exerciseCallerCandidates(t *testing.T, r domain.Repository) {
	t.Helper()
	ctx := context.Background()
	seed(t, r)
	var first time.Time
	if err := r.Transact(ctx, func(s *domain.State) error {
		first = s.Now
		putCandidate(t, s, "c1", candidateRecord(first))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	t.Run("roundtrip", func(t *testing.T) {
		if err := r.Transact(ctx, func(s *domain.State) error {
			candidates, ok := recordState(t, s)["CallerCandidates"].(map[string]any)
			if !ok || candidates["c1"] == nil {
				t.Error("pending candidate was not persisted")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})
	invalid := map[string]map[string]any{
		"duplicate identity": {}, "wrong owner": {"OwnerID": "u2"}, "unknown owner": {"OwnerID": "missing"},
		"unknown subject": {"UserID": "other"}, "unknown issuer": {"Issuer": "https://other.example"},
		"empty ID": {"ID": ""}, "empty client": {"ClientID": ""}, "invalid status": {"Status": "active"},
		"zero first seen": {"FirstSeenAt": time.Time{}}, "pending decision": {"DecidedAt": first},
		"rejected missing decision": {"Status": "rejected"}, "rejected earlier decision": {"Status": "rejected", "DecidedAt": first.Add(-time.Second)},
		"approved without profile": {"Status": "approved", "DecidedAt": first},
	}
	for name, fields := range invalid {
		t.Run(name, func(t *testing.T) {
			err := r.Transact(ctx, func(s *domain.State) error {
				c := candidateRecord(first)
				c["ID"] = "c2"
				for k, v := range fields {
					c[k] = v
				}
				putCandidate(t, s, "c2", c)
				return nil
			})
			if !errors.Is(err, ErrInvariant) {
				t.Fatalf("expected invariant rejection, got %v", err)
			}
		})
	}
	for _, field := range []string{"OwnerID", "Issuer", "UserID", "ClientID", "FirstSeenAt"} {
		t.Run("immutable "+field, func(t *testing.T) {
			err := r.Transact(ctx, func(s *domain.State) error {
				c := candidateRecord(first)
				if field == "FirstSeenAt" {
					c[field] = first.Add(time.Second)
				} else {
					c[field] = "changed"
				}
				putCandidate(t, s, "c1", c)
				return nil
			})
			if !errors.Is(err, ErrInvariant) {
				t.Fatalf("expected immutable rejection, got %v", err)
			}
		})
	}
	t.Run("reject and explicitly reopen", func(t *testing.T) {
		for _, status := range []string{"rejected", "pending"} {
			if err := r.Transact(ctx, func(s *domain.State) error {
				c := candidateRecord(first)
				c["Status"] = status
				if status == "rejected" {
					c["DecidedAt"] = first
				}
				putCandidate(t, s, "c1", c)
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		}
	})
	t.Run("approve atomically and preserve after disable and expiry", func(t *testing.T) {
		if err := r.Transact(ctx, func(s *domain.State) error {
			c := candidateRecord(first)
			c["Status"] = "approved"
			c["DecidedAt"] = first
			putCandidate(t, s, "c1", c)
			s.CallerProfiles["p1"] = domain.CallerProfile{ID: "p1", OwnerID: "u1", AgentID: "a1", Issuer: "https://issuer.example", UserID: "u1", ClientID: "new-client", Status: "disabled", ApprovedAt: first.Add(-2 * time.Hour), ExpiresAt: first.Add(-time.Hour)}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		for _, status := range []string{"pending", "rejected"} {
			err := r.Transact(ctx, func(s *domain.State) error {
				c := candidateRecord(first)
				c["Status"] = status
				if status == "rejected" {
					c["DecidedAt"] = first
				}
				putCandidate(t, s, "c1", c)
				return nil
			})
			if !errors.Is(err, ErrInvariant) {
				t.Fatalf("approved became %s: %v", status, err)
			}
		}
		err := r.Transact(ctx, func(s *domain.State) error { delete(s.CallerProfiles, "p1"); return nil })
		if !errors.Is(err, ErrInvariant) {
			t.Fatalf("approved candidate lost profile: %v", err)
		}
	})
}
func TestMemoryCallerCandidates(t *testing.T)   { exerciseCallerCandidates(t, NewMemory()) }
func TestPostgresCallerCandidates(t *testing.T) { exerciseCallerCandidates(t, testPostgres(t)) }
func exerciseConcurrentCandidates(t *testing.T, r domain.Repository) {
	seed(t, r)
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for _, id := range []string{"c1", "c2"} {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			errs <- r.Transact(context.Background(), func(s *domain.State) error {
				c := candidateRecord(s.Now)
				c["ID"] = id
				putCandidate(t, s, id, c)
				return nil
			})
		}(id)
	}
	wg.Wait()
	close(errs)
	successes, rejections := 0, 0
	for err := range errs {
		if err == nil {
			successes++
		} else if errors.Is(err, ErrInvariant) {
			rejections++
		} else {
			t.Fatal(err)
		}
	}
	if successes != 1 || rejections != 1 {
		t.Fatalf("successes=%d, invariant rejections=%d", successes, rejections)
	}
}
func TestMemoryConcurrentCallerCandidates(t *testing.T) { exerciseConcurrentCandidates(t, NewMemory()) }
func TestPostgresConcurrentCallerCandidates(t *testing.T) {
	exerciseConcurrentCandidates(t, testPostgres(t))
}
func TestMemoryCallerCandidateAliasBinding(t *testing.T) { exerciseCandidateAlias(t, NewMemory()) }
func TestPostgresCallerCandidateAliasBinding(t *testing.T) {
	exerciseCandidateAlias(t, testPostgres(t))
}
func exerciseCandidateAlias(t *testing.T, r domain.Repository) {
	seed(t, r)
	if err := r.Transact(context.Background(), func(s *domain.State) error {
		a := domain.IdentityAlias{Issuer: "https://broker.example/realms/toolbox", Subject: "broker-sub", OwnerID: "u1"}
		s.IdentityAliases[domain.IdentityKey(a.Issuer, a.Subject)] = a
		c := candidateRecord(s.Now)
		c["Issuer"], c["UserID"] = a.Issuer, a.Subject
		putCandidate(t, s, "c1", c)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := r.Transact(context.Background(), func(s *domain.State) error {
		b, _ := json.Marshal(s)
		var records map[string]any
		json.Unmarshal(b, &records)
		candidates, _ := records["CallerCandidates"].(map[string]any)
		if candidates == nil {
			t.Fatal("alias candidate missing")
		}
		c := candidates["c1"].(map[string]any)
		c["OwnerID"] = "u2"
		putCandidate(t, s, "c1", c)
		return nil
	}); !errors.Is(err, ErrInvariant) {
		t.Fatalf("alias candidate rebound: %v", err)
	}
}

func TestPostgresCallerCandidateDatabaseConstraints(t *testing.T) {
	p := testPostgres(t)
	seed(t, p)
	ctx := context.Background()
	first := time.Now().UTC().Truncate(time.Microsecond)
	c := candidateRecord(first)
	insert := func(c map[string]any) error {
		b, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		_, err = p.pool.Exec(ctx, "INSERT INTO caller_candidates(payload) VALUES($1)", b)
		return err
	}
	if err := insert(c); err != nil {
		t.Fatal(err)
	}
	reject := func(t *testing.T, q string, args ...any) {
		t.Helper()
		_, err := p.pool.Exec(ctx, q, args...)
		var pe *pgconn.PgError
		if !errors.As(err, &pe) || len(pe.Code) < 2 || pe.Code[:2] != "23" {
			t.Fatalf("expected SQL integrity rejection: %v", err)
		}
	}
	for _, field := range []string{"ID", "OwnerID", "Issuer", "UserID", "ClientID", "FirstSeenAt"} {
		t.Run("immutable "+field, func(t *testing.T) {
			value := "changed"
			if field == "FirstSeenAt" {
				value = first.Add(time.Second).Format(time.RFC3339Nano)
			}
			reject(t, "UPDATE caller_candidates SET payload=jsonb_set(payload,ARRAY[$1],to_jsonb($2::text)) WHERE id='c1'", field, value)
		})
	}
	t.Run("immutable nanosecond first seen", func(t *testing.T) {
		reject(t, "UPDATE caller_candidates SET payload=jsonb_set(payload,'{FirstSeenAt}',to_jsonb($1::text)) WHERE id='c1'", first.Add(time.Nanosecond).Format(time.RFC3339Nano))
	})
	for name, fields := range map[string]map[string]any{
		"unique tuple": {}, "owner identity": {"OwnerID": "u2"}, "unknown identity": {"UserID": "missing"}, "invalid status": {"Status": "active"}, "pending decision": {"DecidedAt": first}, "missing decision": {"Status": "rejected"}, "earlier decision": {"Status": "rejected", "DecidedAt": first.Add(-time.Second)}, "approved missing profile": {"Status": "approved", "DecidedAt": first}, "zero first": {"FirstSeenAt": time.Time{}}, "wrong string type": {"ClientID": 42}, "secret field": {"AccessToken": "secret"},
	} {
		t.Run(name, func(t *testing.T) {
			v := candidateRecord(first)
			v["ID"] = "c2"
			if name != "unique tuple" {
				v["ClientID"] = "other-client"
			}
			for k, x := range fields {
				v[k] = x
			}
			b, _ := json.Marshal(v)
			reject(t, "INSERT INTO caller_candidates(payload) VALUES($1)", b)
		})
	}
	if err := p.Transact(ctx, func(s *domain.State) error {
		c := s.CallerCandidates["c1"]
		c.Status = "rejected"
		c.DecidedAt = first
		s.CallerCandidates[c.ID] = c
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	reject(t, "UPDATE caller_candidates SET payload=jsonb_set(payload,'{DecidedAt}',to_jsonb($1::text)) WHERE id='c1'", first.Add(time.Second).Format(time.RFC3339Nano))
	if err := p.Transact(ctx, func(s *domain.State) error {
		c := s.CallerCandidates["c1"]
		c.Status = "pending"
		c.DecidedAt = time.Time{}
		s.CallerCandidates[c.ID] = c
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// Profile insertion and candidate approval may be performed in either order,
	// but the committed snapshot must bind approval to the exact owner identity.
	if err := p.Transact(ctx, func(s *domain.State) error {
		c := s.CallerCandidates["c1"]
		c.Status = "approved"
		c.DecidedAt = first
		s.CallerCandidates[c.ID] = c
		s.CallerProfiles["p1"] = domain.CallerProfile{ID: "p1", OwnerID: "u1", AgentID: "a1", Issuer: c.Issuer, UserID: c.UserID, ClientID: c.ClientID, Status: "disabled", ApprovedAt: first.Add(-2 * time.Hour), ExpiresAt: first.Add(-time.Hour)}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	reject(t, "UPDATE caller_candidates SET payload=payload || jsonb_build_object('Status','pending','DecidedAt','0001-01-01T00:00:00Z') WHERE id='c1'")
	reject(t, "DELETE FROM caller_profiles WHERE id='p1'")
}

func exerciseApprovedCandidateBinding(t *testing.T, r domain.Repository) {
	seed(t, r)
	ctx := context.Background()
	if err := r.Transact(ctx, func(s *domain.State) error {
		c := candidateRecord(s.Now)
		c["Status"], c["DecidedAt"] = "approved", s.Now
		putCandidate(t, s, "c1", c)
		s.CallerProfiles["p1"] = domain.CallerProfile{ID: "p1", OwnerID: "u1", AgentID: "a1", Issuer: "https://issuer.example", UserID: "u1", ClientID: "new-client", Status: "active", ApprovedAt: s.Now, ExpiresAt: s.Now.Add(time.Hour)}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	err := r.Transact(ctx, func(s *domain.State) error {
		p := s.CallerProfiles["p1"]
		delete(s.CallerProfiles, p.ID)
		p.ID, p.AgentID = "p2", "a3"
		s.Agents["a3"] = domain.Agent{ID: "a3", OwnerID: "u1", Status: "active"}
		s.CallerProfiles[p.ID] = p
		return nil
	})
	if !errors.Is(err, ErrInvariant) {
		t.Fatalf("approved identity rebound to a replacement profile/agent: %v", err)
	}
}
func TestMemoryApprovedCandidateCannotRebindAgent(t *testing.T) {
	exerciseApprovedCandidateBinding(t, NewMemory())
}
func TestPostgresApprovedCandidateCannotRebindAgent(t *testing.T) {
	exerciseApprovedCandidateBinding(t, testPostgres(t))
}

func seedApprovedCallerCandidate(t *testing.T, r domain.Repository) {
	t.Helper()
	seed(t, r)
	if err := r.Transact(context.Background(), func(s *domain.State) error {
		c := candidateRecord(s.Now)
		c["Status"], c["DecidedAt"] = "approved", s.Now
		putCandidate(t, s, "c1", c)
		s.CallerProfiles["p1"] = domain.CallerProfile{ID: "p1", OwnerID: "u1", AgentID: "a1", Issuer: "https://issuer.example", UserID: "u1", ClientID: "new-client", Status: "active", ApprovedAt: s.Now, ExpiresAt: s.Now.Add(time.Hour)}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func exerciseApprovedCandidateRetention(t *testing.T, newRepository func(*testing.T) domain.Repository) {
	for _, mode := range []string{"candidate only", "candidate and profile", "replace candidate profile and agent"} {
		t.Run(mode, func(t *testing.T) {
			r := newRepository(t)
			seedApprovedCallerCandidate(t, r)
			err := r.Transact(context.Background(), func(s *domain.State) error {
				c, p := s.CallerCandidates["c1"], s.CallerProfiles["p1"]
				delete(s.CallerCandidates, c.ID)
				if mode != "candidate only" {
					delete(s.CallerProfiles, p.ID)
				}
				if mode == "replace candidate profile and agent" {
					c.ID, p.ID, p.AgentID = "c2", "p2", "a3"
					s.CallerCandidates[c.ID], s.CallerProfiles[p.ID] = c, p
					s.Agents["a3"] = domain.Agent{ID: "a3", OwnerID: "u1", Status: "active"}
				}
				return nil
			})
			if !errors.Is(err, ErrInvariant) {
				t.Fatalf("approved candidate removal accepted (%s): %v", mode, err)
			}
			if err := r.Transact(context.Background(), func(s *domain.State) error {
				if s.CallerCandidates["c1"].Status != "approved" || s.CallerProfiles["p1"].AgentID != "a1" || len(s.CallerCandidates) != 1 || len(s.CallerProfiles) != 1 {
					t.Error("rejected removal did not preserve original approval binding")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestMemoryApprovedCandidateCannotBeRemoved(t *testing.T) {
	exerciseApprovedCandidateRetention(t, func(*testing.T) domain.Repository { return NewMemory() })
}

func TestPostgresApprovedCandidateCannotBeRemoved(t *testing.T) {
	exerciseApprovedCandidateRetention(t, func(t *testing.T) domain.Repository { return testPostgres(t) })
}

func TestPostgresApprovedCandidateSQLCannotBeRemoved(t *testing.T) {
	for _, mode := range []string{"candidate only", "candidate and profile", "replace candidate profile and agent"} {
		t.Run(mode, func(t *testing.T) {
			p := testPostgres(t)
			seedApprovedCallerCandidate(t, p)
			ctx := context.Background()
			var candidate, profile, agent []byte
			if err := p.Transact(ctx, func(s *domain.State) error {
				c, cp := s.CallerCandidates["c1"], s.CallerProfiles["p1"]
				c.ID, cp.ID, cp.AgentID = "c2", "p2", "a3"
				candidate, _ = json.Marshal(c)
				profile, _ = json.Marshal(cp)
				agent, _ = json.Marshal(domain.Agent{ID: "a3", OwnerID: "u1", Status: "active"})
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			tx, err := p.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			_, err = tx.Exec(ctx, "DELETE FROM caller_candidates WHERE id='c1'")
			if err == nil && mode != "candidate only" {
				_, err = tx.Exec(ctx, "DELETE FROM caller_profiles WHERE id='p1'")
			}
			if err == nil && mode == "replace candidate profile and agent" {
				for _, insert := range []struct {
					query   string
					payload []byte
				}{
					{"INSERT INTO agents(payload) VALUES($1)", agent},
					{"INSERT INTO caller_profiles(payload) VALUES($1)", profile},
					{"INSERT INTO caller_candidates(payload) VALUES($1)", candidate},
				} {
					if _, err = tx.Exec(ctx, insert.query, insert.payload); err != nil {
						break
					}
				}
			}
			if err == nil {
				err = tx.Commit(ctx)
			}
			var pe *pgconn.PgError
			if !errors.As(err, &pe) || pe.Code != "23514" {
				t.Fatalf("expected SQL approved-candidate retention rejection (%s): %v", mode, err)
			}
		})
	}
}
