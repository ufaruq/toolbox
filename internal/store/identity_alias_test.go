package store

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/ufaruq/toolbox/internal/domain"
)

func exerciseIdentityAliases(t *testing.T, r domain.Repository) {
	ctx := context.Background()
	a := domain.IdentityAlias{Issuer: "https://broker.example/realms/toolbox", Subject: "broker-sub", OwnerID: "u1"}
	k := domain.IdentityKey(a.Issuer, a.Subject)
	if err := r.Transact(ctx, func(s *domain.State) error {
		s.Users["u1"] = domain.User{ID: "u1", Issuer: "https://okta.example", Subject: "old-sub", Status: "active"}
		s.Users["u2"] = domain.User{ID: "u2", Issuer: "https://google.example", Subject: "other-sub", Status: "active"}
		s.IdentityAliases[k] = a
		s.Agents["alias-agent"] = domain.Agent{ID: "alias-agent", OwnerID: "u1", Status: "active"}
		s.CallerProfiles["alias-caller"] = domain.CallerProfile{ID: "alias-caller", OwnerID: "u1", AgentID: "alias-agent", Issuer: a.Issuer, UserID: a.Subject, ClientID: "mcp", Status: "active", ApprovedAt: s.Now, ExpiresAt: s.Now.Add(time.Hour)}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*domain.State){
		"alias reassignment": func(s *domain.State) { v := a; v.OwnerID = "u2"; s.IdentityAliases[k] = v },
		"alias deletion":     func(s *domain.State) { delete(s.IdentityAliases, k) },
		"unknown owner": func(s *domain.State) {
			v := a
			v.Subject = "missing"
			v.OwnerID = "missing"
			s.IdentityAliases[domain.IdentityKey(v.Issuer, v.Subject)] = v
		},
		"alias over primary": func(s *domain.State) {
			v := domain.IdentityAlias{Issuer: "https://okta.example", Subject: "old-sub", OwnerID: "u2"}
			s.IdentityAliases[domain.IdentityKey(v.Issuer, v.Subject)] = v
		},
		"primary over alias": func(s *domain.State) {
			s.Users["u3"] = domain.User{ID: "u3", Issuer: a.Issuer, Subject: a.Subject, Status: "active"}
		},
		"wrong key": func(s *domain.State) { v := a; v.Subject = "different"; s.IdentityAliases["bad"] = v },
		"caller foreign owner": func(s *domain.State) {
			p := s.CallerProfiles["alias-caller"]
			p.OwnerID = "u2"
			s.CallerProfiles[p.ID] = p
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := r.Transact(ctx, func(s *domain.State) error { mutate(s); return nil }); !errors.Is(err, ErrInvariant) {
				t.Fatalf("got %v", err)
			}
		})
	}
	if err := r.Transact(ctx, func(s *domain.State) error {
		u, ok := domain.ResolveIdentity(s, a.Issuer, a.Subject)
		if !ok || u.ID != "u1" || u.Issuer != "https://okta.example" {
			t.Fatal("lost immutable identity")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestMemoryIdentityAliases(t *testing.T)   { exerciseIdentityAliases(t, NewMemory()) }
func TestPostgresIdentityAliases(t *testing.T) { exerciseIdentityAliases(t, testPostgres(t)) }

func TestPostgresIdentityAliasConstraints(t *testing.T) {
	p := testPostgres(t)
	exerciseIdentityAliases(t, p)
	ctx := context.Background()
	reject := func(t *testing.T, q string, args ...any) {
		t.Helper()
		_, err := p.pool.Exec(ctx, q, args...)
		var pe *pgconn.PgError
		if !errors.As(err, &pe) || len(pe.Code) < 2 || pe.Code[:2] != "23" {
			t.Fatalf("expected integrity rejection: %v", err)
		}
	}
	for name, q := range map[string]string{
		"no alias update":         "UPDATE identity_aliases SET payload=jsonb_set(payload,'{OwnerID}','\"u2\"')",
		"no alias delete":         "DELETE FROM identity_aliases",
		"no alias truncate":       "TRUNCATE identity_aliases CASCADE",
		"no primary update":       "UPDATE users SET payload=jsonb_set(payload,'{Subject}','\"changed\"') WHERE id='u2'",
		"no binding delete":       "DELETE FROM identity_bindings WHERE owner_id='u2'",
		"no manufactured binding": "INSERT INTO identity_bindings(issuer,subject,owner_id) VALUES('https://invented.example','invented','u2')",
	} {
		t.Run(name, func(t *testing.T) { reject(t, q) })
	}
	t.Run("primary over alias", func(t *testing.T) {
		b, _ := json.Marshal(domain.User{ID: "u3", Issuer: "https://broker.example/realms/toolbox", Subject: "broker-sub", Status: "active"})
		reject(t, "INSERT INTO users(payload) VALUES($1)", b)
	})
	t.Run("alias caller foreign owner", func(t *testing.T) {
		if err := p.Transact(ctx, func(st *domain.State) error {
			st.Agents["other-agent"] = domain.Agent{ID: "other-agent", OwnerID: "u2", Status: "active"}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(domain.CallerProfile{ID: "foreign-caller", OwnerID: "u2", AgentID: "other-agent", Issuer: "https://broker.example/realms/toolbox", UserID: "broker-sub", ClientID: "foreign", Status: "active", ApprovedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)})
		reject(t, "INSERT INTO caller_profiles(payload) VALUES($1)", b)
	})
	for name, a := range map[string]domain.IdentityAlias{
		"unknown owner":                {Issuer: "https://broker.example", Subject: "missing", OwnerID: "missing"},
		"primary collision":            {Issuer: "https://okta.example", Subject: "old-sub", OwnerID: "u2"},
		"same owner primary collision": {Issuer: "https://okta.example", Subject: "old-sub", OwnerID: "u1"},
	} {
		t.Run(name, func(t *testing.T) {
			b, _ := json.Marshal(a)
			reject(t, "INSERT INTO identity_aliases(payload) VALUES($1)", b)
		})
	}
	if err := p.Transact(ctx, func(s *domain.State) error {
		if len(s.IdentityAliases) != 1 {
			t.Fatal("aliases not persisted")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
