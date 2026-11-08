package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/ufaruq/toolbox/internal/domain"
)

func TestIdentityAliasUpgradePreservesLegacyCallerAndOwner(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	u := domain.User{ID: "legacy-owner", Issuer: "https://okta.example", Subject: "old-sub", Status: "active"}
	a := domain.Agent{ID: "legacy-agent", OwnerID: u.ID, Name: "Legacy", Status: "active"}
	p := domain.CallerProfile{ID: "legacy-profile", OwnerID: u.ID, AgentID: a.ID, Issuer: u.Issuer, UserID: u.Subject, ClientID: "legacy-client", Status: "active", Tools: []string{domain.Tool}, ApprovedAt: now, ExpiresAt: now.Add(time.Hour)}
	repo := testPostgresSetup(t, func(repo *Postgres) {
		if _, err := repo.pool.Exec(ctx, "CREATE TABLE toolbox_migrations(name text PRIMARY KEY, checksum text NOT NULL, applied_at timestamptz NOT NULL DEFAULT clock_timestamp())"); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"001_initial.sql", "002_owner_login.sql", "003_owner_login_descendants.sql", "004_caller_profiles.sql", "005_audit_caller_attribution.sql"} {
			body, err := migrations.ReadFile("migrations/" + name)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = repo.pool.Exec(ctx, string(body)); err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(body)
			if _, err = repo.pool.Exec(ctx, "INSERT INTO toolbox_migrations(name,checksum) VALUES($1,$2)", name, hex.EncodeToString(sum[:])); err != nil {
				t.Fatal(err)
			}
		}
		for _, row := range []struct {
			table string
			value any
		}{{"users", u}, {"agents", a}, {"caller_profiles", p}} {
			body, err := json.Marshal(row.value)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = repo.pool.Exec(ctx, "INSERT INTO "+row.table+"(payload) VALUES($1)", body); err != nil {
				t.Fatal(err)
			}
		}
	})
	if err := repo.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := repo.Transact(ctx, func(st *domain.State) error {
		if st.Users[u.ID] != u || st.Agents[a.ID] != a || !reflect.DeepEqual(st.CallerProfiles[p.ID], p) || len(st.IdentityAliases) != 0 {
			t.Fatal("upgrade altered existing identities or approval")
		}
		alias := domain.IdentityAlias{Issuer: "https://keycloak.example/realms/toolbox", Subject: "kc-sub", OwnerID: u.ID}
		st.IdentityAliases[domain.IdentityKey(alias.Issuer, alias.Subject)] = alias
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := repo.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
}
