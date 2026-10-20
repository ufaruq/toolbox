package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/ufaruq/toolbox/internal/domain"
)

func TestMCPUpgradePreservesExistingOwnerSessionAndConnection(t *testing.T) {
	for _, released := range []int{3, 5} {
		t.Run(fmt.Sprintf("migration_%03d", released), func(t *testing.T) { exerciseMCPUpgrade(t, released) })
	}
}

func exerciseMCPUpgrade(t *testing.T, released int) {
	ctx := context.Background()
	now := time.Now().UTC()
	user := domain.User{ID: "existing-owner", Issuer: "https://tenant.okta.example", Subject: "00uExisting", Status: "active"}
	session := domain.Session{ID: "existing-session", UserID: user.ID, CSRFHash: "synthetic-csrf", ExpiresAt: now.Add(time.Hour)}
	connection := domain.Connection{ID: "existing-google", OwnerID: user.ID, Provider: "google_drive", Subject: "google-subject", ClientID: "google-client", Status: "active", Epoch: 7, SecretVersion: 4, Scopes: []string{"openid", "email", domain.DriveScope}}
	p := testPostgresSetup(t, func(p *Postgres) {
		if _, err := p.pool.Exec(ctx, "CREATE TABLE toolbox_migrations(name text PRIMARY KEY, checksum text NOT NULL, applied_at timestamptz NOT NULL DEFAULT clock_timestamp())"); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"001_initial.sql", "002_owner_login.sql", "003_owner_login_descendants.sql", "004_caller_profiles.sql", "005_audit_caller_attribution.sql"}[:released] {
			body, err := migrations.ReadFile("migrations/" + name)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = p.pool.Exec(ctx, string(body)); err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(body)
			if _, err = p.pool.Exec(ctx, "INSERT INTO toolbox_migrations(name,checksum) VALUES($1,$2)", name, hex.EncodeToString(sum[:])); err != nil {
				t.Fatal(err)
			}
		}
		for _, row := range []struct {
			table string
			value any
		}{{"users", user}, {"sessions", map[string]any{"ID": session.ID, "UserID": session.UserID, "CSRFHash": session.CSRFHash, "ExpiresAt": session.ExpiresAt}}, {"connections", connection}} {
			payload, err := json.Marshal(row.value)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = p.pool.Exec(ctx, "INSERT INTO "+row.table+"(payload) VALUES($1)", payload); err != nil {
				t.Fatal(err)
			}
		}
		if released == 5 {
			login := ownerLoginRecord(now)
			login.ID, login.PreviousSessionID = "existing-login", session.ID
			for _, row := range []struct {
				table string
				value any
			}{
				{"agents", domain.Agent{ID: "existing-agent", OwnerID: user.ID, Name: "Saved agent", Status: "active"}},
				{"caller_profiles", domain.CallerProfile{ID: "existing-profile", OwnerID: user.ID, AgentID: "existing-agent", Issuer: user.Issuer, UserID: user.Subject, ClientID: "code-client", Label: "Saved agent", Status: "active", Tools: []string{domain.Tool}, ApprovedAt: now, ExpiresAt: now.Add(time.Hour)}},
				{"owner_login_transactions", login},
			} {
				payload, err := json.Marshal(row.value)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := p.pool.Exec(ctx, "INSERT INTO "+row.table+"(payload) VALUES($1)", payload); err != nil {
					t.Fatal(err)
				}
			}
		}
	})
	session.PepperID = "legacy"
	if err := p.CheckSchema(ctx); err == nil {
		t.Fatal("old schema advertised MCP readiness")
	}
	if err := p.Migrate(ctx); err != nil {
		t.Fatalf("main-to-MCP upgrade failed: %v", err)
	}
	if err := p.CheckSchema(ctx); err != nil {
		t.Fatal(err)
	}
	if err := p.Transact(ctx, func(st *domain.State) error {
		if st.Users[user.ID] != user || st.Sessions[session.ID] != session {
			t.Fatal("existing owner/session changed during upgrade")
		}
		c := st.Connections[connection.ID]
		if c.OwnerID != user.ID || c.Subject != connection.Subject || c.Epoch != 7 || c.SecretVersion != 4 || len(st.CallerProfiles) != map[bool]int{true: 1, false: 0}[released == 5] {
			t.Fatal("Google connection or ownership changed during upgrade")
		}
		if released == 5 {
			profile := st.CallerProfiles["existing-profile"]
			if profile.Label != "Saved agent" || profile.Status != "active" || st.OwnerLogins["existing-login"].PreviousSessionID != session.ID {
				t.Fatal("existing MCP client or owner login lost during deployment upgrade")
			}
		}
		st.Agents["new-mcp-agent"] = domain.Agent{ID: "new-mcp-agent", OwnerID: user.ID, Status: "active"}
		st.CallerProfiles["new-profile"] = domain.CallerProfile{ID: "new-profile", OwnerID: user.ID, AgentID: "new-mcp-agent", Issuer: user.Issuer, UserID: user.Subject, ClientID: "new-code-client", Status: "active", Tools: []string{domain.Tool}, ApprovedAt: st.Now, ExpiresAt: st.Now.Add(time.Hour)}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := p.Migrate(ctx); err != nil {
		t.Fatalf("upgrade is not idempotent: %v", err)
	}
}
