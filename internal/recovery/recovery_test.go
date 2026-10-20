package recovery

import (
	"context"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ufaruq/toolbox/internal/domain"
	"github.com/ufaruq/toolbox/internal/security"
	"github.com/ufaruq/toolbox/internal/store"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

func TestInvalidateRestoredAuthorityIsIdempotent(t *testing.T) {
	exerciseInvalidation(t, store.NewMemory())
}
func TestPostgresInvalidateRestoredAuthority(t *testing.T) {
	dsn := os.Getenv("TOOLBOX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TOOLBOX_TEST_DATABASE_URL for actual PostgreSQL recovery")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	schema := "recovery_" + strings.ReplaceAll(security.ID(), "-", "")
	name := pgx.Identifier{schema}.Sanitize()
	if _, err := pool.Exec(ctx, "CREATE SCHEMA "+name); err != nil {
		t.Fatal(err)
	}
	defer pool.Exec(ctx, "DROP SCHEMA "+name+" CASCADE")
	config, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	query := config.Query()
	query.Set("search_path", schema)
	config.RawQuery = query.Encode()
	repo, err := store.OpenPostgres(ctx, config.String())
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	if err := repo.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	exerciseInvalidation(t, repo)
}
func exerciseInvalidation(t *testing.T, repo domain.Repository) {
	t.Helper()
	ctx := context.Background()
	err := repo.Transact(ctx, func(st *domain.State) error {
		st.Users["u"] = domain.User{ID: "u", Issuer: "fixture", Subject: "u", Status: "active"}
		st.Agents["a"] = domain.Agent{ID: "a", OwnerID: "u", Status: "active"}
		st.Credentials["k"] = domain.Credential{ID: "k", AgentID: "a", Hash: "hash", Status: "active", ExpiresAt: st.Now.Add(time.Hour)}
		st.Sessions["s"] = domain.Session{ID: "s", UserID: "u", CSRFHash: "hash", ExpiresAt: st.Now.Add(time.Hour)}
		st.Connections["c"] = domain.Connection{ID: "c", OwnerID: "u", Provider: "google_drive", Status: "active", Epoch: 1}
		st.Resources["c:f"] = domain.Resource{ConnectionID: "c", FileID: "f"}
		st.Grants["g"] = domain.Grant{ID: "g", OwnerID: "u", AgentID: "a", ConnectionID: "c", Tool: domain.Tool, Action: domain.Action, FileID: "f", Epoch: 1, Version: 1, NotBefore: st.Now, ExpiresAt: st.Now.Add(time.Hour)}
		st.OAuth["o"] = domain.OAuthTransaction{ID: "o", OwnerID: "u", SessionID: "s", StateHash: "hash", NonceHash: "hash", SecretRef: "oauth-transactions/o", ConnectionID: "c", ExpiresAt: st.Now.Add(time.Minute)}
		st.CallerProfiles["p"] = domain.CallerProfile{ID: "p", OwnerID: "u", AgentID: "a", Issuer: "fixture", UserID: "u", ClientID: "code", Label: "Restored client", Status: "active", Tools: []string{domain.Tool}, ApprovedAt: st.Now, ExpiresAt: st.Now.Add(time.Hour)}
		st.OwnerLogins["login"] = domain.OwnerLoginTransaction{ID: "login", StateHash: "state", BrowserHash: "browser", NonceHash: "nonce", SecretRef: "owner-login/login", Issuer: "https://issuer.example", ClientID: "owner", RedirectURI: "http://127.0.0.1:8080/auth/oidc/callback", PreviousSessionID: "s", Status: "pending", ExpiresAt: st.Now.Add(time.Minute)}
		st.Requests["request"] = domain.Request{ID: "request", AgentID: "a", FileID: "f", Tool: domain.Tool, Digest: "digest", Status: "pending", Version: 1, DurationSeconds: 60, RequestedExpiry: st.Now.Add(time.Minute), ExpiresAt: st.Now.Add(time.Minute)}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	r, err := Invalidate(ctx, repo)
	if err != nil || r.Connections != 1 || r.Credentials != 1 || r.Callers != 1 || r.OwnerLogins != 1 || r.Requests != 1 {
		t.Fatal(r, err)
	}
	if err := repo.Transact(ctx, func(st *domain.State) error {
		if st.CallerProfiles["p"].Status != "disabled" || st.Agents["a"].Status != "disabled" || st.OwnerLogins["login"].Status != "cancelled" || st.Requests["request"].Status != "cancelled" {
			t.Fatal("restored MCP client or in-progress authorization remained usable")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	r, err = Invalidate(ctx, repo)
	if err != nil || r != (Report{}) {
		t.Fatal(r, err)
	}
	_ = repo.Transact(ctx, func(st *domain.State) error {
		if st.Connections["c"].Epoch != 2 || st.Connections["c"].Status != "disconnecting" || st.Grants["g"].RevokedAt == nil || st.Credentials["k"].Status != "revoked" || st.Sessions["s"].ExpiresAt.After(st.Now) || len(st.Cleanup) != 1 || len(st.OAuth) != 1 || len(st.Audits) != 1 {
			t.Fatal("authority restored or references destroyed")
		}
		return nil
	})
}
