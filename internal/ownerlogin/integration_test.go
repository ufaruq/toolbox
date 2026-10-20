package ownerlogin

import (
	"bytes"
	"context"
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/ufaruq/toolbox/internal/domain"
	"github.com/ufaruq/toolbox/internal/security"
	"github.com/ufaruq/toolbox/internal/store"
	"github.com/ufaruq/toolbox/internal/testutil/oidcidp"
	"github.com/ufaruq/toolbox/internal/tokens"
)

// Exercise the new state machine against both actual adapters, including their
// SQL transition constraints and current-version secret cleanup.
func TestOwnerLoginRealStores(t *testing.T) {
	dsn, address := os.Getenv("TOOLBOX_TEST_DATABASE_URL"), os.Getenv("TOOLBOX_TEST_OPENBAO_ADDR")
	if dsn == "" || address == "" {
		t.Skip("set both disposable PostgreSQL and OpenBao test settings")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal("connect disposable database")
	}
	t.Cleanup(func() { _ = admin.Close(context.Background()) })
	schema := "ownerlogin_" + strings.ReplaceAll(security.ID(), "-", "")
	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal("create isolated test schema")
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		_, _ = admin.Exec(cleanup, "DROP SCHEMA "+schema+" CASCADE")
	})
	dbConfig, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal("parse disposable database configuration")
	}
	dbConfig.RuntimeParams["search_path"] = schema
	repo, err := store.OpenPostgres(ctx, dbConfig.ConnString())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(repo.Close)
	if err = repo.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	secrets, err := tokens.NewOpenBaoFixture(tokens.OpenBaoConfig{Address: address, Mount: "secret", Token: os.Getenv("TOOLBOX_TEST_OPENBAO_TOKEN")})
	if err != nil {
		t.Fatal(err)
	}
	idp := oidcidp.New(t)
	provider, err := NewProvider(ctx, ProviderConfig{Issuer: idp.Issuer, ClientID: idp.ClientID, ClientSecret: idp.ClientSecret, RedirectURI: "http://127.0.0.1:18090/auth/oidc/callback"}, idp.TLSClient())
	if err != nil {
		t.Fatal(err)
	}
	cfg := ServiceConfig{Issuer: idp.Issuer, ClientID: idp.ClientID, RedirectURI: "http://127.0.0.1:18090/auth/oidc/callback", Pepper: bytes.Repeat([]byte("p"), 32)}
	login, err := NewService(repo, secrets, provider, cfg)
	if err != nil {
		t.Fatal(err)
	}
	complete := func(service *Service, previous string) (StartResult, LoginResult) {
		t.Helper()
		started, err := service.Start(ctx, previous)
		if err != nil {
			t.Fatal(err)
		}
		u, err := url.Parse(started.AuthorizationURL)
		if err != nil {
			t.Fatal("parse authorization URL")
		}
		state := u.Query().Get("state")
		id, _, err := security.CredentialParts(state)
		if err != nil {
			t.Fatal("parse transaction key")
		}
		var secret loginSecret
		if _, err = secrets.GetJSON(ctx, ownerSecretPath(id), &secret); err != nil {
			t.Fatal(err)
		}
		code := idp.Authorize(t, u.Query().Get("nonce"), secret.Verifier)
		result, err := service.Complete(ctx, state, code, started.BrowserToken)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = secrets.GetJSON(ctx, ownerSecretPath(id), &secret); !errors.Is(err, tokens.ErrNotFound) {
			t.Fatal("completed verifier remains visible")
		}
		if _, err = service.Complete(ctx, state, code, started.BrowserToken); err == nil {
			t.Fatal("real-store callback replay accepted")
		}
		return started, result
	}
	_, first := complete(login, "")
	restarted, err := NewService(repo, secrets, provider, cfg)
	if err != nil {
		t.Fatal(err)
	}
	started, second := complete(restarted, security.Hash(first.SessionToken))
	if first.UserID != second.UserID || first.SessionToken == second.SessionToken {
		t.Fatal("restart changed identity or reused a session")
	}
	if second.CSRFToken != security.KeyedHash(cfg.Pepper, second.SessionToken) {
		t.Fatal("stored session CSRF contract changed")
	}
	if err = repo.Transact(ctx, func(st *domain.State) error {
		if st.Now.Before(st.Sessions[security.Hash(first.SessionToken)].ExpiresAt) || !st.Now.Before(st.Sessions[security.Hash(second.SessionToken)].ExpiresAt) {
			t.Fatal("incorrect real-store rotation")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// This also exercises the completed-login relationship used when logout wins
	// before the callback's Set-Cookie response has reached its browser.
	if err = restarted.Logout(ctx, "", started.BrowserToken); err != nil {
		t.Fatal(err)
	}
	if err = restarted.Cleanup(ctx); err != nil {
		t.Fatal(err)
	}
	if err = repo.Transact(ctx, func(st *domain.State) error {
		if st.Now.Before(st.Sessions[security.Hash(second.SessionToken)].ExpiresAt) {
			t.Fatal("replacement survived logout")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if idp.ExchangeCount() != 2 {
		t.Fatal("unexpected real-store exchange count")
	}
}
