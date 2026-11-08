package identitylink

import (
	"context"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/ufaruq/toolbox/internal/domain"
	"github.com/ufaruq/toolbox/internal/security"
	"github.com/ufaruq/toolbox/internal/store"
)

func TestVerifiedLinkPostgres(t *testing.T) {
	dsn := os.Getenv("TOOLBOX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TOOLBOX_TEST_DATABASE_URL to run PostgreSQL integration tests")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := "identity_link_" + security.ID()
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
		admin.Close(ctx)
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec(ctx, "DROP SCHEMA "+quoted+" CASCADE"); err != nil {
			t.Error(err)
		}
		_ = admin.Close(ctx)
	})
	scopedDSN := dsn
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		parsed, err := url.Parse(dsn)
		if err != nil {
			t.Fatal(err)
		}
		query := parsed.Query()
		query.Set("search_path", schema)
		parsed.RawQuery = query.Encode()
		scopedDSN = parsed.String()
	} else {
		scopedDSN += " search_path=" + schema
	}
	repo, err := store.OpenPostgres(ctx, scopedDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(repo.Close)
	if err = repo.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err = repo.Transact(ctx, func(st *domain.State) error {
		st.Users["owner"] = domain.User{ID: "owner", Issuer: "https://old.example/", Subject: "old-sub", Status: "active"}
		st.Agents["agent"] = domain.Agent{ID: "agent", OwnerID: "owner", Status: "active"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	f := newFixture(t)
	l, err := New(ctx, f.config())
	if err != nil {
		t.Fatal(err)
	}
	report, err := l.Link(ctx, repo, false)
	if err != nil || report.Linked != 1 {
		t.Fatalf("dry run: %+v %v", report, err)
	}
	if err = repo.Transact(ctx, func(st *domain.State) error {
		if len(st.IdentityAliases) != 0 || len(st.Audits) != 0 {
			t.Fatal("dry run wrote to PostgreSQL")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	report, err = l.Link(ctx, repo, true)
	if err != nil || report.Linked != 1 {
		t.Fatalf("apply: %+v %v", report, err)
	}
	reopened, err := store.OpenPostgres(ctx, scopedDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err = reopened.Transact(ctx, func(st *domain.State) error {
		u, ok := domain.ResolveIdentity(st, f.config().RealmIssuer, "kc-owner")
		if !ok || u.ID != "owner" || u.Subject != "old-sub" {
			t.Fatalf("persisted owner continuity: %+v %v", u, ok)
		}
		if st.Agents["agent"].OwnerID != "owner" || len(st.IdentityAliases) != 1 || len(st.Audits) != 1 || st.Audits[0].Action != "owner.identity.linked" {
			t.Fatal("persisted migration or ownership differs")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	report, err = l.Link(ctx, reopened, true)
	if err != nil || report.Linked != 0 || report.AlreadyLinked != 1 {
		t.Fatalf("repeat: %+v %v", report, err)
	}
}
