package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/ufaruq/toolbox/internal/secretstore"
)

func TestRuntimePermissions(t *testing.T) {
	p := testPostgres(t)
	ctx := context.Background()
	seed(t, p)
	var schema string
	if err := p.pool.QueryRow(ctx, "SELECT current_schema()").Scan(&schema); err != nil {
		t.Fatal(err)
	}
	secrets := schema + "_sec"
	if err := secretstore.Migrate(ctx, p.pool, secrets); err != nil {
		t.Fatal(err)
	}
	suffix := fmt.Sprint(time.Now().UnixNano())
	roles := Roles{API: "api_" + suffix, Cleanup: "cleanup_" + suffix, Retention: "retention_" + suffix}
	for _, role := range []string{roles.API, roles.Cleanup, roles.Retention} {
		if _, err := p.pool.Exec(ctx, "CREATE ROLE "+pgx.Identifier{role}.Sanitize()); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = p.pool.Exec(ctx, "DROP SCHEMA "+pgx.Identifier{secrets}.Sanitize()+" CASCADE")
		for _, r := range []string{roles.API, roles.Cleanup, roles.Retention} {
			_, _ = p.pool.Exec(ctx, "DROP OWNED BY "+pgx.Identifier{r}.Sanitize())
			_, _ = p.pool.Exec(ctx, "DROP ROLE "+pgx.Identifier{r}.Sanitize())
		}
	})
	if err := p.ConfigureRoles(ctx, schema, secrets, roles); err != nil {
		t.Fatal(err)
	}
	for _, r := range []string{roles.API, roles.Cleanup} {
		for _, sql := range []string{"CREATE TABLE forbidden(x int)", "TRUNCATE audit_events", "DELETE FROM audit_events", "UPDATE audit_events SET payload=payload", "DELETE FROM grants", "ALTER TABLE agents DISABLE TRIGGER ALL", "CREATE ROLE forbidden", "DELETE FROM " + pgx.Identifier{secrets}.Sanitize() + ".secret_versions"} {
			t.Run(r+sql, func(t *testing.T) {
				tx, err := p.pool.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer rollback(tx)
				if _, err = tx.Exec(ctx, "SET LOCAL ROLE "+pgx.Identifier{r}.Sanitize()); err != nil {
					t.Fatal(err)
				}
				if _, err = tx.Exec(ctx, sql); err == nil {
					t.Fatal("forbidden operation allowed:", sql)
				}
			})
		}
	}
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollback(tx)
	if _, err = tx.Exec(ctx, "SET LOCAL ROLE "+pgx.Identifier{roles.API}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	if _, err = load(ctx, tx); err != nil {
		t.Fatal("runtime cannot load metadata", err)
	}
}

func TestPreflightRejectsPrivilegedOwnerAndUnknownMigrations(t *testing.T) {
	p := testPostgres(t)
	ctx := context.Background()
	if err := p.RuntimeSafe(ctx); err == nil {
		t.Fatal("database owner accepted as runtime")
	}
	if err := p.CheckMigrations(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := p.pool.Exec(ctx, "INSERT INTO toolbox_migrations(name,checksum) VALUES('999_future.sql','future')"); err != nil {
		t.Fatal(err)
	}
	if err := p.CheckMigrations(ctx); err == nil {
		t.Fatal("old binary accepted unknown migration")
	}
}
