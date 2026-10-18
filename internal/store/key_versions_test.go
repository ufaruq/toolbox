package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ufaruq/toolbox/internal/domain"
)

func TestKeyVersionMigrationFromOriginalSchema(t *testing.T) {
	dsn := os.Getenv("TOOLBOX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TOOLBOX_TEST_DATABASE_URL for migration upgrade test")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := fmt.Sprintf("key_upgrade_%d", time.Now().UnixNano())
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = admin.Exec(ctx, "DROP SCHEMA "+quoted+" CASCADE"); _ = admin.Close(ctx) })
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	p := &Postgres{pool: pool, config: cfg.ConnConfig.Copy()}
	t.Cleanup(p.Close)
	body, err := migrations.ReadFile("migrations/001_initial.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, string(body)); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	if _, err = pool.Exec(ctx, "CREATE TABLE toolbox_migrations(name text PRIMARY KEY, checksum text NOT NULL, applied_at timestamptz NOT NULL DEFAULT clock_timestamp())"); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, "INSERT INTO toolbox_migrations(name,checksum) VALUES('001_initial.sql',$1)", hex.EncodeToString(sum[:])); err != nil {
		t.Fatal(err)
	}
	for _, sql := range []string{
		`INSERT INTO users(payload) VALUES('{"ID":"u","Issuer":"https://id.example","Subject":"s","Status":"active"}')`,
		`INSERT INTO agents(payload) VALUES('{"ID":"a","OwnerID":"u","Name":"agent","Status":"active"}')`,
		`INSERT INTO credentials(payload) VALUES('{"ID":"c","AgentID":"a","Hash":"hash","Status":"active","ExpiresAt":"2030-01-01T00:00:00Z"}')`,
		`INSERT INTO sessions(payload) VALUES('{"ID":"s","UserID":"u","CSRFHash":"hash","ExpiresAt":"2030-01-01T00:00:00Z"}')`,
	} {
		if _, err = pool.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	if err = p.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err = p.Transact(ctx, func(st *domain.State) error {
		if st.Credentials["c"].PepperID != "legacy" || st.Sessions["s"].PepperID != "legacy" {
			t.Fatal("legacy key identifiers lost")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err = p.Migrate(ctx); err != nil {
		t.Fatal("migration not idempotent", err)
	}
}
