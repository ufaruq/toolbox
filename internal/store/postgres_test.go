package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ufaruq/toolbox/internal/domain"
)

func testPostgres(t *testing.T) *Postgres {
	t.Helper()
	dsn := os.Getenv("TOOLBOX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TOOLBOX_TEST_DATABASE_URL to run PostgreSQL integration tests")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := fmt.Sprintf("toolbox_test_%d", time.Now().UnixNano())
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
		admin.Close(ctx)
		t.Fatal(err)
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	cfg.MaxConns = 8
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	p := &Postgres{pool: pool, config: cfg.ConnConfig.Copy()}
	t.Cleanup(func() {
		p.Close()
		_, err := admin.Exec(ctx, "DROP SCHEMA "+quoted+" CASCADE")
		if err != nil {
			t.Error(err)
		}
		admin.Close(ctx)
	})
	if err = p.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err = p.Migrate(ctx); err != nil {
		t.Fatalf("idempotent migration: %v", err)
	}
	return p
}
func TestPostgresRepository(t *testing.T) { p := testPostgres(t); exerciseRepository(t, p) }
func TestPostgresDatabaseConstraints(t *testing.T) {
	p := testPostgres(t)
	seed(t, p)
	ctx := context.Background()
	reject := func(t *testing.T, query string, args ...any) {
		t.Helper()
		_, err := p.pool.Exec(ctx, query, args...)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || len(pgErr.Code) < 2 || pgErr.Code[:2] != "23" {
			t.Fatalf("expected DB integrity rejection, got %v", err)
		}
	}
	for name, query := range map[string]string{
		"grant immutable":            "UPDATE grants SET payload=jsonb_set(payload,'{FileID}','\"other\"') WHERE id='g1'",
		"grant no delete":            "DELETE FROM grants WHERE id='g1'",
		"audit no update":            "UPDATE audit_events SET payload=jsonb_set(payload,'{Outcome}','\"changed\"')",
		"audit no delete":            "DELETE FROM audit_events",
		"audit no truncate":          "TRUNCATE audit_events",
		"approval immutable":         "UPDATE delegation_requests SET payload=jsonb_set(payload,'{GrantID}','\"\"') WHERE id='r1'",
		"connection owner immutable": "UPDATE connections SET payload=jsonb_set(payload,'{OwnerID}','\"u2\"') WHERE id='c1'",
		"connection epoch monotonic": "UPDATE connections SET payload=jsonb_set(payload,'{Epoch}','0') WHERE id='c1'",
		"resource owner FK":          "UPDATE resources SET owner_id='u2' WHERE connection_id='c1'",
		"unexpected secret fields":   "UPDATE connections SET payload=payload || '{\"AccessToken\":\"canary\"}'::jsonb WHERE id='c1'",
	} {
		t.Run(name, func(t *testing.T) { reject(t, query) })
	}
	var state *domain.State
	if err := p.Transact(ctx, func(s *domain.State) error { state = s; return nil }); err != nil {
		t.Fatal(err)
	}
	t.Run("cross owner grant FK", func(t *testing.T) {
		g := state.Grants["g1"]
		g.ID = "g2"
		g.AgentID = "a2"
		b, _ := json.Marshal(g)
		reject(t, "INSERT INTO grants(payload) VALUES($1)", b)
	})
	t.Run("wrong resource FK", func(t *testing.T) {
		g := state.Grants["g1"]
		g.ID = "g2"
		g.FileID = "f2"
		b, _ := json.Marshal(g)
		reject(t, "INSERT INTO grants(payload) VALUES($1)", b)
	})
	t.Run("unique approval", func(t *testing.T) {
		r := state.Requests["r1"]
		r.ID = "r2"
		b, _ := json.Marshal(r)
		reject(t, "INSERT INTO delegation_requests(payload,owner_id) VALUES($1,'u1')", b)
	})
	t.Run("approval bound to grant resource", func(t *testing.T) {
		g := state.Grants["g1"]
		g.ID = "g2"
		gb, _ := json.Marshal(g)
		if _, err := p.pool.Exec(ctx, "INSERT INTO grants(payload) VALUES($1)", gb); err != nil {
			t.Fatal(err)
		}
		r := state.Requests["r1"]
		r.ID = "r2"
		r.GrantID = "g2"
		r.FileID = "f2"
		b, _ := json.Marshal(r)
		_, err := p.pool.Exec(ctx, "INSERT INTO delegation_requests(payload,owner_id) VALUES($1,'u1')", b)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "23503" {
			t.Fatalf("expected composite grant FK, got %v", err)
		}
	})
}
func TestPostgresDedicatedLockSessionLoss(t *testing.T) {
	p := testPostgres(t)
	ctx := context.Background()
	unlock, err := p.LockConnection(ctx, "lost-session")
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	var pid int32
	// The current test owns the only advisory lock in its isolated application
	// connection; exclude the pool's own backend and migration lock.
	err = p.pool.QueryRow(ctx, `SELECT l.pid FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid WHERE l.locktype='advisory' AND l.granted AND l.pid<>pg_backend_pid() AND a.application_name='toolbox-lock-test' LIMIT 1`).Scan(&pid)
	if errors.Is(err, pgx.ErrNoRows) {
		t.Skip("set application_name=toolbox-lock-test in test DSN for explicit backend-termination check")
	}
	if err != nil {
		t.Fatal(err)
	}
	if _, err = p.pool.Exec(ctx, "SELECT pg_terminate_backend($1)", pid); err != nil {
		t.Fatal(err)
	}
	if err = unlock(); !errors.Is(err, ErrLockLost) {
		t.Fatalf("expected lost lock, got %v", err)
	}
	again, err := p.LockConnection(ctx, "lost-session")
	if err != nil {
		t.Fatal(err)
	}
	if err = again(); err != nil {
		t.Fatal(err)
	}
}
func TestPostgresDBClockAfterLockWait(t *testing.T) {
	p := testPostgres(t)
	ctx := context.Background()
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollback(tx)
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", transactionLock); err != nil {
		t.Fatal(err)
	}
	got := make(chan time.Time, 1)
	fail := make(chan error, 1)
	go func() { fail <- p.Transact(ctx, func(s *domain.State) error { got <- s.Now; return nil }) }()
	time.Sleep(100 * time.Millisecond)
	var release time.Time
	if err = tx.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&release); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err = <-fail; err != nil {
		t.Fatal(err)
	}
	if at := <-got; at.Before(release) {
		t.Fatalf("database clock captured before lock wait: %v < %v", at, release)
	}
}

func TestPostgresCrossInstanceLock(t *testing.T) {
	p := testPostgres(t)
	ctx := context.Background()
	secondPool, err := pgxpool.NewWithConfig(ctx, p.pool.Config())
	if err != nil {
		t.Fatal(err)
	}
	second := &Postgres{pool: secondPool, config: p.config.Copy()}
	defer second.Close()
	release, err := p.LockConnection(ctx, "shared-connection")
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	short, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	if _, err = second.LockConnection(short, "shared-connection"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("second instance bypassed lock: %v", err)
	}
	if err = release(); err != nil {
		t.Fatal(err)
	}
	other, err := second.LockConnection(ctx, "shared-connection")
	if err != nil {
		t.Fatal(err)
	}
	if err = other(); err != nil {
		t.Fatal(err)
	}
}
