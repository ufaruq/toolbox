package store

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
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

func testPostgres(t *testing.T) *Postgres { return testPostgresSetup(t, nil) }

func testPostgresSetup(t *testing.T, setup func(*Postgres)) *Postgres {
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
	if setup != nil {
		setup(p)
		return p
	}
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
	// A concurrent test or instance may use the same application_name. Its
	// advisory locks must never make it a candidate for backend termination.
	unrelated, err := pgx.ConnectConfig(ctx, p.config.Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer unrelated.Close(ctx)
	if _, err = unrelated.Exec(ctx, "SELECT pg_advisory_lock(1, pg_backend_pid())"); err != nil {
		t.Fatal(err)
	}
	id := p.config.RuntimeParams["search_path"] + "/lost-session"
	unlock, err := p.LockConnection(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	var pid int32
	// Identify this exact connection lease, independent of application_name or
	// DSN format. PostgreSQL exposes a bigint advisory key as two unsigned OIDs
	// with objsubid=1; the schema in id keeps it distinct from concurrent tests.
	sum := sha256.Sum256([]byte("toolbox.connection.lock.v1\x00" + id))
	key := binary.BigEndian.Uint64(sum[:8])
	if key == uint64(transactionLock) {
		key ^= 1
	}
	err = p.pool.QueryRow(ctx, `SELECT min(pid) FROM pg_locks
		WHERE locktype='advisory' AND granted AND mode='ExclusiveLock'
		AND database=(SELECT oid FROM pg_database WHERE datname=current_database())
		AND classid=$1::oid AND objid=$2::oid AND objsubid=1
		HAVING count(*)=1`, key>>32, key&0xffffffff).Scan(&pid)
	if err != nil {
		t.Fatalf("find exact advisory-lock session: %v", err)
	}
	var terminated bool
	if err = p.pool.QueryRow(ctx, "SELECT pg_terminate_backend($1, 5000)", pid).Scan(&terminated); err != nil {
		t.Fatal(err)
	}
	if !terminated {
		t.Fatal("target advisory-lock session was not terminated")
	}
	if err = unlock(); !errors.Is(err, ErrLockLost) {
		t.Fatalf("expected lost lock, got %v", err)
	}
	var unrelatedReleased bool
	if err = unrelated.QueryRow(ctx, "SELECT pg_advisory_unlock(1, pg_backend_pid())").Scan(&unrelatedReleased); err != nil {
		t.Fatalf("unrelated same-application session was terminated: %v", err)
	}
	if !unrelatedReleased {
		t.Fatal("unrelated same-application session lost its advisory lock")
	}
	again, err := p.LockConnection(ctx, id)
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
