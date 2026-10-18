package store

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ufaruq/toolbox/internal/domain"
)

//go:embed migrations/*.sql
var migrations embed.FS

var ErrUnavailable = errors.New("database operation failed")

const transactionLock int64 = 0x54424f5854584e // Separate namespace from connection leases.

// Postgres is a deliberately coarse reference adapter: every transaction reads
// the complete non-secret state and application writers share one advisory lock.
// It is correct for small deployments, not a high-throughput production design.
type Postgres struct {
	pool   *pgxpool.Pool
	config *pgx.ConnConfig
}

// OpenPostgres opens and verifies a primary database connection. It does not run
// migrations. Production configuration must require verified TLS separately.
func OpenPostgres(ctx context.Context, dsn string) (*Postgres, error) {
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, errors.New("invalid database configuration")
	}
	config.MaxConns = 8
	config.ConnConfig.ConnectTimeout = 5 * time.Second
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, ErrUnavailable
	}
	p := &Postgres{pool: pool, config: config.ConnConfig.Copy()}
	if err = p.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return p, nil
}
func (p *Postgres) Close()                         { p.pool.Close() }
func (p *Postgres) Ping(ctx context.Context) error { return dbError(p.pool.Ping(ctx)) }

// Migrate applies embedded migrations atomically. Run with a separate migration
// owner; the production runtime role must not own or alter the schema.
func (p *Postgres) Migrate(ctx context.Context) error {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return dbError(err)
	}
	defer rollback(tx)
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", transactionLock); err != nil {
		return dbError(err)
	}
	if _, err = tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS toolbox_migrations (name text PRIMARY KEY, checksum text NOT NULL, applied_at timestamptz NOT NULL DEFAULT clock_timestamp())`); err != nil {
		return dbError(err)
	}
	entries, err := migrations.ReadDir("migrations")
	if err != nil {
		return err
	}
	for _, entry := range entries {
		body, err := migrations.ReadFile("migrations/" + entry.Name())
		if err != nil {
			return err
		}
		sum := sha256.Sum256(body)
		checksum := hex.EncodeToString(sum[:])
		var stored string
		err = tx.QueryRow(ctx, "SELECT checksum FROM toolbox_migrations WHERE name=$1", entry.Name()).Scan(&stored)
		if err == nil {
			if stored != checksum {
				return errors.New("migration checksum mismatch")
			}
			continue
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return dbError(err)
		}
		if _, err = tx.Exec(ctx, string(body)); err != nil {
			return dbError(err)
		}
		if _, err = tx.Exec(ctx, "INSERT INTO toolbox_migrations(name,checksum) VALUES($1,$2)", entry.Name(), checksum); err != nil {
			return dbError(err)
		}
	}
	return dbError(tx.Commit(ctx))
}
func rollback(tx pgx.Tx) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = tx.Rollback(ctx)
}
func dbError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && strings.HasPrefix(pgErr.Code, "23") {
		return ErrInvariant
	}
	// SQL details may contain metadata from rejected payloads. Never return them.
	return ErrUnavailable
}
func (p *Postgres) Transact(ctx context.Context, fn func(*domain.State) error) error {
	tx, err := p.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return dbError(err)
	}
	defer rollback(tx)
	// READ COMMITTED is intentional: waiting for the advisory lock must not freeze
	// a pre-revocation MVCC snapshot or database clock. Every adapter writer uses it.
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", transactionLock); err != nil {
		return dbError(err)
	}
	old, err := load(ctx, tx)
	if err != nil {
		return err
	}
	next, err := clone(old)
	if err != nil {
		return err
	}
	if err = fn(next); err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if err = validate(old, next); err != nil {
		return err
	}
	if err = syncState(ctx, tx, old, next); err != nil {
		return err
	}
	return dbError(tx.Commit(ctx))
}

var tableNames = []string{"users", "agents", "credentials", "sessions", "connections", "resources", "grants", "delegation_requests", "oauth_transactions", "cleanup_outbox", "audit_events"}

func load(ctx context.Context, tx pgx.Tx) (*domain.State, error) {
	s := domain.NewState()
	// One statement provides a coherent snapshot even if a maintenance reader or
	// retention process exists; writes outside the adapter are unsupported.
	parts := make([]string, 0, len(tableNames))
	for _, table := range tableNames {
		order := "0::bigint"
		if table == "audit_events" {
			order = "event_order"
		}
		parts = append(parts, "SELECT '"+table+"' AS kind, payload, "+order+" AS event_order FROM "+table)
	}
	rows, err := tx.Query(ctx, strings.Join(parts, " UNION ALL ")+" ORDER BY kind, event_order")
	if err != nil {
		return nil, dbError(err)
	}
	defer rows.Close()
	for rows.Next() {
		var table string
		var raw []byte
		var order int64
		if err = rows.Scan(&table, &raw, &order); err != nil {
			return nil, dbError(err)
		}
		switch table {
		case "users":
			err = decode(raw, s.Users, func(v domain.User) string { return v.ID })
		case "agents":
			err = decode(raw, s.Agents, func(v domain.Agent) string { return v.ID })
		case "credentials":
			err = decode(raw, s.Credentials, func(v domain.Credential) string { return v.ID })
		case "sessions":
			err = decode(raw, s.Sessions, func(v domain.Session) string { return v.ID })
		case "connections":
			err = decode(raw, s.Connections, func(v domain.Connection) string { return v.ID })
		case "resources":
			err = decode(raw, s.Resources, func(v domain.Resource) string { return domain.ResourceKey(v.ConnectionID, v.FileID) })
		case "grants":
			err = decode(raw, s.Grants, func(v domain.Grant) string { return v.ID })
		case "delegation_requests":
			err = decode(raw, s.Requests, func(v domain.Request) string { return v.ID })
		case "oauth_transactions":
			err = decode(raw, s.OAuth, func(v domain.OAuthTransaction) string { return v.ID })
		case "cleanup_outbox":
			err = decode(raw, s.Cleanup, func(v domain.Cleanup) string { return v.ID })
		case "audit_events":
			var v domain.Audit
			err = json.Unmarshal(raw, &v)
			s.Audits = append(s.Audits, v)
		}
		if err != nil {
			return nil, errors.New("invalid stored record")
		}
	}
	if err = rows.Err(); err != nil {
		return nil, dbError(err)
	}
	// Obtain primary database time after lock acquisition and snapshot loading.
	if err = tx.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&s.Now); err != nil {
		return nil, dbError(err)
	}
	return s, nil
}
func decode[T any](raw []byte, target map[string]T, key func(T) string) error {
	var v T
	if err := json.Unmarshal(raw, &v); err != nil {
		return err
	}
	target[key(v)] = v
	return nil
}
func upsert[T any](ctx context.Context, tx pgx.Tx, table string, old, next map[string]T, owner func(T) string) error {
	keys := make([]string, 0, len(next))
	for k := range next {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := next[k]
		body, err := json.Marshal(v)
		if err != nil {
			return err
		}
		if prev, ok := old[k]; ok {
			prior, _ := json.Marshal(prev)
			if string(prior) == string(body) {
				continue
			}
		}
		query := "INSERT INTO " + table + " (payload) VALUES ($1) ON CONFLICT (id) DO UPDATE SET payload=EXCLUDED.payload"
		args := []any{body}
		if owner != nil {
			query = "INSERT INTO " + table + " (payload,owner_id) VALUES ($1,$2) ON CONFLICT (id) DO UPDATE SET payload=EXCLUDED.payload,owner_id=EXCLUDED.owner_id"
			args = append(args, owner(v))
		}
		if table == "resources" {
			query = "INSERT INTO resources (payload,owner_id) VALUES ($1,$2) ON CONFLICT (connection_id,file_id) DO UPDATE SET payload=EXCLUDED.payload,owner_id=EXCLUDED.owner_id"
		}
		if _, err = tx.Exec(ctx, query, args...); err != nil {
			return dbError(err)
		}
	}
	return nil
}
func remove[T any](ctx context.Context, tx pgx.Tx, table string, old, next map[string]T) error {
	for k, v := range old {
		if _, ok := next[k]; ok {
			continue
		}
		var err error
		if table == "resources" {
			r := any(v).(domain.Resource)
			_, err = tx.Exec(ctx, "DELETE FROM resources WHERE connection_id=$1 AND file_id=$2", r.ConnectionID, r.FileID)
		} else {
			_, err = tx.Exec(ctx, "DELETE FROM "+table+" WHERE id=$1", k)
		}
		if err != nil {
			return dbError(err)
		}
	}
	return nil
}
func syncState(ctx context.Context, tx pgx.Tx, old, s *domain.State) error {
	// Remove dependants first. Grants and approved requests are never removable.
	for _, fn := range []func() error{
		func() error { return remove(ctx, tx, "oauth_transactions", old.OAuth, s.OAuth) },
		func() error { return remove(ctx, tx, "cleanup_outbox", old.Cleanup, s.Cleanup) },
		func() error { return remove(ctx, tx, "delegation_requests", old.Requests, s.Requests) },
		func() error { return remove(ctx, tx, "credentials", old.Credentials, s.Credentials) },
		func() error { return remove(ctx, tx, "sessions", old.Sessions, s.Sessions) },
		func() error { return remove(ctx, tx, "resources", old.Resources, s.Resources) },
		func() error { return remove(ctx, tx, "connections", old.Connections, s.Connections) },
		func() error { return remove(ctx, tx, "agents", old.Agents, s.Agents) },
		func() error { return remove(ctx, tx, "users", old.Users, s.Users) },
		func() error { return upsert(ctx, tx, "users", old.Users, s.Users, nil) },
		func() error { return upsert(ctx, tx, "agents", old.Agents, s.Agents, nil) },
		func() error { return upsert(ctx, tx, "credentials", old.Credentials, s.Credentials, nil) },
		func() error { return upsert(ctx, tx, "sessions", old.Sessions, s.Sessions, nil) },
		func() error { return upsert(ctx, tx, "connections", old.Connections, s.Connections, nil) },
		func() error {
			return upsert(ctx, tx, "resources", old.Resources, s.Resources, func(v domain.Resource) string { return s.Connections[v.ConnectionID].OwnerID })
		},
		func() error { return upsert(ctx, tx, "grants", old.Grants, s.Grants, nil) },
		func() error {
			return upsert(ctx, tx, "delegation_requests", old.Requests, s.Requests, func(v domain.Request) string { return s.Agents[v.AgentID].OwnerID })
		},
		func() error { return upsert(ctx, tx, "oauth_transactions", old.OAuth, s.OAuth, nil) },
		func() error { return upsert(ctx, tx, "cleanup_outbox", old.Cleanup, s.Cleanup, nil) },
	} {
		if err := fn(); err != nil {
			return err
		}
	}
	for _, event := range s.Audits[len(old.Audits):] {
		body, err := json.Marshal(event)
		if err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, "INSERT INTO audit_events(payload) VALUES($1)", body); err != nil {
			return dbError(err)
		}
	}
	return nil
}

// LockConnection holds a session-level advisory lock on an independent physical
// connection, never a pooled connection. Cancellation or the hold limit closes
// it. The returned function is idempotent and reports lost/expired sessions.
func (p *Postgres) LockConnection(ctx context.Context, id string) (func() error, error) {
	if id == "" {
		return nil, ErrInvariant
	}
	wait, cancel := context.WithTimeout(ctx, lockWaitLimit)
	defer cancel()
	conn, err := pgx.ConnectConfig(wait, p.config.Copy())
	if err != nil {
		return nil, dbError(err)
	}
	closeConn := func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = conn.Close(closeCtx)
		// pgx may already be asynchronously closing after a cancelled query.
		// Force the physical transport closed before returning either way.
		_ = conn.PgConn().Conn().Close()
	}
	sum := sha256.Sum256([]byte("toolbox.connection.lock.v1\x00" + id))
	key := int64(binary.BigEndian.Uint64(sum[:8]))
	// Ensure no connection hash collides with the global transaction namespace.
	if key == transactionLock {
		key ^= 1
	}
	if _, err = conn.Exec(wait, "SELECT pg_advisory_lock($1)", key); err != nil {
		closeConn()
		return nil, dbError(err)
	}
	var once sync.Once
	var result error
	done := make(chan struct{})
	finish := func(lost bool) error {
		once.Do(func() {
			defer closeConn()
			defer close(done)
			if lost {
				result = ErrLockLost
				return
			}
			release, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			var unlocked bool
			if err := conn.QueryRow(release, "SELECT pg_advisory_unlock($1)", key).Scan(&unlocked); err != nil || !unlocked {
				result = ErrLockLost
			}
		})
		return result
	}
	go func() {
		timer := time.NewTimer(lockHoldLimit)
		defer timer.Stop()
		select {
		case <-done:
			return
		case <-ctx.Done():
			finish(true)
		case <-timer.C:
			finish(true)
		}
	}()
	return func() error { return finish(ctx.Err() != nil) }, nil
}

var _ domain.Repository = (*Postgres)(nil)
