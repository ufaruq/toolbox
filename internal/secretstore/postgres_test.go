package secretstore

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ufaruq/toolbox/internal/tokens"
)

func testPostgres(t *testing.T) *Postgres {
	t.Helper()
	dsn := os.Getenv("TOOLBOX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TOOLBOX_TEST_DATABASE_URL for encrypted storage integration")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := fmt.Sprintf("encrypted_%d", time.Now().UnixNano())
	if _, err = pool.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
		pool.Close()
	})
	if err = Migrate(ctx, pool, schema); err != nil {
		t.Fatal(err)
	}
	e := testEnvelope(t, "test", schema)
	s, err := NewPostgres(ctx, PostgresConfig{Pool: pool, Schema: schema, Envelope: e})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestPostgresEncryptedCASAndCreationFence(t *testing.T) {
	s := testPostgres(t)
	ctx := context.Background()
	path := "connections/a"
	if _, _, err := s.Get(ctx, path); err != tokens.ErrNotFound {
		t.Fatal(err)
	}
	b := tokens.Bundle{ConnectionID: "a", Epoch: 1, Generation: 1, State: tokens.StateActive, RefreshToken: "synthetic-refresh-canary"}
	v, err := s.Put(ctx, path, b, 0)
	if err != nil || v != 1 {
		t.Fatal("create", v, err)
	}
	var winners atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, e := s.Put(ctx, path, b, 1)
			if e == nil {
				winners.Add(1)
			} else if e != tokens.ErrCAS {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	if winners.Load() != 1 {
		t.Fatal("CAS winners", winners.Load())
	}
	got, v, err := s.Get(ctx, path)
	if err != nil || v != 2 || got.RefreshToken != b.RefreshToken {
		t.Fatal("read", v, err)
	}
	if err = s.DeleteJSON(ctx, path); err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.Get(ctx, path); err != tokens.ErrNotFound {
		t.Fatal("hidden pointer readable", err)
	}
	if _, err = s.Put(ctx, path, b, 0); err != tokens.ErrCAS {
		t.Fatal("deleted path recreated", err)
	}
	var count int
	if err = s.pool.QueryRow(ctx, "SELECT count(*) FROM "+s.history+"").Scan(&count); err != nil || count != 2 {
		t.Fatal("losing CAS leaked history", count, err)
	}
	rows, err := s.pool.Query(ctx, "SELECT ciphertext FROM "+s.history)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var raw []byte
		if err = rows.Scan(&raw); err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(raw, []byte(b.RefreshToken)) {
			t.Fatal("plaintext stored")
		}
	}
}

func TestPostgresEnvelopeTransplantRejected(t *testing.T) {
	s := testPostgres(t)
	ctx := context.Background()
	for _, p := range []string{"connections/a", "connections/b"} {
		if _, err := s.PutJSON(ctx, p, map[string]string{"secret": "synthetic"}, 0); err != nil {
			t.Fatal(err)
		}
	}
	_, err := s.pool.Exec(ctx, "UPDATE "+s.history+" SET ciphertext=(SELECT ciphertext FROM "+s.history+" WHERE path='connections/a' AND version=1) WHERE path='connections/b'")
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]string
	if _, err = s.GetJSON(ctx, "connections/b", &out); err != tokens.ErrUnavailable {
		t.Fatal("transplanted ciphertext accepted", err)
	}
}

func TestPostgresCancelledWriteAndMigrationChecksum(t *testing.T) {
	s := testPostgres(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.PutJSON(ctx, "connections/cancelled", map[string]string{"secret": "synthetic"}, 0); err == nil {
		t.Fatal("cancelled write accepted")
	}
	var n int
	if err := s.pool.QueryRow(context.Background(), "SELECT count(*) FROM "+s.current).Scan(&n); err != nil || n != 0 {
		t.Fatal(n, err)
	}
	if err := Migrate(context.Background(), s.pool, s.envelope.schema); err != nil {
		t.Fatal(err)
	}
	_, err := s.pool.Exec(context.Background(), "UPDATE "+pgx.Identifier{s.envelope.schema}.Sanitize()+".migrations SET checksum='corrupt'")
	if err != nil {
		t.Fatal(err)
	}
	if err = Migrate(context.Background(), s.pool, s.envelope.schema); err == nil {
		t.Fatal("changed migration checksum accepted")
	}
}
