package secretstore

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ufaruq/toolbox/internal/tokens"
)

//go:embed schema.sql
var schemaFiles embed.FS

type PostgresConfig struct {
	Pool     *pgxpool.Pool
	Schema   string
	Envelope *Envelope
}
type Postgres struct {
	pool             *pgxpool.Pool
	envelope         *Envelope
	current, history string
}

func Migrate(ctx context.Context, pool *pgxpool.Pool, schema string) error {
	if pool == nil || !identifier.MatchString(schema) {
		return ErrUnavailable
	}
	name := pgx.Identifier{schema}.Sanitize()
	tx, err := pool.Begin(ctx)
	if err != nil {
		return ErrUnavailable
	}
	defer func() {
		c, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer cancel()
		_ = tx.Rollback(c)
	}()
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(731541642)"); err != nil {
		return ErrUnavailable
	}
	if _, err = tx.Exec(ctx, "CREATE SCHEMA IF NOT EXISTS "+name); err != nil {
		return ErrUnavailable
	}
	if _, err = tx.Exec(ctx, "CREATE TABLE IF NOT EXISTS "+name+".migrations (version integer PRIMARY KEY, checksum text NOT NULL)"); err != nil {
		return ErrUnavailable
	}
	body, err := schemaFiles.ReadFile("schema.sql")
	if err != nil {
		return ErrUnavailable
	}
	sum := sha256.Sum256(body)
	checksum := hex.EncodeToString(sum[:])
	var existing string
	err = tx.QueryRow(ctx, "SELECT checksum FROM "+name+".migrations WHERE version=1").Scan(&existing)
	if err == nil {
		if existing != checksum {
			return ErrUnavailable
		}
	} else if errors.Is(err, pgx.ErrNoRows) {
		if _, err = tx.Exec(ctx, strings.ReplaceAll(string(body), "{{schema}}", name)); err != nil {
			return ErrUnavailable
		}
		if _, err = tx.Exec(ctx, "INSERT INTO "+name+".migrations(version,checksum) VALUES(1,$1)", checksum); err != nil {
			return ErrUnavailable
		}
	} else {
		return ErrUnavailable
	}
	if err = tx.Commit(ctx); err != nil {
		return ErrUnavailable
	}
	return nil
}

func NewPostgres(ctx context.Context, c PostgresConfig) (*Postgres, error) {
	if c.Pool == nil || c.Envelope == nil || !identifier.MatchString(c.Schema) || c.Schema != c.Envelope.schema {
		return nil, ErrUnavailable
	}
	name := pgx.Identifier{c.Schema}.Sanitize()
	s := &Postgres{pool: c.Pool, envelope: c.Envelope, current: name + ".current_secrets", history: name + ".secret_versions"}
	if err := s.Ping(ctx); err != nil {
		return nil, err
	}
	return s, nil
}
func (s *Postgres) Ping(ctx context.Context) error {
	var n int
	if err := s.pool.QueryRow(ctx, "SELECT count(*) FROM "+s.current+" WHERE false").Scan(&n); err != nil {
		return ErrUnavailable
	}
	return nil
}
func (s *Postgres) Get(ctx context.Context, path string) (tokens.Bundle, int64, error) {
	var b tokens.Bundle
	v, err := s.GetJSON(ctx, path, &b)
	return b, v, err
}
func (s *Postgres) Put(ctx context.Context, path string, b tokens.Bundle, cas int64) (int64, error) {
	return s.PutJSON(ctx, path, b, cas)
}
func (s *Postgres) GetJSON(ctx context.Context, path string, out any) (int64, error) {
	if len(path) > 512 || !logicalPath.MatchString(path) {
		return 0, ErrUnavailable
	}
	var raw []byte
	var v int64
	err := s.pool.QueryRow(ctx, "SELECT c.version,v.ciphertext FROM "+s.current+" c JOIN "+s.history+" v ON v.path=c.path AND v.version=c.version WHERE c.path=$1 AND NOT c.hidden", path).Scan(&v, &raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, tokens.ErrNotFound
	}
	if err != nil {
		return 0, ErrUnavailable
	}
	plain, err := s.envelope.Open(ctx, path, v, raw)
	if err != nil {
		return 0, ErrUnavailable
	}
	defer clear(plain)
	if json.Unmarshal(plain, out) != nil {
		return 0, ErrUnavailable
	}
	return v, nil
}
func (s *Postgres) PutJSON(ctx context.Context, path string, in any, cas int64) (int64, error) {
	if cas < 0 || cas == math.MaxInt64 {
		return 0, ErrUnavailable
	}
	version := cas + 1
	plain, err := json.Marshal(in)
	if err != nil {
		return 0, ErrUnavailable
	}
	defer clear(plain)
	raw, err := s.envelope.Seal(ctx, path, version, plain)
	if err != nil {
		return 0, ErrUnavailable
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, ErrUnavailable
	}
	defer func() {
		c, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer cancel()
		_ = tx.Rollback(c)
	}()
	var affected int64
	if cas == 0 {
		tag, e := tx.Exec(ctx, "INSERT INTO "+s.current+"(path,version,hidden) VALUES($1,1,false) ON CONFLICT DO NOTHING", path)
		err = e
		affected = tag.RowsAffected()
	} else {
		tag, e := tx.Exec(ctx, "UPDATE "+s.current+" SET version=$2 WHERE path=$1 AND version=$3 AND NOT hidden", path, version, cas)
		err = e
		affected = tag.RowsAffected()
	}
	if err != nil {
		return 0, ErrUnavailable
	}
	if affected != 1 {
		return 0, tokens.ErrCAS
	}
	if _, err = tx.Exec(ctx, "INSERT INTO "+s.history+"(path,version,ciphertext) VALUES($1,$2,$3)", path, version, raw); err != nil {
		return 0, ErrUnavailable
	}
	if err = tx.Commit(ctx); err != nil {
		return 0, ErrUnavailable
	}
	return version, nil
}
func (s *Postgres) DeleteJSON(ctx context.Context, path string) error {
	if len(path) > 512 || !logicalPath.MatchString(path) {
		return ErrUnavailable
	}
	if _, err := s.pool.Exec(ctx, "UPDATE "+s.current+" SET hidden=true WHERE path=$1", path); err != nil {
		return ErrUnavailable
	}
	return nil
}

var _ tokens.SecretStore = (*Postgres)(nil)
var _ tokens.JSONStore = (*Postgres)(nil)
