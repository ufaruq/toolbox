package store

import (
	"context"
	"errors"
	"testing"

	"github.com/ufaruq/toolbox/internal/domain"
)

func TestPostgresCheckSchema(t *testing.T) {
	p := testPostgres(t)
	ctx := context.Background()
	if err := p.CheckSchema(ctx); err != nil {
		t.Fatalf("complete schema rejected: %v", err)
	}
	// Missing migration 003 leaves every runtime table available; neither a
	// connection probe nor a read-only snapshot catches its missing constraint.
	if _, err := p.pool.Exec(ctx, "DELETE FROM toolbox_migrations WHERE name=$1", "005_audit_caller_attribution.sql"); err != nil {
		t.Fatal(err)
	}
	if err := p.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	if err := p.Transact(ctx, func(*domain.State) error { return nil }); err != nil {
		t.Fatalf("snapshot unexpectedly rejected existing tables: %v", err)
	}
	if err := p.CheckSchema(ctx); !errors.Is(err, ErrUnavailable) {
		t.Errorf("missing migration accepted: %v", err)
	}
	if err := p.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := p.CheckSchema(ctx); err != nil {
		t.Fatalf("restored ledger rejected: %v", err)
	}
	if _, err := p.pool.Exec(ctx, "UPDATE toolbox_migrations SET checksum='tampered' WHERE name=$1", "005_audit_caller_attribution.sql"); err != nil {
		t.Fatal(err)
	}
	if err := p.CheckSchema(ctx); !errors.Is(err, ErrUnavailable) {
		t.Errorf("tampered checksum accepted: %v", err)
	}
}

func TestPostgresCheckSchemaSanitizesMissingLedger(t *testing.T) {
	p := testPostgres(t)
	ctx := context.Background()
	if _, err := p.pool.Exec(ctx, "DROP TABLE toolbox_migrations"); err != nil {
		t.Fatal(err)
	}
	if err := p.CheckSchema(ctx); err != ErrUnavailable {
		t.Fatalf("missing ledger error must be sanitized: %v", err)
	}
}
