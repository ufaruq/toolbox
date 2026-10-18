package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
)

// CheckMigrations rejects missing, changed or unknown migrations. An image older
// than the deployed schema must not silently claim rollback compatibility.
func (p *Postgres) CheckMigrations(ctx context.Context) error {
	entries, err := migrations.ReadDir("migrations")
	if err != nil {
		return ErrUnavailable
	}
	var count int
	if err = p.pool.QueryRow(ctx, "SELECT count(*) FROM toolbox_migrations").Scan(&count); err != nil || count != len(entries) {
		return ErrUnavailable
	}
	for _, entry := range entries {
		body, e := migrations.ReadFile("migrations/" + entry.Name())
		if e != nil {
			return ErrUnavailable
		}
		sum := sha256.Sum256(body)
		var stored string
		if e = p.pool.QueryRow(ctx, "SELECT checksum FROM toolbox_migrations WHERE name=$1", entry.Name()).Scan(&stored); e != nil || stored != hex.EncodeToString(sum[:]) {
			return ErrUnavailable
		}
	}
	return nil
}

// RuntimeSafe is read-only. Migration/backup/recovery owners must never enter the
// API, cleanup or retention path, even if a wrong DSN was mounted by an operator.
func (p *Postgres) RuntimeSafe(ctx context.Context) error {
	var safe bool
	err := p.pool.QueryRow(ctx, `SELECT NOT (r.rolsuper OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication OR r.rolbypassrls)
 AND NOT has_database_privilege(r.oid,current_database(),'CREATE')
 AND NOT EXISTS(SELECT 1 FROM pg_auth_members WHERE member=r.oid)
 AND NOT EXISTS(SELECT 1 FROM pg_namespace n WHERE n.nspname IN (current_schema(),'toolbox_credentials') AND (n.nspowner=r.oid OR has_schema_privilege(r.oid,n.oid,'CREATE')))
 AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname IN (current_schema(),'toolbox_credentials') AND (c.relowner=r.oid OR has_table_privilege(r.oid,c.oid,'TRUNCATE')))
 AND NOT has_table_privilege(r.oid,'audit_events','UPDATE') AND NOT has_table_privilege(r.oid,'audit_events','DELETE')
 AND NOT has_table_privilege(r.oid,'grants','DELETE')
 FROM pg_roles r WHERE r.rolname=current_user`).Scan(&safe)
	if err != nil || !safe {
		return ErrUnavailable
	}
	return nil
}
