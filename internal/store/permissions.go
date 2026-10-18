package store

import (
	"context"
	"regexp"

	"github.com/jackc/pgx/v5"
)

// Roles must already exist, have no elevated attributes or inherited roles, and
// must not own either schema. Password provisioning is an operator operation.
type Roles struct{ API, Cleanup, Retention, Monitor string }

var sqlIdentifier = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,62}$`)

func (p *Postgres) ConfigureRoles(ctx context.Context, schema, secrets string, roles Roles) error {
	names := []string{roles.API, roles.Cleanup, roles.Retention}
	if roles.Monitor != "" {
		names = append(names, roles.Monitor)
	}
	seen := map[string]bool{}
	if !sqlIdentifier.MatchString(schema) || !sqlIdentifier.MatchString(secrets) || schema == secrets {
		return ErrUnavailable
	}
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return ErrUnavailable
	}
	defer rollback(tx)
	for _, r := range names {
		if !sqlIdentifier.MatchString(r) || seen[r] {
			return ErrUnavailable
		}
		seen[r] = true
		var safe bool
		err = tx.QueryRow(ctx, `SELECT NOT (rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls) AND NOT EXISTS (SELECT 1 FROM pg_auth_members WHERE member=pg_roles.oid) AND NOT has_database_privilege(pg_roles.oid,current_database(),'CREATE')
 AND NOT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname=ANY($2) AND nspowner=pg_roles.oid)
 AND NOT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=ANY($2) AND c.relowner=pg_roles.oid)
 AND NOT EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname=ANY($2) AND p.proowner=pg_roles.oid) FROM pg_roles WHERE rolname=$1`, r, []string{schema, secrets}).Scan(&safe)
		if err != nil || !safe {
			return ErrUnavailable
		}
	}
	q := func(s string) string { return pgx.Identifier{s}.Sanitize() }
	run := func(sql string) error { _, e := tx.Exec(ctx, sql); return e }
	if run("REVOKE CREATE ON SCHEMA public FROM PUBLIC") != nil {
		return ErrUnavailable
	}
	for _, s := range []string{schema, secrets} {
		for _, sql := range []string{"REVOKE ALL ON SCHEMA " + q(s) + " FROM PUBLIC", "REVOKE ALL ON ALL TABLES IN SCHEMA " + q(s) + " FROM PUBLIC", "REVOKE ALL ON ALL SEQUENCES IN SCHEMA " + q(s) + " FROM PUBLIC", "REVOKE ALL ON ALL FUNCTIONS IN SCHEMA " + q(s) + " FROM PUBLIC"} {
			if run(sql) != nil {
				return ErrUnavailable
			}
		}
	}
	for i, r := range names {
		role := q(r)
		for _, s := range []string{schema, secrets} {
			for _, sql := range []string{"REVOKE ALL ON SCHEMA " + q(s) + " FROM " + role, "REVOKE ALL ON ALL TABLES IN SCHEMA " + q(s) + " FROM " + role, "REVOKE ALL ON ALL SEQUENCES IN SCHEMA " + q(s) + " FROM " + role, "GRANT USAGE ON SCHEMA " + q(s) + " TO " + role} {
				if run(sql) != nil {
					return ErrUnavailable
				}
			}
		}
		if run("GRANT SELECT ON "+q(schema)+".toolbox_migrations TO "+role) != nil {
			return ErrUnavailable
		}
		for _, table := range tableNames {
			privilege := "SELECT"
			if i < 2 {
				privilege = "SELECT, INSERT, UPDATE, DELETE"
				if table == "audit_events" {
					privilege = "SELECT, INSERT"
				}
				if table == "grants" || table == "delegation_requests" {
					privilege = "SELECT, INSERT, UPDATE"
				}
			}
			if run("GRANT "+privilege+" ON "+q(schema)+"."+q(table)+" TO "+role) != nil {
				return ErrUnavailable
			}
		}
		if run("GRANT SELECT ON "+q(secrets)+".migrations TO "+role) != nil {
			return ErrUnavailable
		}
		if i < 2 {
			if run("GRANT USAGE ON ALL SEQUENCES IN SCHEMA "+q(schema)+" TO "+role) != nil {
				return ErrUnavailable
			}
			if run("GRANT SELECT, INSERT, UPDATE ON "+q(secrets)+".current_secrets TO "+role) != nil {
				return ErrUnavailable
			}
			if run("GRANT SELECT, INSERT ON "+q(secrets)+".secret_versions TO "+role) != nil {
				return ErrUnavailable
			}
		} else if i == 2 {
			if run("GRANT SELECT ON "+q(secrets)+".current_secrets TO "+role) != nil {
				return ErrUnavailable
			}
			if run("GRANT SELECT, DELETE ON "+q(secrets)+".secret_versions TO "+role) != nil {
				return ErrUnavailable
			}
			if run("GRANT EXECUTE ON FUNCTION "+q(secrets)+".retire_oauth(text,bigint) TO "+role) != nil {
				return ErrUnavailable
			}
			if run("GRANT SELECT, UPDATE ON "+q(secrets)+".retention_cursor TO "+role) != nil {
				return ErrUnavailable
			}

		}
	}
	return dbError(tx.Commit(ctx))
}
