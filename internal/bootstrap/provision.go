package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/jackc/pgx/v5"
	"github.com/ufaruq/toolbox/internal/runtimecfg"
	"path/filepath"
	"regexp"
	"strings"
)

// Provision uses bootstrap credentials only. Repeated runs preserve passwords;
// password rotation is a separate coordinated operator procedure.
func Provision(ctx context.Context, dir string) error {
	raw, err := runtimecfg.ReadSecret(filepath.Join(dir, "roles.json"))
	if err != nil {
		return err
	}
	var passwords map[string]string
	if json.Unmarshal(raw, &passwords) != nil {
		return ErrBootstrap
	}
	raw, err = runtimecfg.ReadSecret(filepath.Join(dir, "admin.dsn"))
	if err != nil {
		return err
	}
	dsn := strings.TrimSpace(string(raw))
	if runtimecfg.ValidateDSN(dsn) != nil {
		return fmt.Errorf("%w: database TLS configuration", ErrBootstrap)
	}
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return fmt.Errorf("%w: database connection", ErrBootstrap)
	}
	defer conn.Close(ctx)
	tx, err := conn.Begin(ctx)
	if err != nil {
		return ErrBootstrap
	}
	defer tx.Rollback(context.Background())
	monitor, e := runtimecfg.ReadSecret(filepath.Join(dir, "monitor-password"))
	if e != nil {
		return e
	}
	passwords["toolbox_monitor"] = strings.TrimSpace(string(monitor))
	valid := regexp.MustCompile(`^[0-9a-f]{64}$`)
	for _, role := range []string{"toolbox_migrate", "toolbox_api", "toolbox_cleanup", "toolbox_retention", "toolbox_monitor"} {
		pass := passwords[role]
		if !valid.MatchString(pass) {
			return ErrBootstrap
		}
		var exists bool
		if err = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=$1)", role).Scan(&exists); err != nil {
			return ErrBootstrap
		}
		if !exists {
			if _, err = tx.Exec(ctx, "CREATE ROLE "+pgx.Identifier{role}.Sanitize()+" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '"+pass+"'"); err != nil {
				return ErrBootstrap
			}
		}
	}
	for _, s := range []string{"toolbox", "toolbox_credentials"} {
		if _, err = tx.Exec(ctx, "CREATE SCHEMA IF NOT EXISTS "+pgx.Identifier{s}.Sanitize()+" AUTHORIZATION toolbox_migrate"); err != nil {
			return ErrBootstrap
		}
	}
	if _, err = tx.Exec(ctx, "REVOKE CREATE ON SCHEMA public FROM PUBLIC"); err != nil {
		return ErrBootstrap
	}
	if err = tx.Commit(ctx); err != nil {
		return ErrBootstrap
	}
	return nil
}
