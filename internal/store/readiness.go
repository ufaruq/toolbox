package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
)

// CheckSchema verifies every migration embedded in this binary against the
// applied migration ledger. It performs no DDL, snapshot mutations or audit
// writes. The runtime role needs SELECT on toolbox_migrations.
func (p *Postgres) CheckSchema(ctx context.Context) error {
	entries, err := migrations.ReadDir("migrations")
	if err != nil {
		return ErrUnavailable
	}
	expected := make(map[string]string, len(entries))
	for _, entry := range entries {
		body, err := migrations.ReadFile("migrations/" + entry.Name())
		if err != nil {
			return ErrUnavailable
		}
		sum := sha256.Sum256(body)
		expected[entry.Name()] = hex.EncodeToString(sum[:])
	}
	rows, err := p.pool.Query(ctx, "SELECT name, checksum FROM toolbox_migrations")
	if err != nil {
		return dbError(err)
	}
	defer rows.Close()
	for rows.Next() {
		var name, checksum string
		if err := rows.Scan(&name, &checksum); err != nil {
			return dbError(err)
		}
		if want, ok := expected[name]; ok {
			if checksum != want {
				return ErrUnavailable
			}
			delete(expected, name)
		}
	}
	if err := rows.Err(); err != nil {
		return dbError(err)
	}
	if len(expected) != 0 {
		return ErrUnavailable
	}
	return nil
}
