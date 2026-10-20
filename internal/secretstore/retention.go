package secretstore

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/ufaruq/toolbox/internal/domain"
	"github.com/ufaruq/toolbox/internal/tokens"
	"strings"
	"time"
)

type RetentionPolicy struct {
	HistoryGrace, OAuthGrace time.Duration
	Limit                    int
}
type RetentionReport struct{ Scanned, Deleted, Blocked int }
type candidate struct {
	path    string
	version int64
	created time.Time
	hidden  bool
}

// RunRetention preserves every unknown operation. It uses the same connection
// lease as refresh/disconnect and rereads the primary under that lease.
func (s *Postgres) RunRetention(ctx context.Context, repo domain.Repository, p RetentionPolicy) (report RetentionReport, err error) {
	if p.HistoryGrace == 0 {
		p.HistoryGrace = 7 * 24 * time.Hour
	}
	if p.OAuthGrace == 0 {
		p.OAuthGrace = time.Hour
	}
	if p.Limit == 0 {
		p.Limit = 100
	}
	if repo == nil || p.HistoryGrace < 7*24*time.Hour || p.OAuthGrace < time.Hour || p.Limit < 1 || p.Limit > 100 {
		return report, ErrUnavailable
	}
	cursorTable := pgx.Identifier{s.envelope.schema}.Sanitize() + ".retention_cursor"
	var cursor string
	if err = s.pool.QueryRow(ctx, "SELECT path FROM "+cursorTable+" WHERE id").Scan(&cursor); err != nil {
		return report, ErrUnavailable
	}
	rows, e := s.pool.Query(ctx, "SELECT path,version,created_at,hidden FROM "+s.current+" ORDER BY (path>$1) DESC,path LIMIT $2", cursor, p.Limit)
	if e != nil {
		return report, ErrUnavailable
	}
	var candidates []candidate
	for rows.Next() {
		var c candidate
		if rows.Scan(&c.path, &c.version, &c.created, &c.hidden) != nil {
			rows.Close()
			return report, ErrUnavailable
		}
		candidates = append(candidates, c)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return report, ErrUnavailable
	}
	for _, c := range candidates {
		report.Scanned++
		id := ""
		isOAuth := strings.HasPrefix(c.path, "oauth-transactions/")
		if strings.HasPrefix(c.path, "connections/") {
			id = strings.TrimPrefix(c.path, "connections/")
		} else if isOAuth {
			if e = repo.Transact(ctx, func(st *domain.State) error {
				for _, o := range st.OAuth {
					if o.SecretRef == c.path {
						id = o.ConnectionID
						break
					}
				}
				return nil
			}); e != nil {
				return report, e
			}
		} else {
			report.Blocked++
			continue
		}
		// Orphan OAuth writes are retained: an operator can reconcile them separately.
		if id == "" {
			report.Blocked++
			continue
		}
		unlock, e := repo.LockConnection(ctx, id)
		if e != nil {
			return report, ErrUnavailable
		}
		deleted, blocked, e := s.retainLocked(ctx, repo, p, c, id, isOAuth)
		unlockErr := unlock()
		if e != nil || unlockErr != nil {
			return report, ErrUnavailable
		}
		report.Deleted += deleted
		if blocked {
			report.Blocked++
		}
	}
	next := ""
	if len(candidates) > 0 {
		next = candidates[len(candidates)-1].path
	}
	if _, err = s.pool.Exec(ctx, "UPDATE "+cursorTable+" SET path=$1 WHERE id", next); err != nil {
		return report, ErrUnavailable
	}
	return report, nil
}
func (s *Postgres) retainLocked(ctx context.Context, repo domain.Repository, p RetentionPolicy, c candidate, id string, isOAuth bool) (int, bool, error) {
	var conn domain.Connection
	var now time.Time
	safe := false
	if err := repo.Transact(ctx, func(st *domain.State) error {
		now = st.Now
		conn = st.Connections[id]
		safe = conn.Status == "active" || conn.Status == "disconnected"
		for _, j := range st.Cleanup {
			if j.ConnectionID == id && j.Status != "complete" {
				safe = false
			}
		}
		if isOAuth {
			found := false
			for _, o := range st.OAuth {
				if o.SecretRef == c.path {
					found = true
					if !(o.Consumed || now.After(o.ExpiresAt)) || now.Before(o.ExpiresAt.Add(p.OAuthGrace)) {
						safe = false
					}
				}
			}
			if !found {
				safe = false
			}
		}
		return nil
	}); err != nil {
		return 0, true, err
	}
	if !safe {
		return 0, true, nil
	}
	bundle, version, err := s.Get(ctx, tokens.Path(id))
	if errors.Is(err, tokens.ErrNotFound) {
		// Abandoned consent can finish cleanup without ever issuing a bundle.
		// Preserve uncertain verifier material but do not starve later pages.
		return 0, true, nil
	}
	if err != nil {
		return 0, true, err
	}
	if conn.Status == "active" && (bundle.State != tokens.StateActive || bundle.ConnectionID != id || bundle.Epoch != conn.Epoch || version != conn.SecretVersion || bundle.Subject != conn.Subject || bundle.ClientID != conn.ClientID) {
		return 0, true, nil
	}
	if conn.Status == "disconnected" && bundle.State != tokens.StateTombstoned {
		return 0, true, nil
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, true, ErrUnavailable
	}
	defer func() {
		c, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = tx.Rollback(c)
	}()
	if isOAuth {
		var retired bool
		if err = tx.QueryRow(ctx, "SELECT "+pgx.Identifier{s.envelope.schema}.Sanitize()+".retire_oauth($1,$2)", c.path, c.version).Scan(&retired); err != nil || !retired {
			return 0, true, ErrUnavailable
		}
		tag, err := tx.Exec(ctx, "DELETE FROM "+s.history+" WHERE path=$1 AND created_at<$2", c.path, now.Add(-p.OAuthGrace))
		if err != nil {
			return 0, true, ErrUnavailable
		}
		if err = tx.Commit(ctx); err != nil {
			return 0, true, ErrUnavailable
		}
		return int(tag.RowsAffected()), false, nil
	}
	tag, err := tx.Exec(ctx, "DELETE FROM "+s.history+" WHERE path=$1 AND version<$2 AND created_at<$3", c.path, version, now.Add(-p.HistoryGrace))
	if err != nil {
		return 0, true, ErrUnavailable
	}
	if err = tx.Commit(ctx); err != nil {
		return 0, true, ErrUnavailable
	}
	return int(tag.RowsAffected()), false, nil
}
