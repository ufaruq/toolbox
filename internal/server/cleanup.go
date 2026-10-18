package server

import (
	"context"
	"crypto/rand"
	"math/big"
	"sort"
	"time"

	"github.com/ufaruq/toolbox/internal/domain"
)

type CleanupReport struct {
	Processed, Succeeded, Failed, Pending int
	OldestAgeSeconds                      int64
}

func (s *Server) CleanupOnce(ctx context.Context) error { _, err := s.RunCleanup(ctx); return err }
func (s *Server) RunCleanup(ctx context.Context) (CleanupReport, error) {
	return RunCleanup(ctx, s.Repository, s.integration)
}

// RunCleanup claims a bounded lease in SQL before making a provider request.
// Crashes leave a due-time retry, never a success or an unblocked connection.
func RunCleanup(ctx context.Context, repo domain.Repository, integration interface {
	Cleanup(context.Context, string, int64) error
}) (report CleanupReport, err error) {
	jobs := []domain.Cleanup{}
	err = repo.Transact(ctx, func(st *domain.State) error {
		for _, j := range st.Cleanup {
			if j.Status == "pending" && !j.NextAttemptAt.After(st.Now) {
				jobs = append(jobs, j)
			}
		}
		sort.Slice(jobs, func(i, j int) bool {
			if jobs[i].CreatedAt.Equal(jobs[j].CreatedAt) {
				return jobs[i].ID < jobs[j].ID
			}
			return jobs[i].CreatedAt.Before(jobs[j].CreatedAt)
		})
		if len(jobs) > 100 {
			jobs = jobs[:100]
		}
		for i, j := range jobs {
			if j.CreatedAt.IsZero() {
				j.CreatedAt = st.Now
			}
			if j.Attempts < 1000000 {
				j.Attempts++
			}
			j.LastAttemptAt = st.Now
			j.NextAttemptAt = st.Now.Add(time.Minute)
			jobs[i] = j
			st.Cleanup[j.ID] = j
		}
		return nil
	})
	if err != nil {
		return report, err
	}
	for _, j := range jobs {
		if ctx.Err() != nil {
			return report, ctx.Err()
		}
		report.Processed++
		jobCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		failure := integration.Cleanup(jobCtx, j.ConnectionID, j.Epoch)
		cancel()
		err = repo.Transact(ctx, func(st *domain.State) error {
			current, ok := st.Cleanup[j.ID]
			if !ok || current.Status != "pending" || !current.LastAttemptAt.Equal(j.LastAttemptAt) {
				return domain.ErrDenied
			}
			c := st.Connections[j.ConnectionID]
			if failure == nil && c.Epoch == j.Epoch && (c.Status == "disconnecting" || c.Status == "disconnected") {
				c.Status = "disconnected"
				st.Connections[c.ID] = c
				current.Status = "complete"
				current.LastError = ""
				current.NextAttemptAt = time.Time{}
				report.Succeeded++
				addAudit(st, "service", "cleanup", j.OwnerID, "connection.cleanup", "", c.ID, "", "complete", "", 0)
			} else {
				current.LastError = "provider_unavailable"
				current.NextAttemptAt = st.Now.Add(cleanupDelay(current.Attempts))
				report.Failed++
			}
			st.Cleanup[j.ID] = current
			return nil
		})
		if err != nil {
			return report, err
		}
	}
	err = repo.Transact(ctx, func(st *domain.State) error {
		for _, j := range st.Cleanup {
			if j.Status == "pending" {
				report.Pending++
				created := j.CreatedAt
				if created.IsZero() {
					created = st.Now
				}
				age := int64(st.Now.Sub(created).Seconds())
				if age > report.OldestAgeSeconds {
					report.OldestAgeSeconds = age
				}
			}
		}
		return nil
	})
	return report, err
}
func cleanupDelay(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	if attempt > 11 {
		attempt = 11
	}
	base := 5 * time.Second * time.Duration(1<<uint(attempt-1))
	if base >= time.Hour {
		return time.Hour
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(base/5)+1))
	if err == nil {
		base += time.Duration(n.Int64())
	}
	if base > time.Hour {
		return time.Hour
	}
	return base
}
