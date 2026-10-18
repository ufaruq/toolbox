// Package monitor emits numeric operational signals without identifiers or secrets.
package monitor

import (
	"context"
	"github.com/ufaruq/toolbox/internal/domain"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"time"
)

type Report struct {
	Healthy                                                                              bool
	Pending                                                                              int
	OldestCleanupSeconds, BackupAgeSeconds, CleanupRunAgeSeconds, RetentionRunAgeSeconds int64
	DiskUsedPercent                                                                      int
	FailedJobs                                                                           int
}

func Inspect(ctx context.Context, repo domain.Repository, backups, jobs string) (r Report, err error) {
	now := time.Now()
	age := func(path string) int64 {
		st, e := os.Stat(path)
		if e != nil {
			return -1
		}
		return int64(now.Sub(st.ModTime()).Seconds())
	}
	r.BackupAgeSeconds = age(filepath.Join(backups, "latest-database.json"))
	r.CleanupRunAgeSeconds = age(filepath.Join(jobs, "cleanup.json"))
	r.RetentionRunAgeSeconds = age(filepath.Join(jobs, "retention.json"))
	for _, name := range []string{"cleanup.failed", "retention.failed"} {
		if _, e := os.Stat(filepath.Join(jobs, name)); e == nil {
			r.FailedJobs++
		}
	}
	err = repo.Transact(ctx, func(st *domain.State) error {
		for _, j := range st.Cleanup {
			if j.Status == "pending" {
				r.Pending++
				age := int64(st.Now.Sub(j.CreatedAt).Seconds())
				if j.CreatedAt.IsZero() {
					age = 0
				}
				if age > r.OldestCleanupSeconds {
					r.OldestCleanupSeconds = age
				}
			}
		}
		return nil
	})
	if err != nil {
		return r, err
	}
	var fs unix.Statfs_t
	if e := unix.Statfs(backups, &fs); e != nil {
		return r, e
	}
	if fs.Blocks > 0 {
		r.DiskUsedPercent = int(100 * (fs.Blocks - fs.Bavail) / fs.Blocks)
	}
	r.Healthy = r.BackupAgeSeconds >= 0 && r.BackupAgeSeconds < 3600 && r.CleanupRunAgeSeconds >= 0 && r.CleanupRunAgeSeconds < 900 && r.RetentionRunAgeSeconds >= 0 && r.RetentionRunAgeSeconds < 172800 && r.OldestCleanupSeconds < 900 && r.DiskUsedPercent < 90 && r.FailedJobs == 0
	return r, nil
}
