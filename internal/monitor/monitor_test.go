package monitor

import (
	"context"
	"github.com/ufaruq/toolbox/internal/store"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStaleBackupsAndFailedJobsAlert(t *testing.T) {
	dir := t.TempDir()
	repo := store.NewMemory()
	ctx := context.Background()
	r, err := Inspect(ctx, repo, dir, dir)
	if err != nil || r.Healthy {
		t.Fatal(r, err)
	}
	for _, file := range []string{"latest-database.json", "cleanup.json", "retention.json"} {
		if err = os.WriteFile(filepath.Join(dir, file), []byte("{}"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	r, err = Inspect(ctx, repo, dir, dir)
	if err != nil || !r.Healthy {
		t.Fatal(r, err)
	}
	path := filepath.Join(dir, "latest-database.json")
	old := time.Now().Add(-2 * time.Hour)
	_ = os.Chtimes(path, old, old)
	r, err = Inspect(ctx, repo, dir, dir)
	if err != nil || r.Healthy {
		t.Fatal(r, err)
	}
	_ = os.Chtimes(path, time.Now(), time.Now())
	_ = os.WriteFile(filepath.Join(dir, "cleanup.failed"), nil, 0600)
	r, err = Inspect(ctx, repo, dir, dir)
	if err != nil || r.Healthy || r.FailedJobs != 1 {
		t.Fatal(r, err)
	}
}
