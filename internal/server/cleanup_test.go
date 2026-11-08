package server

import (
	"context"
	"errors"
	"fmt"
	"github.com/ufaruq/toolbox/internal/domain"
	"github.com/ufaruq/toolbox/internal/store"
	"testing"
	"time"
)

type cleanupBoundary struct {
	Integration
	calls int
	fail  bool
}

func (c *cleanupBoundary) Cleanup(context.Context, string, int64) error {
	c.calls++
	if c.fail {
		return errors.New("sensitive provider detail")
	}
	return nil
}
func TestCleanupRetryPersistsAndSchedules(t *testing.T) {
	repo := store.NewMemory()
	ctx := context.Background()
	if err := repo.Transact(ctx, func(s *domain.State) error {
		s.Users["u"] = domain.User{ID: "u", Issuer: "fixture", Subject: "u", Status: "active"}
		s.Connections["c"] = domain.Connection{ID: "c", OwnerID: "u", Provider: "google_drive", Status: "disconnecting", Epoch: 2}
		s.Cleanup["q"] = domain.Cleanup{ID: "q", ConnectionID: "c", OwnerID: "u", Epoch: 2, Status: "pending", CreatedAt: s.Now}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	boundary := &cleanupBoundary{fail: true}
	report, err := RunCleanup(ctx, repo, boundary)
	if err != nil || report.Failed != 1 || report.Pending != 1 {
		t.Fatal(report, err)
	}
	var due time.Time
	_ = repo.Transact(ctx, func(s *domain.State) error {
		j := s.Cleanup["q"]
		if j.Attempts != 1 || j.LastError != "provider_unavailable" || !j.NextAttemptAt.After(s.Now) {
			t.Fatal(j)
		}
		due = j.NextAttemptAt
		return nil
	})
	// A new worker/process must honor the persisted due time.
	other := &cleanupBoundary{}
	report, err = RunCleanup(ctx, repo, other)
	if err != nil || other.calls != 0 || report.Processed != 0 {
		t.Fatal(report, err)
	}
	_ = repo.Transact(ctx, func(s *domain.State) error {
		j := s.Cleanup["q"]
		j.NextAttemptAt = s.Now.Add(-time.Second)
		s.Cleanup["q"] = j
		return nil
	})
	report, err = RunCleanup(ctx, repo, other)
	if err != nil || report.Succeeded != 1 || report.Pending != 0 || due.IsZero() {
		t.Fatal(report, err)
	}
	_ = repo.Transact(ctx, func(s *domain.State) error {
		if s.Connections["c"].Status != "disconnected" || s.Cleanup["q"].Status != "complete" {
			t.Fatal("not completed")
		}
		return nil
	})
}

func TestCleanupClaimPreventsOverlappingWorkers(t *testing.T) {
	now := time.Now().UTC()
	repo := store.NewMemoryWithClock(func() time.Time { return now })
	ctx := context.Background()
	if err := repo.Transact(ctx, func(s *domain.State) error {
		s.Users["u"] = domain.User{ID: "u", Issuer: "fixture", Subject: "u", Status: "active"}
		s.Connections["c"] = domain.Connection{ID: "c", OwnerID: "u", Provider: "google_drive", Status: "disconnecting", Epoch: 2}
		for i := 0; i < 105; i++ {
			id := fmt.Sprint(i)
			s.Cleanup[id] = domain.Cleanup{ID: id, ConnectionID: "c", OwnerID: "u", Epoch: 2, Status: "pending", CreatedAt: now}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	boundary := &cleanupBoundary{fail: true}
	report, err := RunCleanup(ctx, repo, boundary)
	if err != nil || report.Processed != 100 {
		t.Fatal(report, err)
	}
	second := &cleanupBoundary{fail: true}
	report, err = RunCleanup(ctx, repo, second)
	if err != nil || report.Processed != 5 {
		t.Fatal(report, err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err = RunCleanup(cancelled, repo, second); err == nil {
		t.Fatal("cancelled run accepted")
	}
	now = now.Add(2 * time.Hour)
	report, err = RunCleanup(ctx, repo, second)
	if err != nil || report.Processed != 100 || report.OldestAgeSeconds < 3600 {
		t.Fatal(report, err)
	}
}
