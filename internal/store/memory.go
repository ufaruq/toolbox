// Package store provides transactional, non-secret persistence adapters.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/ufaruq/toolbox/internal/domain"
)

var ErrInvariant = errors.New("store invariant violation")
var ErrLockLost = errors.New("connection lock lost")

const lockWaitLimit = 10 * time.Second
const lockHoldLimit = 45 * time.Second

// Memory is a race-safe, copy-on-write development repository. It must not be
// used for production or shared by independent server processes.
type Memory struct {
	gate    chan struct{}
	state   *domain.State
	now     func() time.Time
	locksMu sync.Mutex
	locks   map[string]*memoryLock
}
type memoryLock struct {
	gate chan struct{}
	refs int
}

func NewMemory() *Memory { return NewMemoryWithClock(time.Now) }

// NewMemoryWithClock is useful for deterministic expiry tests.
func NewMemoryWithClock(now func() time.Time) *Memory {
	if now == nil {
		now = time.Now
	}
	return &Memory{gate: make(chan struct{}, 1), state: domain.NewState(), now: now, locks: map[string]*memoryLock{}}
}
func (m *Memory) Ping(ctx context.Context) error { return ctx.Err() }
func (m *Memory) Transact(ctx context.Context, fn func(*domain.State) error) error {
	select {
	case m.gate <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-m.gate }()
	if err := ctx.Err(); err != nil {
		return err
	}
	next, err := clone(m.state)
	if err != nil {
		return err
	}
	next.Now = m.now().UTC()
	if err = fn(next); err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if err = validate(m.state, next); err != nil {
		return err
	}
	// A second clone prevents retained callback pointers from mutating committed state.
	committed, err := clone(next)
	if err != nil {
		return err
	}
	m.state = committed
	return nil
}
func clone(s *domain.State) (*domain.State, error) {
	b, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	out := domain.NewState()
	if err = json.Unmarshal(b, out); err != nil {
		return nil, err
	}
	return out, nil
}
func (m *Memory) LockConnection(ctx context.Context, id string) (func() error, error) {
	if id == "" {
		return nil, ErrInvariant
	}
	wait, cancel := context.WithTimeout(ctx, lockWaitLimit)
	defer cancel()
	m.locksMu.Lock()
	slot := m.locks[id]
	if slot == nil {
		slot = &memoryLock{gate: make(chan struct{}, 1)}
		m.locks[id] = slot
	}
	slot.refs++
	m.locksMu.Unlock()
	unref := func() {
		m.locksMu.Lock()
		defer m.locksMu.Unlock()
		slot.refs--
		if slot.refs == 0 {
			delete(m.locks, id)
		}
	}
	select {
	case slot.gate <- struct{}{}:
	case <-wait.Done():
		unref()
		return nil, wait.Err()
	}
	var once sync.Once
	var result error
	done := make(chan struct{})
	finish := func(lost bool) error {
		once.Do(func() {
			if lost {
				result = ErrLockLost
			}
			close(done)
			<-slot.gate
			unref()
		})
		return result
	}
	go func() {
		timer := time.NewTimer(lockHoldLimit)
		defer timer.Stop()
		select {
		case <-done:
			return
		case <-ctx.Done():
			finish(true)
		case <-timer.C:
			finish(true)
		}
	}()
	return func() error { return finish(ctx.Err() != nil) }, nil
}

var _ domain.Repository = (*Memory)(nil)
