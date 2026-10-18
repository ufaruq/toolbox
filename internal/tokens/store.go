// Package tokens is the only durable provider-credential boundary. Errors never
// include credentials, secret paths, or provider response bodies.
package tokens

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"
)

var (
	ErrNotFound         = errors.New("SECRET_NOT_FOUND")
	ErrCAS              = errors.New("SECRET_VERSION_CONFLICT")
	ErrUnavailable      = errors.New("SECRET_UNAVAILABLE")
	ErrReauth           = errors.New("REAUTHENTICATION_REQUIRED")
	ErrInvalidGrant     = errors.New("PROVIDER_INVALID_GRANT")
	ErrRefreshUncertain = errors.New("PROVIDER_REFRESH_OUTCOME_UNCERTAIN")
)

// Bundle is a complete credential generation, persisted atomically. Never log it.
type Bundle struct {
	ConnectionID string    `json:"connection_id"`
	Subject      string    `json:"subject"`
	ClientID     string    `json:"client_id"`
	Epoch        int64     `json:"epoch"`
	Generation   int64     `json:"generation"`
	OperationID  string    `json:"operation_id"`
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	Expiry       time.Time `json:"expiry"`
	Scopes       []string  `json:"scopes"`
	State        string    `json:"state"`
}

type SecretStore interface {
	Get(context.Context, string) (Bundle, int64, error)
	Put(context.Context, string, Bundle, int64) (int64, error)
}

// JSONStore supports short-lived OAuth secrets as well as credential bundles.
// DeleteJSON hides the current version; destroying historical KV versions is a
// separately permissioned retention job, not part of an API request.
type JSONStore interface {
	GetJSON(context.Context, string, any) (int64, error)
	PutJSON(context.Context, string, any, int64) (int64, error)
	DeleteJSON(context.Context, string) error
}

func Path(connectionID string) string { return "connections/" + connectionID }
func validPath(path string) bool {
	if path == "" || len(path) > 512 {
		return false
	}
	for _, part := range strings.Split(path, "/") {
		if part == "" {
			return false
		}
		for _, r := range part {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
				return false
			}
		}
	}
	return true
}

// MemorySecretStore is a fixture only. It is volatile and offers no encryption,
// persistence, workload authentication, or production secret isolation.
type MemorySecretStore struct {
	mu     sync.Mutex
	values map[string]memoryValue
}
type memoryValue struct {
	data    []byte
	version int64
	deleted bool
}

func NewMemorySecretStore() *MemorySecretStore {
	return &MemorySecretStore{values: map[string]memoryValue{}}
}
func (s *MemorySecretStore) Get(ctx context.Context, path string) (Bundle, int64, error) {
	var b Bundle
	v, e := s.GetJSON(ctx, path, &b)
	return b, v, e
}
func (s *MemorySecretStore) Put(ctx context.Context, path string, b Bundle, cas int64) (int64, error) {
	return s.PutJSON(ctx, path, b, cas)
}
func (s *MemorySecretStore) GetJSON(ctx context.Context, path string, out any) (int64, error) {
	if ctx.Err() != nil {
		return 0, ctx.Err()
	}
	if !validPath(path) {
		return 0, ErrUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.values[path]
	if !ok || v.deleted {
		return 0, ErrNotFound
	}
	if json.Unmarshal(v.data, out) != nil {
		return 0, ErrUnavailable
	}
	return v.version, nil
}
func (s *MemorySecretStore) PutJSON(ctx context.Context, path string, in any, cas int64) (int64, error) {
	if ctx.Err() != nil {
		return 0, ctx.Err()
	}
	if !validPath(path) || cas < 0 {
		return 0, ErrUnavailable
	}
	data, e := json.Marshal(in)
	if e != nil {
		return 0, ErrUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.values == nil {
		s.values = map[string]memoryValue{}
	}
	v := s.values[path]
	if v.version != cas {
		return 0, ErrCAS
	}
	v = memoryValue{data: append([]byte(nil), data...), version: v.version + 1}
	s.values[path] = v
	return v.version, nil
}
func (s *MemorySecretStore) DeleteJSON(ctx context.Context, path string) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if !validPath(path) {
		return ErrUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.values[path]
	if !ok {
		return nil
	}
	v.deleted = true
	v.data = nil
	s.values[path] = v
	return nil
}

func (s *MemorySecretStore) Ping(ctx context.Context) error { return ctx.Err() }
