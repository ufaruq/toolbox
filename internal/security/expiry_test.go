package security

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/ufaruq/toolbox/internal/domain"
)

func TestMintExpirationBoundary(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSigner("https://toolbox.example", "local", key)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Unix(1800000000, 0)
	for _, tt := range []struct {
		name      string
		nowOffset time.Duration
		expiresIn time.Duration
		denied    bool
	}{
		{"expired", 250 * time.Millisecond, -time.Nanosecond, true},
		{"exact_expiry", 250 * time.Millisecond, 0, true},
		{"same_second_future", 250 * time.Millisecond, 500 * time.Millisecond, true},
		{"same_second_last_nanosecond", 900 * time.Millisecond, 100*time.Millisecond - time.Nanosecond, true},
		{"next_second_boundary", 900 * time.Millisecond, 100 * time.Millisecond, false},
		{"more_than_one_second", 250 * time.Millisecond, 1500 * time.Millisecond, false},
		{"fractional_five_minute_cap", 250 * time.Millisecond, time.Hour, false},
		{"whole_second_five_minute_cap", 0, time.Hour, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			now := base.Add(tt.nowOffset)
			g := domain.Grant{ID: ID(), OwnerID: ID(), AgentID: ID(), ConnectionID: ID(), Tool: domain.Tool, Action: domain.Action, FileID: "doc-A", Epoch: 1, Version: 1, NotBefore: now, ExpiresAt: now.Add(tt.expiresIn)}
			raw, err := s.Mint(g, now)
			if tt.denied {
				if !errors.Is(err, domain.ErrDenied) || raw != "" {
					t.Fatalf("Mint() error = %v, token empty = %v; want denial and no token", err, raw == "")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			claims, err := s.Verify(raw, now)
			if err != nil {
				t.Fatalf("immediate Verify() failed: %v", err)
			}
			if !claims.Matches(g) || time.Unix(claims.ExpiresAt, 0).After(g.ExpiresAt) {
				t.Fatal("token exceeds grant expiration or does not match grant")
			}
			wantExpiry := g.ExpiresAt.Unix()
			if cap := now.Add(5 * time.Minute).Unix(); cap < wantExpiry {
				wantExpiry = cap
			}
			if claims.ExpiresAt != wantExpiry || claims.ExpiresAt-claims.IssuedAt > 300 {
				t.Fatalf("expiration = %d, issued at = %d; want expiration %d and lifetime <= 300 seconds", claims.ExpiresAt, claims.IssuedAt, wantExpiry)
			}
		})
	}
}
