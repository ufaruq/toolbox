package security

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/ufaruq/toolbox/internal/domain"
)

func TestSigningRingRotation(t *testing.T) {
	pub1, key1, _ := ed25519.GenerateKey(rand.Reader)
	_, key2, _ := ed25519.GenerateKey(rand.Reader)
	old, err := NewSigner("https://toolbox.example", "old", key1)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	g := domain.Grant{ID: "g", OwnerID: "u", AgentID: "a", ConnectionID: "c", Tool: domain.Tool, Action: domain.Action, FileID: "f", Epoch: 1, Version: 1, NotBefore: now.Add(-time.Second), ExpiresAt: now.Add(time.Hour)}
	raw, err := old.Mint(g, now)
	if err != nil {
		t.Fatal(err)
	}
	config := SigningKeyRing{Active: "new", PrivateKey: base64.StdEncoding.EncodeToString(key2), PublicKeys: map[string]string{"old": base64.StdEncoding.EncodeToString(pub1)}}
	rotated, err := NewKeyRingSigner("https://toolbox.example", config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = rotated.Verify(raw, now); err != nil {
		t.Fatal("rotation invalidated unexpired old token", err)
	}
	newRaw, err := rotated.Mint(g, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = rotated.Verify(newRaw, now); err != nil {
		t.Fatal(err)
	}
	if _, err = old.Verify(newRaw, now); err == nil {
		t.Fatal("old key accepted new signer")
	}
	delete(config.PublicKeys, "old")
	retired, err := NewKeyRingSigner("https://toolbox.example", config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = retired.Verify(raw, now); err == nil {
		t.Fatal("removed key accepted")
	}
	if _, err = rotated.Verify(raw, now.Add(6*time.Minute)); err == nil {
		t.Fatal("rotation bypassed token expiry")
	}
}

func TestPepperRingRejectsMalformedAndUnknownKeys(t *testing.T) {
	good := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", 32)))
	for _, config := range []PepperConfig{{}, {Active: "missing", Keys: map[string]string{"old": good}}, {Active: "a", Keys: map[string]string{"a": "secret"}}, {Active: "a/b", Keys: map[string]string{"a/b": good}}} {
		if _, err := NewPepperRing(config); err == nil {
			t.Fatal("accepted malformed pepper configuration")
		}
	}
	ring, err := NewPepperRing(PepperConfig{Active: "new", Keys: map[string]string{"new": good}})
	if err != nil {
		t.Fatal(err)
	}
	if ring.Verify("missing", "credential", KeyedHash([]byte(strings.Repeat("x", 32)), "credential")) {
		t.Fatal("unknown pepper authenticated")
	}
}

func TestSigningRingRejectsInconsistentKey(t *testing.T) {
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := NewKeyRingSigner("https://toolbox.example", SigningKeyRing{Active: "a", PrivateKey: base64.StdEncoding.EncodeToString(private), PublicKeys: map[string]string{"a": base64.StdEncoding.EncodeToString(other)}}); err == nil {
		t.Fatal("inconsistent signing keys accepted")
	}
}
