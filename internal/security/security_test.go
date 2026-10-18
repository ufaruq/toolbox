package security

import (
	"crypto/ed25519"
	"crypto/rand"
	"github.com/ufaruq/toolbox/internal/domain"
	"strings"
	"testing"
	"time"
)

func TestDelegationJWT(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	s, _ := NewSigner("https://toolbox.example", "local", key)
	now := time.Unix(1800000000, 0)
	g := domain.Grant{ID: ID(), OwnerID: ID(), AgentID: ID(), ConnectionID: ID(), Tool: domain.Tool, Action: domain.Action, FileID: "doc-A", Epoch: 1, Version: 1, NotBefore: now, ExpiresAt: now.Add(time.Hour)}
	raw, e := s.Mint(g, now)
	if e != nil {
		t.Fatal(e)
	}
	c, e := s.Verify(raw, now)
	if e != nil || !c.Matches(g) {
		t.Fatal("valid grant rejected", e)
	}
	other := g
	other.AgentID = ID()
	if c.Matches(other) {
		t.Fatal("wrong actor matched")
	}
	if _, e = s.Verify(raw, now.Add(5*time.Minute)); e == nil {
		t.Fatal("expired accepted")
	}
	p := strings.Split(raw, ".")
	p[1] = p[1][:len(p[1])-3] + "AAA"
	if _, e = s.Verify(strings.Join(p, "."), now); e == nil {
		t.Fatal("tamper accepted")
	}
	otherSigner, _ := NewSigner("https://evil.example", "local", key)
	if _, e = otherSigner.Verify(raw, now); e == nil {
		t.Fatal("issuer accepted")
	}
}
func TestCredential(t *testing.T) {
	key := []byte(Random())
	id, raw, hash := NewCredential(key)
	got, secret, e := CredentialParts(raw)
	if e != nil || got != id || !Equal(hash, KeyedHash(key, secret)) {
		t.Fatal("credential failed")
	}
	if Equal(hash, KeyedHash(key, Random())) {
		t.Fatal("wrong secret accepted")
	}
}
