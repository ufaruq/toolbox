// Package security separates agent credentials from scoped delegation credentials.
package security

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ufaruq/toolbox/internal/domain"
	"github.com/ufaruq/toolbox/internal/strict"
)

var ErrToken = errors.New("INVALID_TOKEN")

func Random() string {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		panic("secure random source unavailable")
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func ID() string {
	b := make([]byte, 16)
	if _, e := rand.Read(b); e != nil {
		panic("secure random source unavailable")
	}
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:])
}
func Hash(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
func KeyedHash(key []byte, s string) string {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(s))
	return hex.EncodeToString(h.Sum(nil))
}
func Equal(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }
func NewCredential(key []byte) (string, string, string) {
	id := ID()
	secret := Random()
	return id, id + "." + secret, KeyedHash(key, secret)
}
func CredentialParts(raw string) (string, string, error) {
	p := strings.Split(raw, ".")
	if len(p) != 2 || len(p[0]) != 36 || len(p[1]) != 43 {
		return "", "", ErrToken
	}
	if b, e := base64.RawURLEncoding.DecodeString(p[1]); e != nil || len(b) != 32 {
		return "", "", ErrToken
	}
	return p[0], p[1], nil
}

type Actor struct {
	Subject string `json:"sub"`
}
type Resource struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}
type Constraints struct {
	Format   string `json:"format"`
	MaxBytes int    `json:"max_bytes"`
}
type Permission struct {
	Tool        string      `json:"tool"`
	Action      string      `json:"action"`
	Resource    Resource    `json:"resource"`
	Constraints Constraints `json:"constraints"`
}
type Claims struct {
	Issuer       string       `json:"iss"`
	Audience     string       `json:"aud"`
	Subject      string       `json:"sub"`
	Actor        Actor        `json:"act"`
	GrantID      string       `json:"grant_id"`
	ConnectionID string       `json:"connection_id"`
	Epoch        int64        `json:"connection_epoch"`
	Version      int          `json:"grant_version"`
	IssuedAt     int64        `json:"iat"`
	NotBefore    int64        `json:"nbf"`
	ExpiresAt    int64        `json:"exp"`
	ID           string       `json:"jti"`
	Permissions  []Permission `json:"permissions"`
}
type header struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
	KeyID     string `json:"kid"`
}
type Signer struct {
	issuer, keyID string
	private       ed25519.PrivateKey
	public        ed25519.PublicKey
	verification  map[string]ed25519.PublicKey
}

func NewSigner(issuer, keyID string, key ed25519.PrivateKey) (*Signer, error) {
	if issuer == "" || !keyIDPattern.MatchString(keyID) || len(key) != ed25519.PrivateKeySize {
		return nil, ErrToken
	}
	key = append(ed25519.PrivateKey(nil), key...)
	if !Equal(string(key), string(ed25519.NewKeyFromSeed(key.Seed()))) {
		return nil, ErrToken
	}
	public := key.Public().(ed25519.PublicKey)
	return &Signer{issuer: issuer, keyID: keyID, private: key, public: public, verification: map[string]ed25519.PublicKey{keyID: public}}, nil
}
func (s *Signer) Mint(g domain.Grant, now time.Time) (string, error) {
	exp := now.Add(5 * time.Minute)
	if g.ExpiresAt.Before(exp) {
		exp = g.ExpiresAt
	}
	// JWT timestamps use whole seconds, so the serialized expiry must still be in the future.
	if exp.Unix() <= now.Unix() || now.Before(g.NotBefore) || g.RevokedAt != nil {
		return "", domain.ErrDenied
	}
	c := Claims{Issuer: s.issuer, Audience: "toolbox-execution", Subject: g.OwnerID, Actor: Actor{g.AgentID}, GrantID: g.ID, ConnectionID: g.ConnectionID, Epoch: g.Epoch, Version: g.Version, IssuedAt: now.Unix(), NotBefore: now.Unix(), ExpiresAt: exp.Unix(), ID: ID(), Permissions: []Permission{{g.Tool, g.Action, Resource{"document", g.FileID}, Constraints{"text/plain", domain.MaxBytes}}}}
	h, _ := json.Marshal(header{"EdDSA", "toolbox-delegation+jwt", s.keyID})
	b, _ := json.Marshal(c)
	msg := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(b)
	return msg + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(s.private, []byte(msg))), nil
}
func (s *Signer) Verify(raw string, now time.Time) (Claims, error) {
	var c Claims
	if len(raw) > 8192 {
		return c, ErrToken
	}
	p := strings.Split(raw, ".")
	if len(p) != 3 {
		return c, ErrToken
	}
	var h header
	hb, e := base64.RawURLEncoding.DecodeString(p[0])
	if e != nil || strict.Decode(hb, &h) != nil || h.Algorithm != "EdDSA" || h.Type != "toolbox-delegation+jwt" {
		return c, ErrToken
	}
	public, ok := s.verification[h.KeyID]
	if !ok {
		return c, ErrToken
	}
	sig, e := base64.RawURLEncoding.DecodeString(p[2])
	if e != nil || !ed25519.Verify(public, []byte(p[0]+"."+p[1]), sig) {
		return c, ErrToken
	}
	b, e := base64.RawURLEncoding.DecodeString(p[1])
	if e != nil || strict.Decode(b, &c) != nil {
		return c, ErrToken
	}
	n := now.Unix()
	if c.Issuer != s.issuer || c.Audience != "toolbox-execution" || c.Subject == "" || c.Actor.Subject == "" || c.ID == "" || c.NotBefore > n || c.IssuedAt > n || c.ExpiresAt <= n || c.ExpiresAt-c.IssuedAt > 300 || c.ExpiresAt <= c.IssuedAt || len(c.Permissions) != 1 {
		return Claims{}, ErrToken
	}
	q := c.Permissions[0]
	if q.Tool != domain.Tool || q.Action != domain.Action || q.Resource.Kind != "document" || q.Resource.ID == "" || q.Constraints.Format != "text/plain" || q.Constraints.MaxBytes != domain.MaxBytes {
		return Claims{}, ErrToken
	}
	return c, nil
}
func (c Claims) Matches(g domain.Grant) bool {
	return c.Subject == g.OwnerID && c.Actor.Subject == g.AgentID && c.GrantID == g.ID && c.ConnectionID == g.ConnectionID && c.Epoch == g.Epoch && c.Version == g.Version && len(c.Permissions) == 1 && c.Permissions[0].Resource.ID == g.FileID && c.Permissions[0].Tool == g.Tool && c.Permissions[0].Action == g.Action && c.ExpiresAt <= g.ExpiresAt.Unix()
}
