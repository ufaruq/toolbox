package security

import (
	"crypto/ed25519"
	"encoding/base64"
	"regexp"
)

var keyIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// SigningKeyRing carries one active private key and retained verification keys.
// Never log this configuration or include it in infrastructure state.
type SigningKeyRing struct {
	Active     string            `json:"active"`
	PrivateKey string            `json:"private_key"`
	PublicKeys map[string]string `json:"public_keys"`
}

func NewKeyRingSigner(issuer string, config SigningKeyRing) (*Signer, error) {
	key, err := base64.StdEncoding.Strict().DecodeString(config.PrivateKey)
	if err != nil || !keyIDPattern.MatchString(config.Active) || len(config.PublicKeys) > 16 {
		return nil, ErrToken
	}
	s, err := NewSigner(issuer, config.Active, ed25519.PrivateKey(key))
	if err != nil {
		return nil, err
	}
	for id, encoded := range config.PublicKeys {
		public, err := base64.StdEncoding.Strict().DecodeString(encoded)
		if err != nil || !keyIDPattern.MatchString(id) || len(public) != ed25519.PublicKeySize {
			return nil, ErrToken
		}
		if id == config.Active && !Equal(string(public), string(s.public)) {
			return nil, ErrToken
		}
		s.verification[id] = append(ed25519.PublicKey(nil), public...)
	}
	return s, nil
}

type PepperConfig struct {
	Active string            `json:"active"`
	Keys   map[string]string `json:"keys"`
}

// PepperRing is immutable after construction; getters never expose its keys.
type PepperRing struct {
	active string
	keys   map[string][]byte
}

func NewPepperRing(config PepperConfig) (*PepperRing, error) {
	if !keyIDPattern.MatchString(config.Active) || len(config.Keys) == 0 || len(config.Keys) > 16 {
		return nil, ErrToken
	}
	r := &PepperRing{active: config.Active, keys: make(map[string][]byte)}
	for id, encoded := range config.Keys {
		key, err := base64.StdEncoding.Strict().DecodeString(encoded)
		if err != nil || !keyIDPattern.MatchString(id) || len(key) < 32 || len(key) > 64 {
			return nil, ErrToken
		}
		r.keys[id] = key
	}
	if _, ok := r.keys[r.active]; !ok {
		return nil, ErrToken
	}
	return r, nil
}

func LegacyPepperRing(key []byte) (*PepperRing, error) {
	return NewPepperRing(PepperConfig{Active: "legacy", Keys: map[string]string{"legacy": base64.StdEncoding.EncodeToString(key)}})
}

func (r *PepperRing) ActiveID() string { return r.active }
func (r *PepperRing) Hash(id, secret string) (string, error) {
	if r == nil {
		return "", ErrToken
	}
	if id == "" {
		id = "legacy"
	}
	key, ok := r.keys[id]
	if !ok {
		return "", ErrToken
	}
	return KeyedHash(key, secret), nil
}
func (r *PepperRing) Verify(id, secret, hash string) bool {
	want, err := r.Hash(id, secret)
	return err == nil && Equal(hash, want)
}
func (r *PepperRing) NewCredential() (id, raw, hash string) {
	return NewCredential(r.keys[r.active])
}
