// Package secretstore encrypts credential generations outside the application
// snapshot. Local and cloud providers share the same envelope and SQL protocol.
package secretstore

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/ufaruq/toolbox/internal/strict"
	"github.com/ufaruq/toolbox/internal/tokens"
)

var ErrUnavailable = tokens.ErrUnavailable
var identifier = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,62}$`)
var logicalPath = regexp.MustCompile(`^[A-Za-z0-9_-]+(/[A-Za-z0-9_-]+)*$`)

const maxPlaintext = 1 << 20

type KeyWrapper interface {
	Wrap(context.Context, []byte, []byte) ([]byte, error)
	Unwrap(context.Context, []byte, []byte) ([]byte, error)
}

type Envelope struct {
	wrapper            KeyWrapper
	deployment, schema string
}
type encrypted struct {
	Format     int    `json:"format"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
	WrappedKey string `json:"wrapped_key"`
}

func NewEnvelope(wrapper KeyWrapper, deployment, schema string) (*Envelope, error) {
	if wrapper == nil || deployment == "" || len(deployment) > 128 || !logicalPath.MatchString(deployment) || !identifier.MatchString(schema) {
		return nil, ErrUnavailable
	}
	return &Envelope{wrapper: wrapper, deployment: deployment, schema: schema}, nil
}

func (e *Envelope) aad(path string, version int64) ([]byte, error) {
	if version < 1 || len(path) > 512 || !logicalPath.MatchString(path) {
		return nil, ErrUnavailable
	}
	return []byte(fmt.Sprintf("toolbox-envelope-v1\x00%s\x00%s\x00%s\x00%d", e.deployment, e.schema, path, version)), nil
}

func (e *Envelope) Seal(ctx context.Context, path string, version int64, plaintext []byte) ([]byte, error) {
	if ctx.Err() != nil || len(plaintext) > maxPlaintext {
		return nil, ErrUnavailable
	}
	aad, err := e.aad(path, version)
	if err != nil {
		return nil, err
	}
	key := make([]byte, 32)
	defer clear(key)
	if _, err = rand.Read(key); err != nil {
		return nil, ErrUnavailable
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrUnavailable
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrUnavailable
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, ErrUnavailable
	}
	wrapped, err := e.wrapper.Wrap(ctx, key, aad)
	if err != nil || len(wrapped) == 0 || len(wrapped) > 65536 {
		return nil, ErrUnavailable
	}
	if ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	out, err := json.Marshal(encrypted{Format: 1, Nonce: base64.StdEncoding.EncodeToString(nonce), Ciphertext: base64.StdEncoding.EncodeToString(gcm.Seal(nil, nonce, plaintext, aad)), WrappedKey: base64.StdEncoding.EncodeToString(wrapped)})
	if err != nil {
		return nil, ErrUnavailable
	}
	return out, nil
}

func (e *Envelope) Open(ctx context.Context, path string, version int64, ciphertext []byte) ([]byte, error) {
	if ctx.Err() != nil || len(ciphertext) > 2*maxPlaintext {
		return nil, ErrUnavailable
	}
	aad, err := e.aad(path, version)
	if err != nil {
		return nil, err
	}
	var value encrypted
	if strict.Decode(ciphertext, &value) != nil || value.Format != 1 {
		return nil, ErrUnavailable
	}
	nonce, err := base64.StdEncoding.Strict().DecodeString(value.Nonce)
	if err != nil {
		return nil, ErrUnavailable
	}
	wrapped, err := base64.StdEncoding.Strict().DecodeString(value.WrappedKey)
	if err != nil || len(wrapped) == 0 || len(wrapped) > 65536 {
		return nil, ErrUnavailable
	}
	payload, err := base64.StdEncoding.Strict().DecodeString(value.Ciphertext)
	if err != nil || len(payload) > maxPlaintext+16 {
		return nil, ErrUnavailable
	}
	key, err := e.wrapper.Unwrap(ctx, wrapped, aad)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer clear(key)
	if len(key) != 32 {
		return nil, ErrUnavailable
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrUnavailable
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil || len(nonce) != gcm.NonceSize() {
		return nil, ErrUnavailable
	}
	plain, err := gcm.Open(nil, nonce, payload, aad)
	if err != nil || ctx.Err() != nil {
		clear(plain)
		return nil, ErrUnavailable
	}
	return plain, nil
}

// LocalWrapper performs real encryption but is for explicitly selected local
// testing only. Production configuration rejects this provider.
type LocalWrapper struct{ gcm cipher.AEAD }

func NewLocalWrapper(key []byte) (*LocalWrapper, error) {
	if len(key) != 32 {
		return nil, ErrUnavailable
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrUnavailable
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrUnavailable
	}
	return &LocalWrapper{gcm: gcm}, nil
}
func (w *LocalWrapper) Wrap(ctx context.Context, key, aad []byte) ([]byte, error) {
	if ctx.Err() != nil || len(key) != 32 {
		return nil, ErrUnavailable
	}
	nonce := make([]byte, w.gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, ErrUnavailable
	}
	return w.gcm.Seal(nonce, nonce, key, aad), nil
}
func (w *LocalWrapper) Unwrap(ctx context.Context, wrapped, aad []byte) ([]byte, error) {
	n := w.gcm.NonceSize()
	if ctx.Err() != nil || len(wrapped) != n+32+w.gcm.Overhead() {
		return nil, ErrUnavailable
	}
	key, err := w.gcm.Open(nil, wrapped[:n], wrapped[n:], aad)
	if err != nil {
		return nil, ErrUnavailable
	}
	return key, nil
}
