package secretstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
)

func testEnvelope(t *testing.T, deployment, schema string) *Envelope {
	t.Helper()
	w, err := NewLocalWrapper(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	e, err := NewEnvelope(w, deployment, schema)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestEnvelopeRoundTripAndAuthenticatedContext(t *testing.T) {
	ctx := context.Background()
	e := testEnvelope(t, "test", "secrets")
	plain := []byte(`{"refresh_token":"synthetic-secret-canary"}`)
	cipher, err := e.Seal(ctx, "connections/a", 1, plain)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(cipher, []byte("synthetic-secret-canary")) {
		t.Fatal("plaintext persisted")
	}
	got, err := e.Open(ctx, "connections/a", 1, cipher)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatal("round trip failed", err)
	}
	for _, tc := range []struct {
		e       *Envelope
		path    string
		version int64
	}{{e, "connections/b", 1}, {e, "connections/a", 2}, {testEnvelope(t, "other", "secrets"), "connections/a", 1}, {testEnvelope(t, "test", "other"), "connections/a", 1}} {
		if _, err := tc.e.Open(ctx, tc.path, tc.version, cipher); err == nil {
			t.Fatal("cross-context ciphertext accepted")
		}
	}
	other, err := e.Seal(ctx, "connections/a", 1, plain)
	if err != nil || bytes.Equal(cipher, other) {
		t.Fatal("data keys or nonces reused")
	}
	var damaged map[string]any
	if err = json.Unmarshal(cipher, &damaged); err != nil {
		t.Fatal(err)
	}
	damaged["ciphertext"] = "AAAA"
	bad, _ := json.Marshal(damaged)
	if _, err = e.Open(ctx, "connections/a", 1, bad); err == nil {
		t.Fatal("tampered ciphertext accepted")
	}
}

type unavailableWrapper struct{}

func (unavailableWrapper) Wrap(context.Context, []byte, []byte) ([]byte, error) {
	return nil, errors.New("synthetic sensitive provider error")
}
func (unavailableWrapper) Unwrap(context.Context, []byte, []byte) ([]byte, error) {
	return nil, errors.New("synthetic sensitive provider error")
}

func TestEnvelopeUnavailableAndBounds(t *testing.T) {
	e, err := NewEnvelope(unavailableWrapper{}, "test", "secrets")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = e.Seal(context.Background(), "connections/a", 1, []byte("secret")); err != ErrUnavailable {
		t.Fatal("KMS error not sanitized", err)
	}
	e = testEnvelope(t, "test", "secrets")
	if _, err = e.Seal(context.Background(), "../escape", 1, []byte("secret")); err == nil {
		t.Fatal("unsafe path accepted")
	}
	if _, err = e.Seal(context.Background(), "connections/a", 0, []byte("secret")); err == nil {
		t.Fatal("zero version accepted")
	}
	if _, err = e.Seal(context.Background(), "connections/a", 1, make([]byte, (1<<20)+1)); err == nil {
		t.Fatal("oversized secret accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = e.Seal(ctx, "connections/a", 1, []byte("secret")); err == nil {
		t.Fatal("cancelled encryption succeeded")
	}
}
