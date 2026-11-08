package secretstore

import (
	"bytes"
	"context"
	"errors"
	"hash/crc32"
	"strings"
	"testing"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/googleapis/gax-go/v2"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const testKMSKey = "projects/test-project/locations/us-central1/keyRings/test/cryptoKeys/credentials"

type kmsService struct {
	t       *testing.T
	mode    string
	wrapper *LocalWrapper
}

func crc(p []byte) int64 { return int64(crc32.Checksum(p, crc32.MakeTable(crc32.Castagnoli))) }
func (s *kmsService) Encrypt(ctx context.Context, r *kmspb.EncryptRequest, _ ...gax.CallOption) (*kmspb.EncryptResponse, error) {
	if r.Name != testKMSKey || r.PlaintextCrc32C.GetValue() != crc(r.Plaintext) || r.AdditionalAuthenticatedDataCrc32C.GetValue() != crc(r.AdditionalAuthenticatedData) {
		s.t.Error("incorrect KMS encryption request")
	}
	if s.mode == "denied" {
		return nil, errors.New("sensitive backend error")
	}
	wrapped, err := s.wrapper.Wrap(ctx, r.Plaintext, r.AdditionalAuthenticatedData)
	if err != nil {
		return nil, err
	}
	resp := &kmspb.EncryptResponse{Name: testKMSKey + "/cryptoKeyVersions/1", Ciphertext: wrapped, CiphertextCrc32C: wrapperspb.Int64(crc(wrapped)), VerifiedPlaintextCrc32C: true, VerifiedAdditionalAuthenticatedDataCrc32C: true}
	switch s.mode {
	case "bad-ciphertext":
		resp.CiphertextCrc32C = wrapperspb.Int64(-1)
	case "unverified":
		resp.VerifiedAdditionalAuthenticatedDataCrc32C = false
	case "wrong-key":
		resp.Name = "projects/other/locations/global/keyRings/a/cryptoKeys/b/cryptoKeyVersions/1"
	}
	return resp, nil
}
func (s *kmsService) Decrypt(ctx context.Context, r *kmspb.DecryptRequest, _ ...gax.CallOption) (*kmspb.DecryptResponse, error) {
	if r.Name != testKMSKey || r.CiphertextCrc32C.GetValue() != crc(r.Ciphertext) || r.AdditionalAuthenticatedDataCrc32C.GetValue() != crc(r.AdditionalAuthenticatedData) {
		s.t.Error("incorrect KMS decryption request")
	}
	plain, err := s.wrapper.Unwrap(ctx, r.Ciphertext, r.AdditionalAuthenticatedData)
	if err != nil {
		return nil, err
	}
	rsp := &kmspb.DecryptResponse{Plaintext: plain, PlaintextCrc32C: wrapperspb.Int64(crc(plain))}
	if s.mode == "bad-plaintext" {
		rsp.PlaintextCrc32C = wrapperspb.Int64(-1)
	}
	return rsp, nil
}

func TestKMSIntegrityAndKeyIdentity(t *testing.T) {
	ctx := context.Background()
	local, _ := NewLocalWrapper(bytes.Repeat([]byte{1}, 32))
	service := &kmsService{t: t, wrapper: local}
	w, err := NewKMSWrapper(service, testKMSKey)
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{9}, 32)
	aad := []byte("bound-deployment-path-version")
	wrapped, err := w.Wrap(ctx, key, aad)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := w.Unwrap(ctx, wrapped, aad)
	if err != nil || !bytes.Equal(plain, key) {
		t.Fatal("KMS wrapping failed", err)
	}
	if _, err = w.Unwrap(ctx, wrapped, []byte("different-context")); err != ErrUnavailable {
		t.Fatal("wrong context accepted", err)
	}
	for _, mode := range []string{"bad-ciphertext", "unverified", "wrong-key", "denied"} {
		service.mode = mode
		if _, err = w.Wrap(ctx, key, aad); err != ErrUnavailable {
			t.Fatalf("%s accepted or exposed error: %v", mode, err)
		}
	}
	service.mode = "bad-plaintext"
	if _, err = w.Unwrap(ctx, wrapped, aad); err != ErrUnavailable {
		t.Fatal("bad plaintext integrity accepted", err)
	}
	other, err := NewKMSWrapper(service, strings.Replace(testKMSKey, "credentials", "other", 1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = other.Unwrap(ctx, wrapped, aad); err != ErrUnavailable {
		t.Fatal("wrapped key transplanted to different CryptoKey", err)
	}
}
