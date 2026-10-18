package secretstore

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"hash/crc32"
	"regexp"
	"strings"
	"time"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/googleapis/gax-go/v2"
	"github.com/ufaruq/toolbox/internal/strict"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type KMSClient interface {
	Encrypt(context.Context, *kmspb.EncryptRequest, ...gax.CallOption) (*kmspb.EncryptResponse, error)
	Decrypt(context.Context, *kmspb.DecryptRequest, ...gax.CallOption) (*kmspb.DecryptResponse, error)
}
type KMSWrapper struct {
	client KMSClient
	key    string
}
type cloudWrappedKey struct {
	Key     string `json:"key"`
	Version string `json:"version"`
	Data    string `json:"data"`
}

var cloudKeyPattern = regexp.MustCompile(`^projects/[A-Za-z0-9_-]+/locations/[A-Za-z0-9_-]+/keyRings/[A-Za-z0-9_-]+/cryptoKeys/[A-Za-z0-9_-]+$`)
var cloudVersionPattern = regexp.MustCompile(`^[1-9][0-9]*$`)
var crcTable = crc32.MakeTable(crc32.Castagnoli)

func integrity(data []byte) *wrapperspb.Int64Value {
	return wrapperspb.Int64(int64(crc32.Checksum(data, crcTable)))
}

func NewKMSWrapper(client KMSClient, key string) (*KMSWrapper, error) {
	if client == nil || len(key) > 512 || !cloudKeyPattern.MatchString(key) {
		return nil, ErrUnavailable
	}
	return &KMSWrapper{client: client, key: key}, nil
}
func NewGCPWrapper(ctx context.Context, key string) (*KMSWrapper, func() error, error) {
	if len(key) > 512 || !cloudKeyPattern.MatchString(key) {
		return nil, nil, ErrUnavailable
	}
	c, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, nil, ErrUnavailable
	}
	w, err := NewKMSWrapper(c, key)
	if err != nil {
		_ = c.Close()
		return nil, nil, err
	}
	return w, c.Close, nil
}
func (w *KMSWrapper) validVersion(name string) bool {
	prefix := w.key + "/cryptoKeyVersions/"
	return strings.HasPrefix(name, prefix) && cloudVersionPattern.MatchString(strings.TrimPrefix(name, prefix))
}
func (w *KMSWrapper) Wrap(ctx context.Context, key, aad []byte) ([]byte, error) {
	if len(key) != 32 || ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	resp, err := w.client.Encrypt(ctx, &kmspb.EncryptRequest{Name: w.key, Plaintext: key, AdditionalAuthenticatedData: aad, PlaintextCrc32C: integrity(key), AdditionalAuthenticatedDataCrc32C: integrity(aad)})
	if err != nil || resp == nil || !w.validVersion(resp.Name) || !resp.VerifiedPlaintextCrc32C || !resp.VerifiedAdditionalAuthenticatedDataCrc32C || resp.CiphertextCrc32C == nil || resp.CiphertextCrc32C.Value != integrity(resp.Ciphertext).Value || len(resp.Ciphertext) == 0 || len(resp.Ciphertext) > 45000 {
		return nil, ErrUnavailable
	}
	out, err := json.Marshal(cloudWrappedKey{Key: w.key, Version: resp.Name, Data: base64.StdEncoding.EncodeToString(resp.Ciphertext)})
	if err != nil {
		return nil, ErrUnavailable
	}
	return out, nil
}
func (w *KMSWrapper) Unwrap(ctx context.Context, wrapped, aad []byte) ([]byte, error) {
	var value cloudWrappedKey
	if len(wrapped) > 65536 || strict.Decode(wrapped, &value) != nil || value.Key != w.key || !w.validVersion(value.Version) || ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	ciphertext, err := base64.StdEncoding.Strict().DecodeString(value.Data)
	if err != nil || len(ciphertext) == 0 || len(ciphertext) > 45000 {
		return nil, ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	resp, err := w.client.Decrypt(ctx, &kmspb.DecryptRequest{Name: w.key, Ciphertext: ciphertext, AdditionalAuthenticatedData: aad, CiphertextCrc32C: integrity(ciphertext), AdditionalAuthenticatedDataCrc32C: integrity(aad)})
	if err != nil || resp == nil || len(resp.Plaintext) != 32 || resp.PlaintextCrc32C == nil || resp.PlaintextCrc32C.Value != integrity(resp.Plaintext).Value {
		return nil, ErrUnavailable
	}
	return resp.Plaintext, nil
}
