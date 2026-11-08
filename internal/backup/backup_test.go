package backup

import (
	"bytes"
	"filippo.io/age"
	"testing"
)

func TestEncryptedBackupRoundTripAndTampering(t *testing.T) {
	key, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	var encrypted bytes.Buffer
	plain := bytes.Repeat([]byte("synthetic snapshot"), 10000)
	if err = Encrypt(bytes.NewReader(plain), &encrypted, key.Recipient().String()); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encrypted.Bytes(), []byte("synthetic snapshot")) {
		t.Fatal("plaintext backup")
	}
	var out bytes.Buffer
	if err = Decrypt(bytes.NewReader(encrypted.Bytes()), &out, key.String()); err != nil || !bytes.Equal(out.Bytes(), plain) {
		t.Fatal(err)
	}
	raw := append([]byte(nil), encrypted.Bytes()...)
	raw[len(raw)-1] ^= 1
	if err = Decrypt(bytes.NewReader(raw), &bytes.Buffer{}, key.String()); err == nil {
		t.Fatal("tampered backup accepted")
	}
	other, _ := age.GenerateX25519Identity()
	if err = Decrypt(bytes.NewReader(encrypted.Bytes()), &bytes.Buffer{}, other.String()); err == nil {
		t.Fatal("wrong recovery key accepted")
	}
}
