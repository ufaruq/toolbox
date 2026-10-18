package bootstrap

import (
	"bytes"
	"crypto/tls"
	"os"
	"path/filepath"
	"testing"
)

func TestInitPersistsSecretsAndRefusesPartialState(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	if err := Init(dir); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(dir, "signing.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = Init(dir); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(filepath.Join(dir, "signing.json"))
	if !bytes.Equal(before, after) {
		t.Fatal("keys replaced")
	}
	for _, file := range []string{"signing.json", "peppers.json", "local-root", "api.dsn", "migration.dsn", "roles.json", "postgres-password", "ca.key", "postgres.key"} {
		st, err := os.Stat(filepath.Join(dir, file))
		if err != nil || st.Mode().Perm()&0077 != 0 {
			t.Fatal(file, err)
		}
	}
	if _, err = tls.LoadX509KeyPair(filepath.Join(dir, "postgres.crt"), filepath.Join(dir, "postgres.key")); err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(filepath.Join(dir, "peppers.json")); err != nil {
		t.Fatal(err)
	}
	if err = Init(dir); err == nil {
		t.Fatal("partial state silently regenerated")
	}
}

func TestBackupRecipientSupportsOfflineIdentity(t *testing.T) {
	dir := t.TempDir()
	if err := InitBackups(dir); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(dir, "backup-recipient"))
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(filepath.Join(dir, "backup-identity")); err != nil {
		t.Fatal(err)
	}
	if err = InitBackups(dir); err != nil {
		t.Fatal("offline custody broke repeated preparation", err)
	}
	after, err := os.ReadFile(filepath.Join(dir, "backup-recipient"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("recipient changed", err)
	}
	if _, err = os.Stat(filepath.Join(dir, "backup-identity")); !os.IsNotExist(err) {
		t.Fatal("private recovery identity regenerated")
	}
}
