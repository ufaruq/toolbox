package runtimecfg

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProductionRejectsLocalAndUnverifiedDatabase(t *testing.T) {
	env := map[string]string{"TOOLBOX_MODE": "production", "TOOLBOX_KEY_PROVIDER": "local"}
	if _, err := Load(func(k string) string { return env[k] }); err == nil {
		t.Fatal("production local key accepted")
	}
	file := filepath.Join(t.TempDir(), "database")
	if err := os.WriteFile(file, []byte("postgres://user:synthetic@postgres/toolbox?sslmode=require"), 0600); err != nil {
		t.Fatal(err)
	}
	env = map[string]string{"TOOLBOX_DATABASE_FILE": file, "TOOLBOX_KMS_KEY": "projects/p/locations/l/keyRings/r/cryptoKeys/k"}
	if _, err := Load(func(k string) string { return env[k] }); err == nil {
		t.Fatal("unverified TLS accepted")
	}
}
func TestFixtureRequiresLoopbackOrigin(t *testing.T) {
	for _, origin := range []string{"http://public.example:18080", "http://127.0.0.1:18080/path", "http://127.0.0.1:18080?x=y"} {
		env := map[string]string{"TOOLBOX_MODE": "fixture", "TOOLBOX_ADDR": "0.0.0.0:18080", "TOOLBOX_ORIGIN": origin, "TOOLBOX_CONTAINER_FIXTURE": "1"}
		if _, err := Load(func(k string) string { return env[k] }); err == nil {
			t.Fatal(origin)
		}
	}
}

func TestSecretFilesRejectSymlinksAndSharedPermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "private")
	if err := os.WriteFile(path, []byte("synthetic"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadSecret(path); err == nil {
		t.Fatal("shared secret accepted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadSecret(path); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadSecret(link); err == nil {
		t.Fatal("symlink accepted")
	}
}
