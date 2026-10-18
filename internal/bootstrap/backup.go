package bootstrap

import (
	"filippo.io/age"
	"github.com/ufaruq/toolbox/internal/runtimecfg"
	"os"
	"path/filepath"
	"strings"
)

// InitBackups is an explicit, independent initialization. Never regenerate one
// half of an existing recovery pair; keep the private identity offline afterward.
func InitBackups(dir string) error {
	private := filepath.Join(dir, "backup-identity")
	public := filepath.Join(dir, "backup-recipient")
	if raw, err := runtimecfg.ReadSecret(private); err == nil {
		id, e := age.ParseX25519Identity(strings.TrimSpace(string(raw)))
		if e != nil {
			return ErrBootstrap
		}
		recipient, e := os.ReadFile(public)
		if e != nil || strings.TrimSpace(string(recipient)) != id.Recipient().String() {
			return ErrBootstrap
		}
		return nil
	}
	if _, err := os.Lstat(private); !os.IsNotExist(err) {
		return ErrBootstrap
	}
	if _, err := os.Lstat(public); !os.IsNotExist(err) {
		return ErrBootstrap
	}
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return ErrBootstrap
	}
	for file, value := range map[string]string{private: id.String(), public: id.Recipient().String()} {
		f, e := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return ErrBootstrap
		}
		_, e = f.WriteString(value + "\n")
		sync := f.Sync()
		close := f.Close()
		if e != nil || sync != nil || close != nil {
			return ErrBootstrap
		}
	}
	return nil
}
