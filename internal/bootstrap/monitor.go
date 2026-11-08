package bootstrap

import (
	"github.com/ufaruq/toolbox/internal/runtimecfg"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

func InitMonitor(dir string) error {
	passFile := filepath.Join(dir, "monitor-password")
	dsnFile := filepath.Join(dir, "monitor.dsn")
	if b, err := runtimecfg.ReadSecret(passFile); err == nil {
		dsn, err := runtimecfg.ReadSecret(dsnFile)
		if err != nil || !strings.Contains(string(dsn), strings.TrimSpace(string(b))) {
			return ErrBootstrap
		}
		return nil
	}
	if _, err := os.Lstat(passFile); !os.IsNotExist(err) {
		return ErrBootstrap
	}
	if _, err := os.Lstat(dsnFile); !os.IsNotExist(err) {
		return ErrBootstrap
	}
	pass := random()
	u := &url.URL{Scheme: "postgres", Host: "postgres:5432", Path: "/toolbox", User: url.UserPassword("toolbox_monitor", pass)}
	q := url.Values{"sslmode": {"verify-full"}, "sslrootcert": {"/run/toolbox/ca.crt"}, "search_path": {"toolbox,pg_catalog"}}
	u.RawQuery = q.Encode()
	for f, v := range map[string]string{passFile: pass, dsnFile: u.String()} {
		file, err := os.OpenFile(f, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return ErrBootstrap
		}
		_, err = file.WriteString(v)
		sync := file.Sync()
		close := file.Close()
		if err != nil || sync != nil || close != nil {
			return ErrBootstrap
		}
	}
	return nil
}
