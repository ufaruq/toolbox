// Package runtimecfg validates deployment configuration without printing secrets.
package runtimecfg

import (
	"errors"
	"github.com/jackc/pgx/v5/pgxpool"
	"net"
	"net/url"
	"os"
	"strings"
)

var ErrConfiguration = errors.New("invalid or incomplete deployment configuration")

type Config struct {
	Mode, Addr, Origin, DSN, KeyProvider, KeyFile, KMSKey, Deployment, SecretSchema, AppSchema, SigningFile, PepperFile string
	Persistent                                                                                                          bool
}

// ReadSecret refuses symlinks and files readable by other host users.
func ReadSecret(path string) ([]byte, error) {
	st, err := os.Lstat(path)
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || st.Size() > 1<<20 {
		return nil, ErrConfiguration
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, ErrConfiguration
	}
	return b, nil
}
func Load(get func(string) string) (c Config, err error) {
	c.Mode = get("TOOLBOX_MODE")
	if c.Mode == "" {
		c.Mode = "production"
	}
	if c.Mode != "fixture" && c.Mode != "production" {
		return c, ErrConfiguration
	}
	c.Addr = get("TOOLBOX_ADDR")
	if c.Addr == "" {
		c.Addr = "127.0.0.1:8080"
	}
	host, port, e := net.SplitHostPort(c.Addr)
	if e != nil || port == "" {
		return c, ErrConfiguration
	}
	c.Origin = get("TOOLBOX_ORIGIN")
	if c.Origin == "" {
		c.Origin = "http://" + c.Addr
	}
	u, e := url.Parse(c.Origin)
	if e != nil || u.User != nil || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return c, ErrConfiguration
	}
	loop := func(h string) bool { return h == "localhost" || h == "127.0.0.1" || h == "::1" }
	if c.Mode == "fixture" {
		if u.Scheme != "http" || !loop(u.Hostname()) || (!loop(host) && !(host == "0.0.0.0" && get("TOOLBOX_CONTAINER_FIXTURE") == "1")) {
			return c, ErrConfiguration
		}
	} else if u.Scheme != "https" {
		return c, ErrConfiguration
	}
	c.DSN = get("DATABASE_URL")
	if f := get("TOOLBOX_DATABASE_FILE"); f != "" {
		b, e := ReadSecret(f)
		if e != nil {
			return c, e
		}
		c.DSN = strings.TrimSpace(string(b))
		c.Persistent = true
	}
	c.KeyProvider = get("TOOLBOX_KEY_PROVIDER")
	if c.KeyProvider == "" {
		c.KeyProvider = "gcp"
	}
	c.KeyFile = get("TOOLBOX_LOCAL_KEY_FILE")
	c.KMSKey = get("TOOLBOX_KMS_KEY")
	if c.KeyProvider != "gcp" && c.KeyProvider != "local" {
		return c, ErrConfiguration
	}
	if c.Mode == "production" && (c.KeyProvider != "gcp" || c.KeyFile != "" || !c.Persistent) {
		return c, ErrConfiguration
	}
	if c.Persistent {
		if ValidateDSN(c.DSN) != nil {
			return c, ErrConfiguration
		}
		if c.KeyProvider == "local" && c.KeyFile == "" {
			return c, ErrConfiguration
		}
		if c.KeyProvider == "gcp" && c.KMSKey == "" {
			return c, ErrConfiguration
		}
		f := get("TOOLBOX_DEPLOYMENT_FILE")
		b, e := ReadSecret(f)
		if e != nil {
			return c, e
		}
		c.Deployment = strings.TrimSpace(string(b))
		if c.Deployment == "" {
			return c, ErrConfiguration
		}
	}
	c.SecretSchema = get("TOOLBOX_SECRET_SCHEMA")
	if c.SecretSchema == "" {
		c.SecretSchema = "toolbox_credentials"
	}
	c.AppSchema = get("TOOLBOX_APP_SCHEMA")
	if c.AppSchema == "" {
		c.AppSchema = "toolbox"
	}
	c.SigningFile = get("TOOLBOX_SIGNING_FILE")
	c.PepperFile = get("TOOLBOX_PEPPER_FILE")
	return c, nil
}

func ValidateDSN(dsn string) error {
	parsed, e := pgxpool.ParseConfig(dsn)
	if e != nil || parsed.ConnConfig.TLSConfig == nil || parsed.ConnConfig.TLSConfig.InsecureSkipVerify || parsed.ConnConfig.TLSConfig.ServerName == "" || len(parsed.ConnConfig.Fallbacks) > 0 {
		return ErrConfiguration
	}
	return nil
}
