package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ufaruq/toolbox/internal/identity"
	"github.com/ufaruq/toolbox/internal/tokens"
)

type runtimeConfig struct {
	Mode, Addr, Origin, DatabaseURL, KeyID string
	SigningSeed, Pepper                    []byte
	Bao                                    tokens.OpenBaoConfig
	Identity                               identity.Config
}

func loadConfig(getenv func(string) string) (runtimeConfig, error) {
	cfg := runtimeConfig{Mode: getenv("TOOLBOX_MODE"), Addr: getenv("TOOLBOX_ADDR"), DatabaseURL: getenv("DATABASE_URL")}
	if cfg.Mode != "fixture" && cfg.Mode != "hosted" {
		return runtimeConfig{}, errRuntimeConfig
	}
	if cfg.Addr == "" {
		if cfg.Mode == "fixture" {
			cfg.Addr = "127.0.0.1:8080"
		} else {
			cfg.Addr = "0.0.0.0:8080"
		}
	}
	if !validBind(cfg.Addr, cfg.Mode == "fixture") {
		return runtimeConfig{}, errRuntimeConfig
	}
	cfg.Bao = tokens.OpenBaoConfig{Address: getenv("OPENBAO_ADDR"), Token: getenv("OPENBAO_TOKEN"), Mount: getenv("OPENBAO_MOUNT"), Namespace: getenv("OPENBAO_NAMESPACE")}
	if cfg.Bao.Mount == "" {
		cfg.Bao.Mount = "secret"
	}
	if cfg.Mode == "fixture" {
		cfg.Origin = "http://" + cfg.Addr
		return cfg, nil
	}
	cfg.Origin = strings.TrimSuffix(getenv("TOOLBOX_PUBLIC_ORIGIN"), "/")
	if !validHTTPS(cfg.Origin, true) || !canonicalPublicOrigin(cfg.Origin) || !validDatabaseURL(cfg.DatabaseURL, true) {
		return runtimeConfig{}, errRuntimeConfig
	}
	u, _ := url.Parse(cfg.Origin)
	if u.Hostname() == "localhost" {
		return runtimeConfig{}, errRuntimeConfig
	}
	if ip := net.ParseIP(u.Hostname()); ip != nil && (ip.IsLoopback() || ip.IsUnspecified()) {
		return runtimeConfig{}, errRuntimeConfig
	}
	if cfg.Bao.Token == "fixture-only" || cfg.Bao.Token == "root" || cfg.Bao.Token == "dev-root" {
		return runtimeConfig{}, errRuntimeConfig
	}
	if _, err := tokens.NewOpenBao(cfg.Bao); err != nil {
		return runtimeConfig{}, errRuntimeConfig
	}
	cfg.Identity = identity.Config{Issuer: getenv("TOOLBOX_OKTA_ISSUER"), Audience: cfg.Origin + "/mcp", OwnerClientID: getenv("TOOLBOX_OKTA_OWNER_CLIENT_ID"), OwnerClientSecret: getenv("TOOLBOX_OKTA_OWNER_CLIENT_SECRET"), OwnerCallbackURL: cfg.Origin + "/auth/okta/callback"}
	if !validHTTPS(cfg.Identity.Issuer, false) || !nonblank(cfg.Identity.OwnerClientID) || cfg.Identity.OwnerClientSecret == "" || cfg.Identity.OwnerClientID == cfg.Identity.Audience {
		return runtimeConfig{}, errRuntimeConfig
	}
	clients, err := parseClients(getenv("TOOLBOX_MCP_CLIENTS"))
	if err != nil {
		return runtimeConfig{}, errRuntimeConfig
	}
	for id := range clients {
		if id == cfg.Identity.Audience || id == cfg.Identity.OwnerClientID {
			return runtimeConfig{}, errRuntimeConfig
		}
	}
	cfg.Identity.Clients = clients
	cfg.KeyID = getenv("TOOLBOX_SIGNING_KEY_ID")
	if !nonblank(cfg.KeyID) {
		return runtimeConfig{}, errRuntimeConfig
	}
	cfg.SigningSeed, err = base64.StdEncoding.Strict().DecodeString(getenv("TOOLBOX_SIGNING_SEED"))
	if err != nil || len(cfg.SigningSeed) != 32 {
		return runtimeConfig{}, errRuntimeConfig
	}
	cfg.Pepper, err = base64.StdEncoding.Strict().DecodeString(getenv("TOOLBOX_CREDENTIAL_PEPPER"))
	if err != nil || len(cfg.Pepper) != 32 {
		return runtimeConfig{}, errRuntimeConfig
	}
	return cfg, nil
}

var errRuntimeConfig = errors.New("invalid runtime configuration")

func nonblank(s string) bool {
	return s != "" && strings.TrimSpace(s) == s && !strings.ContainsAny(s, "\r\n\x00")
}
func validBind(addr string, fixture bool) bool {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return false
	}
	ip := net.ParseIP(host)
	if fixture {
		return host == "localhost" || ip != nil && ip.IsLoopback()
	}
	return host == "" || host == "localhost" || ip != nil
}
func validHTTPS(raw string, origin bool) bool {
	if !nonblank(raw) || strings.Contains(raw, "#") {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	if u.Port() != "" {
		port, err := strconv.Atoi(u.Port())
		if err != nil || port < 1 || port > 65535 {
			return false
		}
	}
	return err == nil && u.Scheme == "https" && u.Host != "" && u.Hostname() != "" && u.User == nil && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && u.Opaque == "" && (!origin || u.Path == "" && u.RawPath == "")
}

// Browser Origin serialization lowercases hosts and removes a default port.
// Reject other spellings so the registered audience and CSRF origin stay exact.
func canonicalPublicOrigin(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	host := u.Hostname()
	if strings.HasSuffix(host, ".") {
		return false
	}
	for _, r := range host {
		if r > 127 || r == '%' {
			return false
		}
	}
	if ip := net.ParseIP(host); ip != nil {
		host = ip.String()
	} else {
		host = strings.ToLower(host)
		// WHATWG URL parsers interpret numeric final labels as IPv4, including
		// shortened, octal and hexadecimal spellings that net/url preserves.
		last := host[strings.LastIndex(host, ".")+1:]
		if _, err := strconv.ParseUint(last, 10, 64); err == nil {
			return false
		}
		if strings.HasPrefix(last, "0x") {
			if _, err := strconv.ParseUint(last[2:], 16, 64); err == nil {
				return false
			}
		}
	}
	expected := host
	if strings.Contains(host, ":") {
		expected = "[" + host + "]"
	}
	if port := u.Port(); port != "" {
		if port == "443" {
			return false
		}
		number, err := strconv.Atoi(port)
		if err != nil {
			return false
		}
		expected = net.JoinHostPort(host, strconv.Itoa(number))
	}
	return u.Host == expected
}

func validDatabaseURL(raw string, requireTLS bool) bool {
	if raw == "" {
		return false
	}
	if !requireTLS {
		_, err := pgxpool.ParseConfig(raw)
		return err == nil
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") || u.Hostname() == "" || u.Fragment != "" || strings.Contains(u.Host, ",") {
		return false
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil || len(q["sslmode"]) != 1 || q.Get("sslmode") != "verify-full" {
		return false
	}
	cfg, err := pgxpool.ParseConfig(raw)
	return err == nil && cfg.ConnConfig.TLSConfig != nil && !cfg.ConnConfig.TLSConfig.InsecureSkipVerify && cfg.ConnConfig.TLSConfig.ServerName != "" && len(cfg.ConnConfig.Fallbacks) == 0 && !strings.HasPrefix(cfg.ConnConfig.Host, "/") && cfg.ConnConfig.Password != "fixture-only"
}
func parseClients(raw string) (map[string]string, error) {
	if len(raw) > 65536 {
		return nil, errRuntimeConfig
	}
	dec := json.NewDecoder(strings.NewReader(raw))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return nil, errRuntimeConfig
	}
	clients := map[string]string{}
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return nil, errRuntimeConfig
		}
		id, ok := key.(string)
		if !ok || !nonblank(id) || len(id) > 256 {
			return nil, errRuntimeConfig
		}
		if _, ok := clients[id]; ok {
			return nil, errRuntimeConfig
		}
		var label string
		if err := dec.Decode(&label); err != nil || !nonblank(label) || len(label) > 256 {
			return nil, errRuntimeConfig
		}
		clients[id] = label
		if len(clients) > 128 {
			return nil, errRuntimeConfig
		}
	}
	if _, err := dec.Token(); err != nil {
		return nil, errRuntimeConfig
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF || len(clients) == 0 {
		return nil, errRuntimeConfig
	}
	return clients, nil
}
