package main

import (
	"encoding/base64"
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
)

type runtimeConfig struct {
	mode, addr, origin                         string
	oidcIssuer, oidcClientID, oidcClientSecret string
	pepper                                     []byte
	databaseURL, baoAddr, baoToken             string
}

func loadConfig(getenv func(string) string) (runtimeConfig, error) {
	c := runtimeConfig{mode: getenv("TOOLBOX_MODE"), addr: getenv("TOOLBOX_ADDR")}
	if c.mode != "fixture" && c.mode != "oidc-local" {
		return c, errors.New("TOOLBOX_MODE must explicitly select fixture or oidc-local")
	}
	if c.addr == "" {
		c.addr = "127.0.0.1:8080"
	}
	host, port, err := net.SplitHostPort(c.addr)
	p, portErr := strconv.Atoi(port)
	ip := net.ParseIP(host)
	if err != nil || portErr != nil || p < 1 || p > 65535 || (host != "localhost" && (ip == nil || !ip.IsLoopback())) {
		return c, errors.New("TOOLBOX_ADDR must be a loopback listener with an explicit port")
	}
	c.origin = "http://" + c.addr
	c.databaseURL, c.baoAddr, c.baoToken = getenv("DATABASE_URL"), getenv("OPENBAO_ADDR"), getenv("OPENBAO_TOKEN")
	if c.mode == "fixture" {
		return c, nil
	}
	for _, key := range []string{"TOOLBOX_ORIGIN", "TOOLBOX_OIDC_ISSUER", "TOOLBOX_OIDC_CLIENT_ID", "TOOLBOX_OIDC_CLIENT_SECRET", "TOOLBOX_SESSION_PEPPER", "DATABASE_URL", "OPENBAO_ADDR", "OPENBAO_TOKEN"} {
		if getenv(key) == "" {
			return c, errors.New("missing required setting " + key)
		}
	}
	u, err := url.Parse(getenv("TOOLBOX_ORIGIN"))
	if err != nil || u.Scheme != "http" || u.Host != c.addr || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return c, errors.New("TOOLBOX_ORIGIN must exactly match the loopback HTTP listener")
	}
	c.origin = getenv("TOOLBOX_ORIGIN")
	c.oidcIssuer, c.oidcClientID, c.oidcClientSecret = getenv("TOOLBOX_OIDC_ISSUER"), getenv("TOOLBOX_OIDC_CLIENT_ID"), getenv("TOOLBOX_OIDC_CLIENT_SECRET")
	u, err = url.Parse(c.oidcIssuer)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return c, errors.New("TOOLBOX_OIDC_ISSUER must be an exact trusted HTTPS issuer")
	}
	if len(c.oidcClientID) > 1024 || strings.TrimSpace(c.oidcClientID) != c.oidcClientID || strings.ContainsAny(c.oidcClientID+c.oidcClientSecret, "\x00\r\n") {
		return c, errors.New("invalid OIDC client configuration")
	}
	encoded := getenv("TOOLBOX_SESSION_PEPPER")
	c.pepper, err = base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(c.pepper) != 32 || strings.ContainsAny(encoded, "\r\n") {
		return c, errors.New("TOOLBOX_SESSION_PEPPER must encode exactly 32 random bytes")
	}
	return c, nil
}
