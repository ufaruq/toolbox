package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/ufaruq/toolbox/internal/identitylink"
	"github.com/ufaruq/toolbox/internal/keycloakrealm"
	"github.com/ufaruq/toolbox/internal/store"
	"github.com/ufaruq/toolbox/internal/strict"
)

// The generated realm contains provider/client secrets. Never print it or
// replace an existing file; output remains private even on a permissive umask.
func runKeycloakConfig(getenv func(string) string, path string) error {
	bad := errors.New("invalid Keycloak realm configuration")
	if path == "" {
		return bad
	}
	cfg := keycloakrealm.Config{
		Realm: getenv("TOOLBOX_KEYCLOAK_REALM"), Origin: getenv("TOOLBOX_ORIGIN"),
		OwnerClientID: getenv("TOOLBOX_KEYCLOAK_OWNER_CLIENT_ID"), OwnerClientSecret: getenv("TOOLBOX_KEYCLOAK_OWNER_CLIENT_SECRET"),
		OktaIssuer: getenv("TOOLBOX_KEYCLOAK_OKTA_ISSUER"), OktaClientID: getenv("TOOLBOX_KEYCLOAK_OKTA_CLIENT_ID"), OktaClientSecret: getenv("TOOLBOX_KEYCLOAK_OKTA_CLIENT_SECRET"),
		GoogleClientID: getenv("TOOLBOX_KEYCLOAK_GOOGLE_CLIENT_ID"), GoogleClientSecret: getenv("TOOLBOX_KEYCLOAK_GOOGLE_CLIENT_SECRET"), GoogleHostedDomain: getenv("TOOLBOX_KEYCLOAK_GOOGLE_HOSTED_DOMAIN"),
	}
	if cfg.Realm == "" {
		cfg.Realm = "toolbox"
	}
	if raw := getenv("TOOLBOX_KEYCLOAK_MCP_CLIENTS"); raw != "" {
		if len(raw) > 65536 || strict.Decode([]byte(raw), &cfg.MCPClients) != nil {
			return bad
		}
	}
	if raw := getenv("TOOLBOX_KEYCLOAK_MCP_REDIRECT_URIS"); raw != "" {
		if len(raw) > 65536 || strict.Decode([]byte(raw), &cfg.MCPRedirectURIs) != nil {
			return bad
		}
	}
	flag := getenv("TOOLBOX_KEYCLOAK_DYNAMIC_CLIENT_REGISTRATION")
	if flag != "" && flag != "true" && flag != "false" {
		return bad
	}
	cfg.DynamicClientRegistration = flag == "true"
	if raw := getenv("TOOLBOX_KEYCLOAK_DYNAMIC_REGISTRATION_TRUSTED_HOSTS"); raw != "" {
		if len(raw) > 8192 || strict.Decode([]byte(raw), &cfg.DynamicRegistrationTrustedHosts) != nil {
			return bad
		}
	}
	data, err := keycloakrealm.Render(cfg)
	if err != nil {
		return bad
	}
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return errors.New("cannot create private Keycloak configuration directory")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return errors.New("cannot create private Keycloak configuration; choose a new file")
	}
	complete := false
	defer func() {
		_ = f.Close()
		if !complete {
			_ = os.Remove(path)
		}
	}()
	if _, err = f.Write(data); err != nil {
		return errors.New("cannot write private Keycloak configuration")
	}
	if err = f.Close(); err != nil {
		return errors.New("cannot close private Keycloak configuration")
	}
	complete = true
	return nil
}

// Dry-run verifies proof and writes no aliases. Schema migration belongs to
// ordinary application startup, so even dry-run must use the upgraded database.
func runKeycloakLink(getenv func(string) string, apply bool, out io.Writer) error {
	for _, key := range []string{"DATABASE_URL", "TOOLBOX_KEYCLOAK_ISSUER", "TOOLBOX_KEYCLOAK_ADMIN_CLIENT_ID", "TOOLBOX_KEYCLOAK_ADMIN_CLIENT_SECRET", "TOOLBOX_KEYCLOAK_OKTA_ISSUER"} {
		if getenv(key) == "" {
			return errors.New("missing required Keycloak migration setting " + key)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	linker, err := identitylink.New(ctx, identitylink.Config{
		RealmIssuer: getenv("TOOLBOX_KEYCLOAK_ISSUER"),
		ClientID:    getenv("TOOLBOX_KEYCLOAK_ADMIN_CLIENT_ID"), ClientSecret: getenv("TOOLBOX_KEYCLOAK_ADMIN_CLIENT_SECRET"),
		SourceIssuer: getenv("TOOLBOX_KEYCLOAK_OKTA_ISSUER"), SourceProviderAlias: "okta",
	})
	if err != nil {
		return errors.New("invalid or unavailable Keycloak migration configuration")
	}
	repo, err := store.OpenPostgres(ctx, getenv("DATABASE_URL"))
	if err != nil {
		return errors.New("migration database unavailable")
	}
	defer repo.Close()
	report, err := linker.Link(ctx, repo, apply)
	if err != nil {
		return errors.New("Keycloak identity migration rejected; check provider binding, account readiness, and alias conflicts")
	}
	mode := "dry-run (no links written)"
	if apply {
		mode = "applied"
	}
	_, err = fmt.Fprintf(out, "Keycloak migration %s: scanned=%d linked=%d already-linked=%d\n", mode, report.Scanned, report.Linked, report.AlreadyLinked)
	return err
}
