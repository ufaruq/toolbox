package main

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestOIDCLocalConfig(t *testing.T) {
	valid := map[string]string{
		"TOOLBOX_MODE": "oidc-local", "TOOLBOX_ADDR": "127.0.0.1:8080",
		"TOOLBOX_ORIGIN": "http://127.0.0.1:8080", "TOOLBOX_OIDC_ISSUER": "https://integrator.example.test",
		"TOOLBOX_OIDC_CLIENT_ID": "test-client", "TOOLBOX_OIDC_CLIENT_SECRET": "test-secret",
		"TOOLBOX_SESSION_PEPPER": base64.StdEncoding.EncodeToString([]byte(strings.Repeat("p", 32))),
		"DATABASE_URL":           "postgres://test:test@127.0.0.1/test?sslmode=disable",
		"OPENBAO_ADDR":           "http://127.0.0.1:8200", "OPENBAO_TOKEN": "test-token",
	}
	load := func(values map[string]string) (runtimeConfig, error) {
		return loadConfig(func(k string) string { return values[k] })
	}
	if cfg, err := load(valid); err != nil || cfg.origin != valid["TOOLBOX_ORIGIN"] || len(cfg.pepper) != 32 {
		t.Fatalf("valid config rejected: %v", err)
	}
	for _, key := range []string{"TOOLBOX_ORIGIN", "TOOLBOX_OIDC_ISSUER", "TOOLBOX_OIDC_CLIENT_ID", "TOOLBOX_OIDC_CLIENT_SECRET", "TOOLBOX_SESSION_PEPPER", "DATABASE_URL", "OPENBAO_ADDR", "OPENBAO_TOKEN"} {
		t.Run("missing "+key, func(t *testing.T) {
			values := copySettings(valid)
			delete(values, key)
			if _, err := load(values); err == nil || strings.Contains(err.Error(), "test-secret") {
				t.Fatal("missing setting accepted or secret disclosed")
			}
		})
	}
	for _, tc := range []struct{ key, value string }{
		{"TOOLBOX_MODE", ""}, {"TOOLBOX_MODE", "production"},
		{"TOOLBOX_ADDR", "0.0.0.0:8080"}, {"TOOLBOX_ADDR", "example.test:8080"}, {"TOOLBOX_ADDR", "127.0.0.1:0"},
		{"TOOLBOX_ORIGIN", "http://127.0.0.1:8081"}, {"TOOLBOX_ORIGIN", "http://localhost:8080"},
		{"TOOLBOX_ORIGIN", "https://127.0.0.1:8080"}, {"TOOLBOX_ORIGIN", "http://127.0.0.1:8080/"},
		{"TOOLBOX_ORIGIN", "http://user@127.0.0.1:8080"}, {"TOOLBOX_ORIGIN", "http://127.0.0.1:8080?bad=1"},
		{"TOOLBOX_OIDC_ISSUER", "http://integrator.example.test"}, {"TOOLBOX_OIDC_ISSUER", "https://user@integrator.example.test"},
		{"TOOLBOX_OIDC_ISSUER", "https://integrator.example.test?bad=1"}, {"TOOLBOX_SESSION_PEPPER", "not-base64"},
		{"TOOLBOX_SESSION_PEPPER", base64.StdEncoding.EncodeToString(make([]byte, 16))},
		{"TOOLBOX_OIDC_CLIENT_ID", "bad\nclient"},
	} {
		t.Run(tc.key+" invalid "+tc.value, func(t *testing.T) {
			values := copySettings(valid)
			values[tc.key] = tc.value
			if _, err := load(values); err == nil {
				t.Fatal("invalid setting accepted")
			}
		})
	}
}

func copySettings(values map[string]string) map[string]string {
	out := make(map[string]string, len(values))
	for k, v := range values {
		out[k] = v
	}
	return out
}

func TestFixtureConfig(t *testing.T) {
	cfg, err := loadConfig(func(k string) string {
		if k == "TOOLBOX_MODE" {
			return "fixture"
		}
		return ""
	})
	if err != nil || cfg.addr != "127.0.0.1:8080" || cfg.origin != "http://127.0.0.1:8080" {
		t.Fatalf("fixture defaults failed: %v", err)
	}
}

func TestWorkspaceLocalConfigRequiresRealProvidersAndStableCrypto(t *testing.T) {
	valid := map[string]string{
		"TOOLBOX_MODE": "workspace-local", "TOOLBOX_ADDR": "127.0.0.1:8080",
		"TOOLBOX_ORIGIN": "http://127.0.0.1:8080", "TOOLBOX_OIDC_ISSUER": "https://idp.example.test",
		"TOOLBOX_OIDC_CLIENT_ID": "owner-client", "TOOLBOX_OIDC_CLIENT_SECRET": "owner-secret",
		"TOOLBOX_SESSION_PEPPER":    base64.StdEncoding.EncodeToString([]byte(strings.Repeat("s", 32))),
		"TOOLBOX_CREDENTIAL_PEPPER": base64.StdEncoding.EncodeToString([]byte(strings.Repeat("c", 32))),
		"TOOLBOX_SIGNING_SEED":      base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32))),
		"TOOLBOX_SIGNING_KEY_ID":    "workspace-local-1",
		"DATABASE_URL":              "postgres://test:test@127.0.0.1/test?sslmode=disable",
		"OPENBAO_ADDR":              "http://127.0.0.1:8200", "OPENBAO_TOKEN": "test-token",
		"TOOLBOX_GOOGLE_CLIENT_ID": "google-client", "TOOLBOX_GOOGLE_CLIENT_SECRET": "google-secret",
		"TOOLBOX_GOOGLE_PKCE_VALIDATED": "true", "TOOLBOX_GOOGLE_PICKER_API_KEY": "public-test-key",
		"TOOLBOX_GOOGLE_PROJECT_NUMBER": "1234567890",
	}
	load := func(values map[string]string) (runtimeConfig, error) {
		return loadConfig(func(k string) string { return values[k] })
	}
	if cfg, err := load(valid); err != nil || cfg.mode != "workspace-local" {
		t.Fatalf("valid real workspace config rejected: %v", err)
	}
	for _, key := range []string{"TOOLBOX_CREDENTIAL_PEPPER", "TOOLBOX_SIGNING_SEED", "TOOLBOX_SIGNING_KEY_ID", "TOOLBOX_GOOGLE_CLIENT_ID", "TOOLBOX_GOOGLE_CLIENT_SECRET", "TOOLBOX_GOOGLE_PKCE_VALIDATED", "TOOLBOX_GOOGLE_PICKER_API_KEY", "TOOLBOX_GOOGLE_PROJECT_NUMBER"} {
		t.Run("missing "+key, func(t *testing.T) {
			values := copySettings(valid)
			delete(values, key)
			if _, err := load(values); err == nil || strings.Contains(err.Error(), "google-secret") {
				t.Fatal("missing real setting accepted or secret exposed")
			}
		})
	}
	for _, key := range []string{"TOOLBOX_CREDENTIAL_PEPPER", "TOOLBOX_SIGNING_SEED"} {
		values := copySettings(valid)
		values[key] = valid["TOOLBOX_SESSION_PEPPER"]
		if _, err := load(values); err == nil {
			t.Fatal("session and credential/signing material must be independent")
		}
	}
	values := copySettings(valid)
	values["TOOLBOX_GOOGLE_PKCE_VALIDATED"] = "false"
	if _, err := load(values); err == nil {
		t.Fatal("unverified real-client PKCE gate accepted")
	}
}
