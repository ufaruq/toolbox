package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func keycloakSettings() map[string]string {
	return map[string]string{
		"TOOLBOX_ORIGIN":                       "http://127.0.0.1:8080",
		"TOOLBOX_KEYCLOAK_REALM":               "toolbox",
		"TOOLBOX_KEYCLOAK_OWNER_CLIENT_ID":     "toolbox-owner",
		"TOOLBOX_KEYCLOAK_OWNER_CLIENT_SECRET": "fixture-owner-private-secret",
		"TOOLBOX_KEYCLOAK_OKTA_ISSUER":         "https://tenant.okta.example",
		"TOOLBOX_KEYCLOAK_OKTA_CLIENT_ID":      "broker-client",
		"TOOLBOX_KEYCLOAK_OKTA_CLIENT_SECRET":  "fixture-upstream-private-secret",
	}
}

func TestKeycloakConfigWritesPrivateFile(t *testing.T) {
	values := keycloakSettings()
	path := filepath.Join(t.TempDir(), "private", "realm.json")
	if err := runKeycloakConfig(func(k string) string { return values[k] }, path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("private config permissions: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil || !bytes.Contains(data, []byte("fixture-owner-private-secret")) {
		t.Fatal("realm config not written")
	}
}

func TestKeycloakConfigRefusesOverwrite(t *testing.T) {
	values := keycloakSettings()
	path := filepath.Join(t.TempDir(), "realm.json")
	if err := os.WriteFile(path, []byte("keep-original"), 0600); err != nil {
		t.Fatal(err)
	}
	err := runKeycloakConfig(func(k string) string { return values[k] }, path)
	data, _ := os.ReadFile(path)
	if err == nil || string(data) != "keep-original" || strings.Contains(err.Error(), "private-secret") {
		t.Fatal("overwrote config or exposed a secret")
	}
}

func TestKeycloakLinkRejectsMissingCredentials(t *testing.T) {
	var out bytes.Buffer
	err := runKeycloakLink(func(k string) string {
		if k == "TOOLBOX_KEYCLOAK_ADMIN_CLIENT_SECRET" {
			return "never-print-this-secret"
		}
		return ""
	}, false, &out)
	if err == nil || out.Len() != 0 || strings.Contains(err.Error(), "never-print-this-secret") {
		t.Fatal("invalid migration config accepted or secret exposed")
	}
}
