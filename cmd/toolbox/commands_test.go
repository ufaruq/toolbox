package main

import (
	"errors"
	"github.com/ufaruq/toolbox/internal/secretstore"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func arguments(t *testing.T, args ...string) {
	t.Helper()
	old := os.Args
	os.Args = append([]string{"toolbox"}, args...)
	t.Cleanup(func() { os.Args = old })
}
func TestProductionServeCannotBeEnabledByFlags(t *testing.T) {
	arguments(t, "serve")
	t.Setenv("TOOLBOX_MODE", "fixture")
	t.Setenv("TOOLBOX_OWNER_OIDC_VALIDATED", "true")
	t.Setenv("TOOLBOX_PKCE_VALIDATED", "true")
	if err := run(); !errors.Is(err, errProductionGate) {
		t.Fatal(err)
	}
}
func TestHealthcheckDoesNotFollowRedirect(t *testing.T) {
	visited := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { visited = true; w.WriteHeader(200) }))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 302) }))
	defer source.Close()
	arguments(t, "healthcheck")
	t.Setenv("TOOLBOX_MODE", "fixture")
	t.Setenv("TOOLBOX_ORIGIN", source.URL)
	t.Setenv("TOOLBOX_DATABASE_FILE", "")
	if err := run(); !errors.Is(err, secretstore.ErrUnavailable) || visited {
		t.Fatal("redirect followed", err)
	}
}
