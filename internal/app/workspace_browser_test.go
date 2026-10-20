package app_test

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ufaruq/toolbox/internal/app"
	"github.com/ufaruq/toolbox/internal/connectors/gdrive"
	"github.com/ufaruq/toolbox/internal/oauth"
	"github.com/ufaruq/toolbox/internal/ownerlogin"
	"github.com/ufaruq/toolbox/internal/security"
	"github.com/ufaruq/toolbox/internal/server"
	"github.com/ufaruq/toolbox/internal/store"
	"github.com/ufaruq/toolbox/internal/testutil/oidcidp"
	"github.com/ufaruq/toolbox/internal/tokens"
)

// Only the test composes simulated Google consent with the live-runtime UI.
// The executable's workspace factory always selects the fixed Google endpoints.
func TestWorkspaceBrowserFlow(t *testing.T) {
	if os.Getenv("TOOLBOX_TEST_WORKSPACE_BROWSER") != "1" {
		t.Skip("requires pinned Playwright and Chromium")
	}
	idp := oidcidp.New(t)
	ts := httptest.NewUnstartedServer(nil)
	t.Cleanup(ts.Close)
	origin := "http://" + ts.Listener.Addr().String()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	repo, secrets := store.NewMemory(), tokens.NewMemorySecretStore()
	provider, err := ownerlogin.NewProvider(ctx, ownerlogin.ProviderConfig{Issuer: idp.Issuer, ClientID: idp.ClientID, ClientSecret: idp.ClientSecret, RedirectURI: origin + "/auth/oidc/callback"}, idp.TLSClient())
	if err != nil {
		t.Fatal(err)
	}
	sessionPepper := []byte(strings.Repeat("s", 32))
	login, err := ownerlogin.NewService(repo, secrets, provider, ownerlogin.ServiceConfig{Issuer: idp.Issuer, ClientID: idp.ClientID, RedirectURI: origin + "/auth/oidc/callback", Pepper: sessionPepper})
	if err != nil {
		t.Fatal(err)
	}
	google, err := oauth.NewFixtureProvider("synthetic-google", origin+"/oauth/callback")
	if err != nil {
		t.Fatal(err)
	}
	flow, err := oauth.NewService(repo, secrets, google)
	if err != nil {
		t.Fatal(err)
	}
	integration := &app.Integration{OAuth: flow, TokenManager: &tokens.Manager{Repository: repo, Secrets: secrets, Provider: google}, Drive: gdrive.NewFixture(&app.FixtureDrive{})}
	signer, err := security.NewSigner(origin, "synthetic", ed25519.NewKeyFromSeed(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	api, err := server.New(server.Config{Repository: repo, Origin: origin, Signer: signer, Pepper: []byte(strings.Repeat("c", 32)), SessionPepper: sessionPepper, OwnerLogin: login, WorkspaceLocal: true, Picker: server.PickerConfig{APIKey: "synthetic-picker-key", ProjectNumber: "123456"}}, integration)
	if err != nil {
		t.Fatal(err)
	}
	ts.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/fixture/google/authorize" {
			callback, err := google.Authorize(r.Context(), origin+r.URL.String(), "synthetic-workspace-account")
			if err != nil {
				http.Error(w, "synthetic consent failed", 400)
				return
			}
			http.Redirect(w, r, callback+"&scope=openid&authuser=0&hd=example.test", 303)
			return
		}
		api.ServeHTTP(w, r)
	})
	ts.Start()
	_, source, _, _ := runtime.Caller(0)
	command := exec.CommandContext(ctx, "python3", filepath.Join(filepath.Dir(source), "../../tests/browser/workspace_e2e.py"))
	for _, v := range os.Environ() {
		k, _, _ := strings.Cut(v, "=")
		if k != "DEBUG" && k != "DEBUG_FILE" && k != "PWDEBUG" && !strings.HasPrefix(k, "PW_TEST_DEBUG") && !strings.HasPrefix(k, "PW_TEST_TRACE") {
			command.Env = append(command.Env, v)
		}
	}
	command.Env = append(command.Env, "TOOLBOX_WORKSPACE_TEST_ORIGIN="+origin, "TOOLBOX_WORKSPACE_TEST_IDP="+idp.Issuer, "TOOLBOX_WORKSPACE_TEST_SPKI="+idp.SPKIHash())
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("synthetic Workspace browser flow failed: %s", out)
	} else {
		t.Log(strings.TrimSpace(string(out)))
	}
}
