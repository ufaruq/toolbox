package server

import (
	"context"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ufaruq/toolbox/internal/ownerlogin"
	"github.com/ufaruq/toolbox/internal/store"
	"github.com/ufaruq/toolbox/internal/testutil/oidcidp"
	"github.com/ufaruq/toolbox/internal/tokens"
)

// The protocol tests run without Python. This separate gate requires the pinned
// Playwright installation and never connects to a live identity provider.
func TestOIDCBrowserFlow(t *testing.T) {
	if os.Getenv("TOOLBOX_TEST_OIDC_BROWSER") != "1" {
		t.Skip("set TOOLBOX_TEST_OIDC_BROWSER=1 after installing tests/browser/requirements.txt and Chromium")
	}
	python := os.Getenv("TOOLBOX_TEST_PYTHON")
	if python == "" {
		python = "python3"
	}
	python, err := exec.LookPath(python)
	if err != nil {
		t.Fatal("OIDC browser test requires Python; TOOLBOX_TEST_PYTHON can select the runner")
	}

	idp := oidcidp.New(t)
	app := httptest.NewUnstartedServer(nil)
	t.Cleanup(app.Close)
	origin := "http://" + app.Listener.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	provider, err := ownerlogin.NewProvider(ctx, ownerlogin.ProviderConfig{
		Issuer: idp.Issuer, ClientID: idp.ClientID, ClientSecret: idp.ClientSecret,
		RedirectURI: origin + "/auth/oidc/callback",
	}, idp.TLSClient())
	if err != nil {
		t.Fatal("create synthetic OIDC provider:", err)
	}
	repo := store.NewMemory()
	pepper := []byte(strings.Repeat("b", 32))
	login, err := ownerlogin.NewService(repo, tokens.NewMemorySecretStore(), provider, ownerlogin.ServiceConfig{
		Issuer: idp.Issuer, ClientID: idp.ClientID,
		RedirectURI: origin + "/auth/oidc/callback", Pepper: pepper,
	})
	if err != nil {
		t.Fatal("create synthetic owner login:", err)
	}
	handler, err := New(Config{Repository: repo, Pepper: pepper, Origin: origin, OwnerOnly: true, OwnerLogin: login}, nil)
	if err != nil {
		t.Fatal("create owner-only test server:", err)
	}
	app.Config.Handler = handler
	app.Start()

	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate OIDC browser runner")
	}
	runner := filepath.Join(filepath.Dir(source), "../../tests/browser/oidc_e2e.py")
	browserCtx, stop := context.WithTimeout(ctx, 2*time.Minute)
	defer stop()
	command := exec.CommandContext(browserCtx, python, runner)
	settings := map[string]string{
		"TOOLBOX_OIDC_TEST_APP_ORIGIN": origin,
		"TOOLBOX_OIDC_TEST_IDP_ORIGIN": idp.Issuer,
		"TOOLBOX_OIDC_TEST_IDP_SPKI":   idp.SPKIHash(),
	}
	for _, value := range os.Environ() {
		key, _, _ := strings.Cut(value, "=")
		// Playwright debug output can contain authorization URLs and cookies.
		if key == "DEBUG" || key == "DEBUG_FILE" || key == "PWDEBUG" || strings.HasPrefix(key, "PW_TEST_DEBUG") || strings.HasPrefix(key, "PW_TEST_TRACE") {
			continue
		}
		if _, replaced := settings[key]; !replaced {
			command.Env = append(command.Env, value)
		}
	}
	for key, value := range settings {
		command.Env = append(command.Env, key+"="+value)
	}
	// The runner prints only a fixed stage, outcome, and artifact directory.
	// It deliberately suppresses raw Playwright exceptions and network traces.
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("synthetic OIDC browser flow failed: %s", output)
	}
	if idp.ExchangeCount() != 2 {
		t.Fatalf("want exactly two one-use browser code exchanges, got %d", idp.ExchangeCount())
	}
	t.Log(strings.TrimSpace(string(output)))
}
