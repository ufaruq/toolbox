package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ufaruq/toolbox/internal/domain"
	"github.com/ufaruq/toolbox/internal/identity"
	"github.com/ufaruq/toolbox/internal/store"
	"github.com/ufaruq/toolbox/internal/tokens"
)

func hostedEnv() map[string]string {
	return map[string]string{
		"TOOLBOX_MODE": "hosted", "TOOLBOX_PUBLIC_ORIGIN": "https://toolbox.example", "TOOLBOX_ADDR": "0.0.0.0:8080",
		"DATABASE_URL": "postgres://runtime:secret@db.example/toolbox?sslmode=verify-full",
		"OPENBAO_ADDR": "https://bao.example", "OPENBAO_MOUNT": "secret", "OPENBAO_TOKEN": "workload-token",
		"TOOLBOX_OKTA_ISSUER": "https://tenant.okta.example/oauth2/default", "TOOLBOX_OKTA_OWNER_CLIENT_ID": "owner-client", "TOOLBOX_OKTA_OWNER_CLIENT_SECRET": "owner-secret",
		"TOOLBOX_MCP_CLIENTS":  `{"web-client":"Claude.ai","code-client":"Claude Code"}`,
		"TOOLBOX_SIGNING_SEED": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, ed25519.SeedSize)), "TOOLBOX_SIGNING_KEY_ID": "deployment-key-1", "TOOLBOX_CREDENTIAL_PEPPER": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32)),
	}
}
func envReader(env map[string]string) func(string) string {
	return func(key string) string { return env[key] }
}
func TestHostedConfig(t *testing.T) {
	cfg, err := loadConfig(envReader(hostedEnv()))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != "hosted" || cfg.Origin != "https://toolbox.example" || cfg.Identity.Audience != "https://toolbox.example/mcp" || cfg.Identity.OwnerCallbackURL != "https://toolbox.example/auth/okta/callback" || cfg.Identity.AllowLoopbackHTTP {
		t.Fatalf("invalid hosted identity configuration")
	}
	if len(cfg.SigningSeed) != 32 || len(cfg.Pepper) != 32 || cfg.KeyID != "deployment-key-1" || len(cfg.Identity.Clients) != 2 {
		t.Fatal("persistent crypto or client configuration lost")
	}
}
func TestHostedConfigRejectsUnsafeOrMissingSettings(t *testing.T) {
	for _, key := range []string{"TOOLBOX_PUBLIC_ORIGIN", "DATABASE_URL", "OPENBAO_ADDR", "OPENBAO_TOKEN", "TOOLBOX_OKTA_ISSUER", "TOOLBOX_OKTA_OWNER_CLIENT_ID", "TOOLBOX_OKTA_OWNER_CLIENT_SECRET", "TOOLBOX_MCP_CLIENTS", "TOOLBOX_SIGNING_SEED", "TOOLBOX_SIGNING_KEY_ID", "TOOLBOX_CREDENTIAL_PEPPER"} {
		t.Run("missing "+key, func(t *testing.T) {
			env := hostedEnv()
			delete(env, key)
			if _, err := loadConfig(envReader(env)); err == nil {
				t.Fatal("accepted incomplete hosted configuration")
			}
		})
	}
	for name, change := range map[string]map[string]string{
		"invalid origin port": {"TOOLBOX_PUBLIC_ORIGIN": "https://toolbox.example:99999"},
		"plain origin":        {"TOOLBOX_PUBLIC_ORIGIN": "http://toolbox.example"}, "origin path": {"TOOLBOX_PUBLIC_ORIGIN": "https://toolbox.example/base"}, "origin query": {"TOOLBOX_PUBLIC_ORIGIN": "https://toolbox.example?"}, "origin credentials": {"TOOLBOX_PUBLIC_ORIGIN": "https://user:secret@toolbox.example"}, "origin fragment": {"TOOLBOX_PUBLIC_ORIGIN": "https://toolbox.example#bad"},
		"plain Okta": {"TOOLBOX_OKTA_ISSUER": "http://tenant.okta.example"}, "Okta query": {"TOOLBOX_OKTA_ISSUER": "https://tenant.okta.example?bad=1"}, "plain Bao": {"OPENBAO_ADDR": "http://openbao:8200"}, "fixture Bao token": {"OPENBAO_TOKEN": "fixture-only"},
		"DB no TLS": {"DATABASE_URL": "postgres://user:secret@db.example/toolbox?sslmode=disable"}, "DB insecure TLS": {"DATABASE_URL": "postgres://user:secret@db.example/toolbox?sslmode=require"}, "DB fallback": {"DATABASE_URL": "postgres://user:secret@db.example,other.example/toolbox?sslmode=verify-full"}, "DB Unix socket": {"DATABASE_URL": "postgres:///toolbox?host=/tmp&sslmode=verify-full"}, "DB no explicit TLS": {"DATABASE_URL": "postgres://user:secret@db.example/toolbox"},
		"short seed": {"TOOLBOX_SIGNING_SEED": base64.StdEncoding.EncodeToString([]byte("short"))}, "bad pepper": {"TOOLBOX_CREDENTIAL_PEPPER": "bad-base64"}, "blank key ID": {"TOOLBOX_SIGNING_KEY_ID": " "}, "invalid bind": {"TOOLBOX_ADDR": "0.0.0.0:99999"},
		"empty clients": {"TOOLBOX_MCP_CLIENTS": "{}"}, "array clients": {"TOOLBOX_MCP_CLIENTS": "[]"}, "blank client ID": {"TOOLBOX_MCP_CLIENTS": `{" ":"Code"}`}, "blank client label": {"TOOLBOX_MCP_CLIENTS": `{"code":""}`}, "duplicate clients": {"TOOLBOX_MCP_CLIENTS": `{"code":"First","code":"Second"}`}, "trailing clients": {"TOOLBOX_MCP_CLIENTS": `{"code":"Code"} {}`}, "audience as client": {"TOOLBOX_MCP_CLIENTS": `{"https://toolbox.example/mcp":"Code"}`},
	} {
		t.Run(name, func(t *testing.T) {
			env := hostedEnv()
			for k, v := range change {
				env[k] = v
			}
			if _, err := loadConfig(envReader(env)); err == nil {
				t.Fatal("accepted unsafe hosted configuration")
			} else if strings.Contains(err.Error(), "secret") {
				t.Fatal("configuration error leaked sensitive input")
			}
		})
	}
}
func TestFixtureConfigCompatibility(t *testing.T) {
	cfg, err := loadConfig(envReader(map[string]string{"TOOLBOX_MODE": "fixture"}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Addr != "127.0.0.1:8080" || cfg.Origin != "http://127.0.0.1:8080" {
		t.Fatal("fixture defaults changed")
	}
	if _, err := loadConfig(envReader(map[string]string{"TOOLBOX_MODE": "fixture", "TOOLBOX_ADDR": "0.0.0.0:8080"})); err == nil {
		t.Fatal("fixture exposed outside loopback")
	}
	if _, err := loadConfig(envReader(map[string]string{})); err == nil {
		t.Fatal("implicit mode accepted")
	}
}

// Runtime wiring is tested with in-memory dependencies and a fake identity; it
// does not pretend to validate live Okta, PostgreSQL or OpenBao connectivity.
type runtimeIdentity struct{}

func (runtimeIdentity) VerifyAccess(context.Context, string) (identity.Claims, error) {
	return identity.Claims{}, context.Canceled
}
func (runtimeIdentity) AuthorizationURL(string, string, string) (string, error) {
	return "https://tenant.okta.example/authorize", nil
}
func (runtimeIdentity) Complete(context.Context, string, string, string) (identity.Owner, error) {
	return identity.Owner{}, context.Canceled
}
func (runtimeIdentity) Clients() map[string]string {
	return map[string]string{"code-client": "Claude Code"}
}
func (runtimeIdentity) Issuer() string { return "https://tenant.okta.example/oauth2/default" }
func TestHostedWiringHasNoFixtureRoutes(t *testing.T) {
	cfg, err := loadConfig(envReader(hostedEnv()))
	if err != nil {
		t.Fatal(err)
	}
	api, err := newAPI(cfg, store.NewMemory(), tokens.NewMemorySecretStore(), runtimeIdentity{})
	if err != nil {
		t.Fatal(err)
	}
	for path, method := range map[string]string{"/fixture/login": http.MethodPost, "/fixture/authorize": http.MethodGet} {
		w := httptest.NewRecorder()
		api.ServeHTTP(w, httptest.NewRequest(method, path, nil))
		if w.Code >= 200 && w.Code < 400 {
			t.Fatalf("fixture route exposed: %s (%d)", path, w.Code)
		}
	}
}
func TestFixtureWiringStillSignsIn(t *testing.T) {
	cfg, err := loadConfig(envReader(map[string]string{"TOOLBOX_MODE": "fixture"}))
	if err != nil {
		t.Fatal(err)
	}
	api, err := newAPI(cfg, store.NewMemory(), tokens.NewMemorySecretStore(), nil)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/fixture/login", strings.NewReader(`{}`))
	r.Header.Set("Origin", cfg.Origin)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	api.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("fixture login failed: %d %s", w.Code, w.Body.String())
	}
}

func TestRuntimeCommandSeparation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	minimal := map[string]string{"TOOLBOX_MODE": "hosted", "DATABASE_URL": hostedEnv()["DATABASE_URL"]}
	if err := runCommand(ctx, []string{"migrate"}, envReader(minimal)); !errors.Is(err, context.Canceled) {
		t.Fatalf("migration should reach database without serving settings: %v", err)
	}
	if err := runCommand(ctx, nil, envReader(minimal)); !errors.Is(err, errRuntimeConfig) {
		t.Fatal("runtime accepted migration-only settings")
	}
	for _, args := range [][]string{{"unknown"}, {"migrate", "extra"}} {
		if err := runCommand(ctx, args, envReader(hostedEnv())); !errors.Is(err, errRuntimeConfig) {
			t.Fatal("invalid command accepted")
		}
	}
}
func TestHealthcheckUsesLocalReadinessWithoutFullConfig(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusServiceUnavailable, http.StatusFound} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/readyz" {
					t.Errorf("unexpected healthcheck path: %s", r.URL.Path)
				}
				w.Header().Set("Location", "https://external.example")
				w.WriteHeader(status)
			}))
			defer ts.Close()
			addr := strings.TrimPrefix(ts.URL, "http://")
			err := runCommand(context.Background(), []string{"healthcheck"}, envReader(map[string]string{"TOOLBOX_ADDR": addr}))
			if (err == nil) != (status == http.StatusOK) {
				t.Fatalf("healthcheck status %d: %v", status, err)
			}
		})
	}
}
func TestHostedSigningAndPepperSurviveRestart(t *testing.T) {
	cfg, err := loadConfig(envReader(hostedEnv()))
	if err != nil {
		t.Fatal(err)
	}
	first, err := newAPI(cfg, store.NewMemory(), tokens.NewMemorySecretStore(), runtimeIdentity{})
	if err != nil {
		t.Fatal(err)
	}
	second, err := newAPI(cfg, store.NewMemory(), tokens.NewMemorySecretStore(), runtimeIdentity{})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	token, err := first.Signer.Mint(domain.Grant{ID: "grant", OwnerID: "owner", AgentID: "agent", ConnectionID: "connection", Tool: domain.Tool, Action: domain.Action, FileID: "file", Epoch: 1, Version: 1, NotBefore: now, ExpiresAt: now.Add(time.Hour)}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := second.Signer.Verify(token, now); err != nil {
		t.Fatal("persisted signing key changed across runtime construction")
	}
	if !bytes.Equal(first.Pepper, second.Pepper) || !bytes.Equal(second.Pepper, cfg.Pepper) {
		t.Fatal("persisted pepper changed")
	}
	w := httptest.NewRecorder()
	second.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/v1/config", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"google_available":false`) {
		t.Fatal("hosted runtime advertised fixture Google availability")
	}
}

type schemaFailureRepository struct {
	domain.Repository
	fail bool
}

func (r *schemaFailureRepository) Ping(context.Context) error { return nil }
func (r *schemaFailureRepository) Transact(ctx context.Context, fn func(*domain.State) error) error {
	if r.fail {
		return errors.New("schema unavailable")
	}
	return r.Repository.Transact(ctx, fn)
}
func TestReadinessRejectsMissingSchemaWithReachableDatabase(t *testing.T) {
	cfg, err := loadConfig(envReader(hostedEnv()))
	if err != nil {
		t.Fatal(err)
	}
	repo := &schemaFailureRepository{Repository: store.NewMemory()}
	api, err := newAPI(cfg, repo, tokens.NewMemorySecretStore(), runtimeIdentity{})
	if err != nil {
		t.Fatal(err)
	}
	repo.fail = true
	w := httptest.NewRecorder()
	api.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("readiness accepted missing schema: %d", w.Code)
	}
}

func TestHostedStartupDependencyCheckRejectsMissingSchema(t *testing.T) {
	repo := &schemaFailureRepository{Repository: store.NewMemory(), fail: true}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := checkRuntimeDependencies(ctx, repo, tokens.NewMemorySecretStore()); err == nil {
		t.Fatal("startup dependency check accepted an unmigrated schema")
	}
}

func TestHostedRejectsNoncanonicalBrowserOrigin(t *testing.T) {
	for _, origin := range []string{"https://toolbox.example:443", "https://TOOLBOX.EXAMPLE", "https://toolbox.example:08443", "https://toolbox.example:", "https://tööls.example", "https://[2001:0db8::1]", "https://127.1.", "https://0x7f000001.", "https://127.1", "https://0x7f000001", "https://[fe80::1%25eth0]"} {
		t.Run(origin, func(t *testing.T) {
			env := hostedEnv()
			env["TOOLBOX_PUBLIC_ORIGIN"] = origin
			if _, err := loadConfig(envReader(env)); err == nil {
				t.Fatal("accepted origin whose browser serialization differs")
			}
		})
	}
}

type outdatedMigrationRepository struct{ domain.Repository }

func (r outdatedMigrationRepository) CheckSchema(context.Context) error {
	return errors.New("migration missing")
}
func TestReadinessRejectsIncompleteMigrationLedger(t *testing.T) {
	cfg, err := loadConfig(envReader(hostedEnv()))
	if err != nil {
		t.Fatal(err)
	}
	repo := outdatedMigrationRepository{store.NewMemory()}
	api, err := newAPI(cfg, repo, tokens.NewMemorySecretStore(), runtimeIdentity{})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	api.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if w.Code != 503 {
		t.Fatalf("incomplete migration readiness: %d", w.Code)
	}
	if err := checkRuntimeDependencies(context.Background(), repo, tokens.NewMemorySecretStore()); err == nil {
		t.Fatal("startup accepted incomplete migration ledger")
	}
}
