package app_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"github.com/jackc/pgx/v5"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ufaruq/toolbox/internal/app"
	"github.com/ufaruq/toolbox/internal/connectors/gdrive"
	"github.com/ufaruq/toolbox/internal/domain"
	"github.com/ufaruq/toolbox/internal/oauth"
	"github.com/ufaruq/toolbox/internal/security"
	"github.com/ufaruq/toolbox/internal/server"
	"github.com/ufaruq/toolbox/internal/store"
	"github.com/ufaruq/toolbox/internal/tokens"
)

type countSecrets struct {
	*tokens.MemorySecretStore
	Reads atomic.Int64
}

func (s *countSecrets) Get(ctx context.Context, path string) (tokens.Bundle, int64, error) {
	s.Reads.Add(1)
	return s.MemorySecretStore.Get(ctx, path)
}

type harness struct {
	t                                                                   *testing.T
	repo                                                                domain.Repository
	ts                                                                  *httptest.Server
	client                                                              *http.Client
	csrf, credential, agentID, connection, requestID, grant, delegation string
	drive                                                               *app.FixtureDrive
	secrets                                                             *countSecrets
	api                                                                 *server.Server
}

func newHarness(t *testing.T, repo domain.Repository) *harness {
	t.Helper()
	if repo == nil {
		repo = store.NewMemory()
	}
	h := &harness{t: t, repo: repo, drive: &app.FixtureDrive{}, secrets: &countSecrets{MemorySecretStore: tokens.NewMemorySecretStore()}}
	h.ts = httptest.NewUnstartedServer(nil)
	origin := "http://" + h.ts.Listener.Addr().String()
	provider, e := oauth.NewFixtureProvider("fixture-client", origin+"/oauth/callback")
	if e != nil {
		t.Fatal(e)
	}
	flow, e := oauth.NewService(repo, h.secrets, provider)
	if e != nil {
		t.Fatal(e)
	}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := security.NewSigner(origin, "fixture", key)
	integration := &app.Integration{OAuth: flow, TokenManager: &tokens.Manager{Repository: repo, Secrets: h.secrets, Provider: provider}, Drive: gdrive.NewFixture(h.drive), Fixture: provider}
	h.api, e = server.New(server.Config{Repository: repo, Signer: signer, Pepper: []byte(strings.Repeat("x", 32)), Origin: origin, Fixture: true}, integration)
	if e != nil {
		t.Fatal(e)
	}
	h.ts.Config.Handler = h.api
	h.ts.Start()
	t.Cleanup(h.ts.Close)
	jar, _ := cookiejar.New(nil)
	h.client = &http.Client{Jar: jar}
	v := h.call("POST", "/fixture/login", map[string]any{}, "", "", 200)
	h.csrf = v["csrf_token"].(string)
	v = h.call("POST", "/v1/agents", map[string]any{"name": "Test agent"}, "", "", 201)
	h.credential = v["credential"].(string)
	h.agentID = v["agent_id"].(string)
	v = h.call("POST", "/v1/connections/google/start", map[string]any{}, "", "", 200)
	resp, e := h.client.Get(v["authorization_url"].(string))
	if e != nil {
		t.Fatal(e)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("oauth redirect %d: %s", resp.StatusCode, b)
	}
	e = repo.Transact(context.Background(), func(st *domain.State) error {
		for _, c := range st.Connections {
			if c.Status == "active" && c.ClientID == "fixture-client" {
				h.connection = c.ID
			}
		}
		return nil
	})
	if e != nil || h.connection == "" {
		t.Fatal("connection not active", e)
	}
	return h
}
func (h *harness) call(method, path string, data any, credential, delegation string, want int) map[string]any {
	h.t.Helper()
	var raw []byte
	switch v := data.(type) {
	case string:
		raw = []byte(v)
	case nil:
	default:
		raw, _ = json.Marshal(v)
	}
	req, _ := http.NewRequest(method, h.ts.URL+path, bytes.NewReader(raw))
	req.Header.Set("Origin", h.ts.URL)
	if data != nil {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", h.csrf)
	}
	if credential != "" {
		req.Header.Set("Authorization", "Bearer "+credential)
	}
	if delegation != "" {
		req.Header.Set("Toolbox-Delegation", delegation)
	}
	resp, e := h.client.Do(req)
	if e != nil {
		h.t.Fatal(e)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != want {
		h.t.Fatalf("%s %s: want %d got %d %s", method, path, want, resp.StatusCode, b)
	}
	v := map[string]any{}
	if len(b) > 0 && json.Unmarshal(b, &v) != nil {
		h.t.Fatalf("non-JSON: %s", b)
	}
	return v
}
func (h *harness) approve() {
	h.t.Helper()
	v := h.call("POST", "/v1/delegation-requests", map[string]any{"tool": domain.Tool, "file_id": "doc-A", "duration_seconds": 3600}, h.credential, "", 201)
	h.requestID = v["request_id"].(string)
	v = h.call("POST", "/v1/delegation-requests/"+h.requestID+"/review", map[string]any{"connection_id": h.connection}, "", "", 200)
	v = h.call("POST", "/v1/delegation-requests/"+h.requestID+"/approve", map[string]any{"connection_id": h.connection, "version": v["version"], "digest": v["digest"]}, "", "", 201)
	h.grant = v["grant_id"].(string)
	v = h.call("POST", "/v1/delegation-tokens", map[string]any{"grant_id": h.grant}, h.credential, "", 200)
	h.delegation = v["delegation_token"].(string)
}
func (h *harness) invoke(file string, want int) map[string]any {
	return h.call("POST", "/v1/tool-invocations", map[string]any{"tool": domain.Tool, "grant_id": h.grant, "arguments": map[string]string{"file_id": file}}, h.credential, h.delegation, want)
}
func TestAllowedReadAndAuditIsolation(t *testing.T) {
	h := newHarness(t, nil)
	h.approve()
	before := h.drive.Calls.Load()
	v := h.invoke("doc-A", 200)
	if h.drive.Calls.Load() != before+2 || !strings.Contains(v["content"].(string), "Synthetic document doc-A") {
		t.Fatal("wrong export")
	}
	b, _ := json.Marshal(v)
	if bytes.Contains(b, []byte("fixture-access")) || bytes.Contains(b, []byte("fixture-refresh")) {
		t.Fatal("token leaked to agent")
	}
	if e := h.repo.Transact(context.Background(), func(st *domain.State) error {
		seen := false
		for _, a := range st.Audits {
			b, _ := json.Marshal(a)
			if bytes.Contains(b, []byte("Synthetic document")) || bytes.Contains(b, []byte("fixture-access")) || bytes.Contains(b, []byte("fixture-refresh")) {
				t.Fatal("secret or document leaked to audit")
			}
			if a.Outcome == "succeeded" && a.ActorID == h.agentID && a.SubjectID == "11111111-1111-4111-8111-111111111111" {
				seen = true
			}
		}
		if !seen {
			t.Fatal("missing actor+subject audit")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
}
func TestDeniedShapesNeverTouchProviderOrSecrets(t *testing.T) {
	h := newHarness(t, nil)
	h.approve()
	for _, body := range []string{`{"tool":"google_drive.write_document.v1","grant_id":"` + h.grant + `","arguments":{"file_id":"doc-A"}}`, `{"tool":"` + domain.Tool + `","grant_id":"` + h.grant + `","arguments":{"file_id":"doc-A","method":"PATCH"}}`, `{"tool":"` + domain.Tool + `","grant_id":"` + h.grant + `","arguments":{"file_id":"doc-A","body":"write"}}`, `{"tool":"` + domain.Tool + `","grant_id":"` + h.grant + `","arguments":{"file_id":"../doc-A"}}`, `{"tool":"` + domain.Tool + `","grant_id":"` + h.grant + `","arguments":{"file_id":"doc-A","file_id":"doc-B"}}`, `{"Tool":"` + domain.Tool + `","grant_id":"` + h.grant + `","arguments":{"file_id":"doc-A"}}`} {
		before, reads := h.drive.Calls.Load(), h.secrets.Reads.Load()
		h.call("POST", "/v1/tool-invocations", body, h.credential, h.delegation, 400)
		if before != h.drive.Calls.Load() || reads != h.secrets.Reads.Load() {
			t.Fatal("denied schema reached credential/provider boundary")
		}
	}
	before, reads := h.drive.Calls.Load(), h.secrets.Reads.Load()
	v := h.invoke("doc-B", 403)
	if v["error"] != "RESOURCE_NOT_ALLOWED" || before != h.drive.Calls.Load() || reads != h.secrets.Reads.Load() {
		t.Fatal("other document was not denied before secrets")
	}
}
func TestWrongAgentExpiredRevokedAndEpoch(t *testing.T) {
	for _, name := range []string{"wrong-agent", "expired", "revoked", "epoch", "credential-revoked"} {
		t.Run(name, func(t *testing.T) {
			var clockOffset atomic.Int64
			h := newHarness(t, store.NewMemoryWithClock(func() time.Time { return time.Now().Add(time.Duration(clockOffset.Load())) }))
			h.approve()
			switch name {
			case "wrong-agent":
				v := h.call("POST", "/v1/agents", map[string]any{"name": "Other agent"}, "", "", 201)
				h.credential = v["credential"].(string)
			case "revoked":
				h.call("POST", "/v1/grants/"+h.grant+"/revoke", map[string]any{}, "", "", 200)
			case "credential-revoked":
				id, _, _ := security.CredentialParts(h.credential)
				h.call("POST", "/v1/credentials/"+id+"/revoke", map[string]any{}, "", "", 200)
			case "epoch":
				_ = h.repo.Transact(context.Background(), func(st *domain.State) error {
					c := st.Connections[h.connection]
					c.Epoch++
					st.Connections[c.ID] = c
					return nil
				})
			case "expired":
				clockOffset.Store(int64(2 * time.Hour))
			}
			before, reads := h.drive.Calls.Load(), h.secrets.Reads.Load()
			want := 403
			if name == "credential-revoked" {
				want = 401
			}
			h.invoke("doc-A", want)
			if before != h.drive.Calls.Load() || reads != h.secrets.Reads.Load() {
				t.Fatal("denied request reached secret/provider")
			}
		})
	}
}
func TestRevokedDuringFetchDiscardsBufferedContent(t *testing.T) {
	h := newHarness(t, nil)
	h.approve()
	h.drive.After = func(r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/export") {
			if e := h.repo.Transact(context.Background(), func(st *domain.State) error {
				g := st.Grants[h.grant]
				now := st.Now
				g.RevokedAt = &now
				st.Grants[g.ID] = g
				return nil
			}); e != nil {
				t.Error(e)
			}
		}
	}
	v := h.invoke("doc-A", 403)
	if v["error"] != "GRANT_REVOKED" || v["content"] != nil {
		t.Fatal("revoked buffered content returned")
	}
}
func TestOwnerCSRFAndApprovalReplay(t *testing.T) {
	h := newHarness(t, nil)
	h.approve()
	h.call("POST", "/v1/delegation-requests/"+h.requestID+"/approve", map[string]any{"connection_id": h.connection, "version": 1, "digest": "wrong"}, "", "", 403)
	csrf := h.csrf
	h.csrf = "wrong"
	h.call("POST", "/v1/grants/"+h.grant+"/revoke", map[string]any{}, "", "", 403)
	h.csrf = csrf
	h.invoke("doc-A", 200)
}
func TestDisconnectBlocksAndCleansUp(t *testing.T) {
	h := newHarness(t, nil)
	h.approve()
	h.call("POST", "/v1/connections/"+h.connection+"/disconnect", map[string]any{}, "", "", 202)
	before := h.drive.Calls.Load()
	h.invoke("doc-A", 403)
	if h.drive.Calls.Load() != before {
		t.Fatal("disconnect allowed dispatch")
	}
	if e := h.api.CleanupOnce(context.Background()); e != nil {
		t.Fatal(e)
	}
	_ = h.repo.Transact(context.Background(), func(st *domain.State) error {
		if st.Connections[h.connection].Status != "disconnected" {
			t.Fatal("cleanup incomplete")
		}
		return nil
	})
}
func TestPostgresFullAPIFlow(t *testing.T) {
	dsn := os.Getenv("TOOLBOX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TOOLBOX_TEST_DATABASE_URL for actual PostgreSQL API test")
	}
	// Keep API fixtures isolated across repeated runs. Their provider secrets are
	// ephemeral, so selecting a connection retained by an earlier run is invalid.
	ctx := context.Background()
	admin, e := pgx.Connect(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	schema := "toolbox_api_test_" + strconv.FormatInt(time.Now().UnixNano(), 10)
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, e = admin.Exec(ctx, "CREATE SCHEMA "+quoted); e != nil {
		admin.Close(ctx)
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec(ctx, "DROP SCHEMA "+quoted+" CASCADE"); err != nil {
			t.Error(err)
		}
		admin.Close(ctx)
	})
	isolatedDSN := dsn + " search_path=" + schema
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		u, err := url.Parse(dsn)
		if err != nil {
			t.Fatal("invalid PostgreSQL test URL")
		}
		q := u.Query()
		q.Set("search_path", schema)
		u.RawQuery = q.Encode()
		isolatedDSN = u.String()
	}
	repo, e := store.OpenPostgres(ctx, isolatedDSN)
	if e != nil {
		t.Fatal(e)
	}
	defer repo.Close()
	if e = repo.Migrate(context.Background()); e != nil {
		t.Fatal(e)
	}
	h := newHarness(t, repo)
	h.approve()
	h.invoke("doc-A", 200)
	h.call("POST", "/v1/grants/"+h.grant+"/revoke", map[string]any{}, "", "", 200)
	h.invoke("doc-A", 403)
}
