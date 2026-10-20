package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/ufaruq/toolbox/internal/domain"
	"github.com/ufaruq/toolbox/internal/identity"
)

type mcpIdentity struct{}

func (mcpIdentity) Issuer() string { return "https://okta.example/oauth2/default" }
func (mcpIdentity) Clients() map[string]string {
	return map[string]string{"web": "Claude web", "code": "Claude Code"}
}
func (mcpIdentity) VerifyAccess(_ context.Context, raw string) (identity.Claims, error) {
	if raw != "web" && raw != "code" {
		return identity.Claims{}, domain.ErrDenied
	}
	return identity.Claims{Issuer: mcpIdentity{}.Issuer(), UserID: "owner", ClientID: raw, ExpiresAt: time.Now().Add(time.Hour)}, nil
}
func (mcpIdentity) AuthorizationURL(string, string, string) (string, error) {
	return "", domain.ErrDenied
}
func (mcpIdentity) Complete(context.Context, string, string, string) (identity.Owner, error) {
	return identity.Owner{}, domain.ErrDenied
}

type mcpBearer struct {
	token string
	base  http.RoundTripper
}

func (t mcpBearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+t.token)
	return t.base.RoundTrip(r)
}

func mcpFixture(t *testing.T) (*Server, *invocationAuditRepository, *httptest.Server) {
	t.Helper()
	s, repo, _ := invocationFixture(t, domain.User{ID: "owner", Issuer: (mcpIdentity{}).Issuer(), Subject: "owner", Status: "active"})
	s.Identity = mcpIdentity{}
	if err := repo.Transact(context.Background(), func(st *domain.State) error {
		u := st.Users["owner"]
		u.Issuer = mcpIdentity{}.Issuer()
		st.Users[u.ID] = u
		st.CallerProfiles["web-profile"] = domain.CallerProfile{ID: "web-profile", OwnerID: "owner", AgentID: "agent", Issuer: u.Issuer, UserID: u.Subject, ClientID: "web", Label: "web", Status: "active", Tools: []string{domain.Tool}, ApprovedAt: st.Now, ExpiresAt: st.Now.Add(time.Hour)}
		st.Agents["code-agent"] = domain.Agent{ID: "code-agent", OwnerID: "owner", Status: "active"}
		st.CallerProfiles["code-profile"] = domain.CallerProfile{ID: "code-profile", OwnerID: "owner", AgentID: "code-agent", Issuer: u.Issuer, UserID: u.Subject, ClientID: "code", Label: "code", Status: "active", Tools: []string{}, ApprovedAt: st.Now, ExpiresAt: st.Now.Add(time.Hour)}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s)
	t.Cleanup(ts.Close)
	return s, repo, ts
}
func connectMCP(t *testing.T, ts *httptest.Server, token, version string) *mcp.ClientSession {
	t.Helper()
	c := mcp.NewClient(&mcp.Implementation{Name: "acceptance", Version: "1"}, nil)
	var opts *mcp.ClientSessionOptions
	if version != "" {
		opts = &mcp.ClientSessionOptions{ProtocolVersion: version}
	}
	sess, err := c.Connect(context.Background(), &mcp.StreamableClientTransport{Endpoint: ts.URL + "/mcp", HTTPClient: &http.Client{Transport: mcpBearer{token: token, base: http.DefaultTransport}}, MaxRetries: -1}, opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sess.Close() })
	return sess
}
func TestMCPChallengeAndMetadata(t *testing.T) {
	_, _, ts := mcpFixture(t)
	for _, token := range []string{"", "invalid"} {
		req, _ := http.NewRequest("POST", ts.URL+"/mcp", strings.NewReader(`{}`))
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 401 || !strings.Contains(resp.Header.Get("WWW-Authenticate"), `resource_metadata="http://toolbox.test/.well-known/oauth-protected-resource/mcp"`) {
			t.Fatalf("challenge %d %q", resp.StatusCode, resp.Header)
		}
	}
	resp, err := http.Get(ts.URL + "/.well-known/oauth-protected-resource/mcp")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var metadata map[string]any
	if err = json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		t.Fatal(err)
	}
	if metadata["resource"] != "http://toolbox.test/mcp" {
		t.Fatalf("metadata: %v", metadata)
	}
}
func TestMCPSDKClientIsolationAndArguments(t *testing.T) {
	for _, version := range []string{"2025-11-25", ""} {
		t.Run("protocol-"+version, func(t *testing.T) {
			_, _, ts := mcpFixture(t)
			web := connectMCP(t, ts, "web", version)
			code := connectMCP(t, ts, "code", version)
			tools, err := web.ListTools(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			if len(tools.Tools) != 3 {
				t.Fatalf("web tools: %v", tools.Tools)
			}
			empty, err := code.ListTools(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			if len(empty.Tools) != 0 {
				t.Fatalf("code catalog leaked: %v", empty.Tools)
			}
			bad, err := web.CallTool(context.Background(), &mcp.CallToolParams{Name: "toolbox_request_document_access", Arguments: map[string]any{"file_id": "doc-A", "duration_seconds": 60, "owner_id": "owner"}})
			if err == nil && !bad.IsError {
				t.Fatalf("extra identity field accepted: %+v", bad)
			}
			made, err := web.CallTool(context.Background(), &mcp.CallToolParams{Name: "toolbox_request_document_access", Arguments: map[string]any{"file_id": "doc-A", "duration_seconds": 60}})
			if err != nil || made.IsError {
				t.Fatalf("request %+v %v", made, err)
			}
			var q map[string]any
			if err = json.Unmarshal([]byte(made.Content[0].(*mcp.TextContent).Text), &q); err != nil {
				t.Fatal(err)
			}
			denied, err := code.CallTool(context.Background(), &mcp.CallToolParams{Name: "toolbox_get_access_request", Arguments: map[string]any{"request_id": q["request_id"]}})
			if err == nil && !denied.IsError {
				t.Fatalf("cross-client access accepted: %+v", denied)
			}
			again, err := web.ListTools(context.Background(), nil)
			if err != nil || len(again.Tools) != 3 {
				t.Fatalf("catalog changed: %+v %v", again, err)
			}
		})
	}
}
func TestMCPRejectsUnapprovedOrDisabledProfile(t *testing.T) {
	s, repo, _ := mcpFixture(t)
	if err := repo.Transact(context.Background(), func(st *domain.State) error {
		p := st.CallerProfiles["web-profile"]
		p.Status = "disabled"
		st.CallerProfiles[p.ID] = p
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "/mcp", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer web")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	if w.Code != 403 {
		t.Fatalf("disabled: %d %s", w.Code, w.Body)
	}
}

func TestMCPLegacyCancellationReachesProvider(t *testing.T) {
	s, repo, ts := mcpFixture(t)
	started, stopped := make(chan struct{}), make(chan struct{})
	s.integration = invocationIntegration{read: func(ctx context.Context, _ func(context.Context) error) (Document, error) {
		close(started)
		<-ctx.Done()
		close(stopped)
		return Document{}, ctx.Err()
	}}
	client := connectMCP(t, ts, "web", "2025-11-25")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := client.CallTool(ctx, &mcp.CallToolParams{Name: "google_drive_read_document_v1", Arguments: map[string]any{"grant_id": "grant", "file_id": "doc-A"}})
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("provider did not start")
	}
	cancel()
	select {
	case <-stopped:
	case <-time.After(3 * time.Second):
		t.Fatal("legacy HTTP cancellation did not reach provider")
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled call succeeded")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("client call stuck")
	}
	// Detached terminal audit persistence may finish after the provider returns.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		events := invocationEvents(t, repo)
		for _, e := range events {
			if e.Action == "tool.invocation" && e.Outcome == "failed" {
				return
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("cancelled MCP invocation has no terminal failure audit")
}
func TestMCPRejectsBrowserOriginAndOversizeBody(t *testing.T) {
	_, _, ts := mcpFixture(t)
	for _, test := range []struct {
		origin, body string
		want         int
	}{{"https://attacker.example", `{}`, 403}, {"", strings.Repeat(" ", 17<<10), 413}} {
		req, _ := http.NewRequest("POST", ts.URL+"/mcp", strings.NewReader(test.body))
		req.Header.Set("Authorization", "Bearer web")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		if test.origin != "" {
			req.Header.Set("Origin", test.origin)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != test.want {
			t.Fatalf("request status %d want %d", resp.StatusCode, test.want)
		}
	}
}
