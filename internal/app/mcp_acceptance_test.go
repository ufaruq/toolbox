package app_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/ufaruq/toolbox/internal/domain"
	"github.com/ufaruq/toolbox/internal/identity"
)

// Cryptographic OIDC verification is covered by identity's signed-issuer suite.
// This fixture models its verified result while exercising the real owner HTTP,
// SDK transport, caller policy, Google credential boundary and document export.
type acceptanceIdentity struct{}

func (acceptanceIdentity) Issuer() string { return "fixture://local" }
func (acceptanceIdentity) Clients() map[string]string {
	return map[string]string{"web": "Claude web", "code": "Claude Code"}
}
func (acceptanceIdentity) VerifyAccess(_ context.Context, raw string) (identity.Claims, error) {
	if raw != "web-access" && raw != "code-access" {
		return identity.Claims{}, domain.ErrDenied
	}
	return identity.Claims{Issuer: "fixture://local", UserID: "local-owner", ClientID: strings.TrimSuffix(raw, "-access"), ExpiresAt: time.Now().Add(time.Hour)}, nil
}
func (acceptanceIdentity) AuthorizationURL(string, string, string) (string, error) {
	return "", domain.ErrDenied
}
func (acceptanceIdentity) Complete(context.Context, string, string, string) (identity.Owner, error) {
	return identity.Owner{}, domain.ErrDenied
}

type acceptanceBearer struct{ token string }

func (b acceptanceBearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return http.DefaultTransport.RoundTrip(r)
}
func connectAcceptanceMCP(t *testing.T, ctx context.Context, h *harness, client, version string) *mcp.ClientSession {
	t.Helper()
	c := mcp.NewClient(&mcp.Implementation{Name: "toolbox-acceptance", Version: "1"}, nil)
	var opts *mcp.ClientSessionOptions
	if version != "" {
		opts = &mcp.ClientSessionOptions{ProtocolVersion: version}
	}
	session, err := c.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: h.ts.URL + "/mcp", HTTPClient: &http.Client{Transport: acceptanceBearer{token: client + "-access"}, Timeout: 15 * time.Second}, MaxRetries: -1}, opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session
}
func acceptanceTool(t *testing.T, ctx context.Context, s *mcp.ClientSession, name string, args map[string]any) map[string]any {
	t.Helper()
	result, err := s.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil || result == nil || result.IsError {
		t.Fatalf("%s failed: %+v %v", name, result, err)
	}
	if len(result.Content) != 1 {
		t.Fatalf("%s returned unexpected content: %+v", name, result)
	}
	text, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("%s returned non-text result", name)
	}
	for _, secret := range []string{"fixture-access-", "fixture-refresh-", "delegation_token"} {
		if strings.Contains(text.Text, secret) {
			t.Fatalf("%s leaked credential material", name)
		}
	}
	var out map[string]any
	if err = json.Unmarshal([]byte(text.Text), &out); err != nil {
		t.Fatalf("%s did not return JSON: %v", name, err)
	}
	return out
}
func acceptanceDenied(t *testing.T, ctx context.Context, h *harness, s *mcp.ClientSession, name string, args map[string]any) {
	t.Helper()
	calls, reads := h.drive.Calls.Load(), h.secrets.Reads.Load()
	result, err := s.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil || result == nil || !result.IsError {
		t.Fatalf("%s did not return an authorization tool error: %+v %v", name, result, err)
	}
	if len(result.Content) != 1 {
		t.Fatalf("%s returned malformed denial: %+v", name, result)
	}
	text, ok := result.Content[0].(*mcp.TextContent)
	if !ok || (text.Text != "NOT_AUTHORIZED" && text.Text != "RESOURCE_NOT_ALLOWED" && text.Text != "GRANT_REVOKED") {
		t.Fatalf("%s returned unexpected denial: %+v", name, result)
	}
	raw, _ := json.Marshal(result)
	if strings.Contains(string(raw), "Synthetic document") {
		t.Fatal("denied call returned document content")
	}
	if h.drive.Calls.Load() != calls || h.secrets.Reads.Load() != reads {
		t.Fatal("denied SDK call reached provider or secrets")
	}
}
func acceptanceRequest(t *testing.T, ctx context.Context, h *harness, s *mcp.ClientSession, file string) string {
	t.Helper()
	q := acceptanceTool(t, ctx, s, "toolbox_request_document_access", map[string]any{"file_id": file, "duration_seconds": 3600})
	request, ok := q["request_id"].(string)
	if !ok || request == "" || q["status"] != "pending" {
		t.Fatalf("invalid pending request: %v", q)
	}
	if q["approval_url"] != h.ts.URL+"/approve/"+request {
		t.Fatalf("wrong owner approval URL: %v", q)
	}
	poll := acceptanceTool(t, ctx, s, "toolbox_get_access_request", map[string]any{"request_id": request})
	if poll["status"] != "pending" || poll["grant_id"] != "" {
		t.Fatalf("unapproved request already has grant: %v", poll)
	}
	return request
}
func acceptanceApprove(t *testing.T, ctx context.Context, h *harness, s *mcp.ClientSession, request, client, file string) string {
	t.Helper()
	// Visit the link as the cookie-authenticated owner, then perform the explicit
	// review and approval used by that browser. MCP cannot perform either step.
	resp, err := h.client.Get(h.ts.URL + "/approve/" + request)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("approval page status %d", resp.StatusCode)
	}
	review := h.call("POST", "/v1/delegation-requests/"+request+"/review", map[string]any{"connection_id": h.connection}, "", "", 200)
	if review["verified_client"] != client || review["file_id"] != file || review["connection_id"] != h.connection {
		t.Fatalf("owner was shown wrong request identity/resource: %v", review)
	}
	approved := h.call("POST", "/v1/delegation-requests/"+request+"/approve", map[string]any{"connection_id": h.connection, "version": review["version"], "digest": review["digest"]}, "", "", 201)
	grant, ok := approved["grant_id"].(string)
	if !ok || grant == "" {
		t.Fatalf("missing approved grant: %v", approved)
	}
	poll := acceptanceTool(t, ctx, s, "toolbox_get_access_request", map[string]any{"request_id": request})
	if poll["status"] != "approved" || poll["grant_id"] != grant {
		t.Fatalf("caller did not observe approval: %v", poll)
	}
	return grant
}
func acceptanceRead(t *testing.T, ctx context.Context, h *harness, s *mcp.ClientSession, grant, file string) {
	t.Helper()
	before := h.drive.Calls.Load()
	out := acceptanceTool(t, ctx, s, "google_drive_read_document_v1", map[string]any{"grant_id": grant, "file_id": file})
	content, ok := out["content"].(string)
	resource, resourceOK := out["resource"].(map[string]any)
	if !ok || !strings.Contains(content, "Synthetic document "+file) || !resourceOK || resource["file_id"] != file || out["untrusted_content"] != true {
		t.Fatalf("wrong document result: %v", out)
	}
	if h.drive.Calls.Load() <= before {
		t.Fatal("successful read never reached fixture Drive")
	}
}

func TestMCPFullOwnerApprovalAndCallerIsolation(t *testing.T) {
	for _, version := range []string{"2025-11-25", ""} {
		name := version
		if name == "" {
			name = "default"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			h := newHarness(t, nil)
			h.api.Identity = acceptanceIdentity{}
			profiles := map[string]string{}
			for _, client := range []string{"web", "code"} {
				profile := h.call("POST", "/v1/callers", map[string]any{"client_id": client, "label": "Approved " + client, "tools": []string{domain.Tool}, "duration_seconds": 7200}, "", "", 201)
				profiles[client] = profile["id"].(string)
			}
			web := connectAcceptanceMCP(t, ctx, h, "web", version)
			code := connectAcceptanceMCP(t, ctx, h, "code", version)
			for _, session := range []*mcp.ClientSession{web, code} {
				tools, err := session.ListTools(ctx, nil)
				if err != nil || len(tools.Tools) != 3 {
					t.Fatalf("approved read catalog: %+v %v", tools, err)
				}
			}

			requestA := acceptanceRequest(t, ctx, h, web, "doc-A")
			acceptanceDenied(t, ctx, h, code, "toolbox_get_access_request", map[string]any{"request_id": requestA})
			acceptanceDenied(t, ctx, h, web, "google_drive_read_document_v1", map[string]any{"grant_id": requestA, "file_id": "doc-A"})
			grantA := acceptanceApprove(t, ctx, h, web, requestA, "web", "doc-A")
			acceptanceRead(t, ctx, h, web, grantA, "doc-A")

			requestB := acceptanceRequest(t, ctx, h, code, "doc-B")
			acceptanceDenied(t, ctx, h, web, "toolbox_get_access_request", map[string]any{"request_id": requestB})
			grantB := acceptanceApprove(t, ctx, h, code, requestB, "code", "doc-B")
			acceptanceRead(t, ctx, h, code, grantB, "doc-B")
			for _, denial := range []struct {
				s           *mcp.ClientSession
				grant, file string
			}{{code, grantA, "doc-A"}, {web, grantB, "doc-B"}, {web, grantA, "doc-B"}, {code, grantB, "doc-A"}} {
				acceptanceDenied(t, ctx, h, denial.s, "google_drive_read_document_v1", map[string]any{"grant_id": denial.grant, "file_id": denial.file})
			}

			// The owner disables web after its export has been buffered. The final
			// authorization check must discard that content before the SDK receives it.
			exported, release := make(chan struct{}), make(chan struct{})
			releaseExport := sync.OnceFunc(func() { close(release) })
			defer releaseExport()
			h.drive.After = func(r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/export") {
					close(exported)
					<-release
				}
			}
			type outcome struct {
				result *mcp.CallToolResult
				err    error
			}
			finished := make(chan outcome, 1)
			go func() {
				result, err := web.CallTool(ctx, &mcp.CallToolParams{Name: "google_drive_read_document_v1", Arguments: map[string]any{"grant_id": grantA, "file_id": "doc-A"}})
				finished <- outcome{result, err}
			}()
			select {
			case <-exported:
			case <-ctx.Done():
				releaseExport()
				t.Fatal("web export did not reach revocation barrier")
			}
			h.call("POST", "/v1/callers/"+profiles["web"]+"/disable", map[string]any{}, "", "", 200)
			releaseExport()
			var stopped outcome
			select {
			case stopped = <-finished:
			case <-ctx.Done():
				t.Fatal("disabled buffered export did not finish")
			}
			h.drive.After = nil
			if stopped.err != nil || stopped.result == nil || !stopped.result.IsError {
				t.Fatalf("revoked in-flight read did not return a tool error: %+v %v", stopped.result, stopped.err)
			}
			if len(stopped.result.Content) != 1 {
				t.Fatalf("malformed stopped export: %+v", stopped.result)
			}
			denial, ok := stopped.result.Content[0].(*mcp.TextContent)
			if !ok || (denial.Text != "NOT_AUTHORIZED" && denial.Text != "GRANT_REVOKED") {
				t.Fatalf("wrong stopped-export error: %+v", stopped.result)
			}
			raw, _ := json.Marshal(stopped.result)
			if strings.Contains(string(raw), "Synthetic document") {
				t.Fatal("disabled export released buffered content")
			}

			calls, reads := h.drive.Calls.Load(), h.secrets.Reads.Load()
			denied, err := web.CallTool(ctx, &mcp.CallToolParams{Name: "google_drive_read_document_v1", Arguments: map[string]any{"grant_id": grantA, "file_id": "doc-A"}})
			if err == nil || !strings.Contains(err.Error(), "Forbidden") {
				t.Fatalf("disabled caller did not receive HTTP403: %+v %v", denied, err)
			}
			if h.drive.Calls.Load() != calls || h.secrets.Reads.Load() != reads {
				t.Fatal("disabled caller reached provider or secrets")
			}
			acceptanceRead(t, ctx, h, code, grantB, "doc-B")

			// Re-enabling the caller authorizes its tools, but previous grants stay
			// revoked. An entirely new owner review is necessary to read again.
			h.call("POST", "/v1/callers/"+profiles["web"]+"/enable", map[string]any{"tools": []string{domain.Tool}, "duration_seconds": 7200}, "", "", 200)
			// An HTTP 403 terminates the SDK connection; a newly enabled client reconnects.
			web = connectAcceptanceMCP(t, ctx, h, "web", version)
			acceptanceDenied(t, ctx, h, web, "google_drive_read_document_v1", map[string]any{"grant_id": grantA, "file_id": "doc-A"})
			freshRequest := acceptanceRequest(t, ctx, h, web, "doc-A")
			freshGrant := acceptanceApprove(t, ctx, h, web, freshRequest, "web", "doc-A")
			if freshGrant == grantA {
				t.Fatal("new owner approval reused revoked grant")
			}
			acceptanceRead(t, ctx, h, web, freshGrant, "doc-A")
			acceptanceDenied(t, ctx, h, code, "google_drive_read_document_v1", map[string]any{"grant_id": freshGrant, "file_id": "doc-A"})
			acceptanceRead(t, ctx, h, code, grantB, "doc-B")
		})
	}
}
