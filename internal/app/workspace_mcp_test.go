package app_test

import (
	"bytes"
	"context"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ufaruq/toolbox/internal/app"
	"github.com/ufaruq/toolbox/internal/connectors/gdrive"
	"github.com/ufaruq/toolbox/internal/domain"
	"github.com/ufaruq/toolbox/internal/identity"
	"github.com/ufaruq/toolbox/internal/oauth"
	"github.com/ufaruq/toolbox/internal/ownerlogin"
	"github.com/ufaruq/toolbox/internal/server"
	"github.com/ufaruq/toolbox/internal/tokens"
)

type workspaceMCPIdentity struct{ ownerIssuer, subject string }

func (i workspaceMCPIdentity) OwnerIssuer() string { return i.ownerIssuer }
func (i workspaceMCPIdentity) Issuer() string      { return i.ownerIssuer + "/oauth2/default" }
func (i workspaceMCPIdentity) Clients() map[string]string {
	return map[string]string{"code": "Local agent"}
}
func (i workspaceMCPIdentity) VerifyAccess(_ context.Context, raw string) (identity.Claims, error) {
	if raw != "code-access" {
		return identity.Claims{}, domain.ErrDenied
	}
	return identity.Claims{Issuer: i.Issuer(), UserID: i.subject, ClientID: "code", ExpiresAt: time.Now().Add(time.Hour)}, nil
}

func TestWorkspaceOwnerUsesSameGoogleConnectionThroughMCP(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, nil)
	h.ts = httptest.NewUnstartedServer(nil)
	t.Cleanup(h.ts.Close)
	origin := "http://" + h.ts.Listener.Addr().String()
	sessionPepper := bytes.Repeat([]byte("s"), 32)
	login, err := ownerlogin.NewService(h.repo, h.secrets, workspaceOwnerProvider{}, ownerlogin.ServiceConfig{Issuer: "https://owner.example.test", ClientID: "owner-client", RedirectURI: origin + "/auth/oidc/callback", Pepper: sessionPepper})
	if err != nil {
		t.Fatal(err)
	}
	google, err := oauth.NewFixtureProvider("workspace-google", origin+"/oauth/callback")
	if err != nil {
		t.Fatal(err)
	}
	flow, err := oauth.NewService(h.repo, h.secrets, google)
	if err != nil {
		t.Fatal(err)
	}
	integration := &app.Integration{OAuth: flow, TokenManager: &tokens.Manager{Repository: h.repo, Secrets: h.secrets, Provider: google}, Drive: gdrive.NewFixture(h.drive)}
	h.api, err = server.New(server.Config{Repository: h.repo, Origin: origin, Signer: h.api.Signer, Pepper: bytes.Repeat([]byte("c"), 32), SessionPepper: sessionPepper, WorkspaceLocal: true, OwnerLogin: login, Identity: workspaceMCPIdentity{ownerIssuer: "https://owner.example.test", subject: "real-owner"}}, integration)
	if err != nil {
		t.Fatal(err)
	}
	h.ts.Config.Handler = h.api
	h.ts.Start()
	start := h.call("POST", "/auth/oidc/start", map[string]any{}, "", "", 200)
	auth, _ := url.Parse(start["authorization_url"].(string))
	response, err := h.client.Get(origin + "/auth/oidc/callback?state=" + url.QueryEscape(auth.Query().Get("state")) + "&code=test")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	session := h.call("GET", "/v1/session", nil, "", "", 200)
	ownerID := session["user_id"].(string)
	h.csrf = session["csrf_token"].(string)
	start = h.call("POST", "/v1/connections/google/start", map[string]any{}, "", "", 200)
	callback, err := google.Authorize(ctx, start["authorization_url"].(string), "workspace-google-account")
	if err != nil {
		t.Fatal(err)
	}
	response, err = h.client.Get(callback)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if err := h.repo.Transact(ctx, func(st *domain.State) error {
		for _, c := range st.Connections {
			if c.OwnerID == ownerID && c.Subject == "workspace-google-account" && c.Status == "active" {
				h.connection = c.ID
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	h.call("POST", "/v1/callers", map[string]any{"client_id": "code", "label": "Local client", "tools": []string{domain.Tool}, "duration_seconds": 7200}, "", "", 201)
	client := connectAcceptanceMCP(t, ctx, h, "code", "")
	requestID := acceptanceRequest(t, ctx, h, client, "doc-A")
	grant := acceptanceApprove(t, ctx, h, client, requestID, "code", "doc-A")
	acceptanceRead(t, ctx, h, client, grant, "doc-A")
	acceptanceDenied(t, ctx, h, client, "google_drive_read_document_v1", map[string]any{"grant_id": grant, "file_id": "doc-B"})
	h.call("POST", "/v1/grants/"+grant+"/revoke", map[string]any{}, "", "", 200)
	acceptanceDenied(t, ctx, h, client, "google_drive_read_document_v1", map[string]any{"grant_id": grant, "file_id": "doc-A"})
	current := h.call("GET", "/v1/session", nil, "", "", 200)
	if current["user_id"] != ownerID || !strings.HasPrefix(h.api.Identity.Issuer(), login.Issuer()+"/oauth2/") {
		t.Fatal("MCP replaced the owner identity")
	}
}
