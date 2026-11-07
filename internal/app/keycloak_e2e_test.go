package app_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/ufaruq/toolbox/internal/app"
	"github.com/ufaruq/toolbox/internal/connectors/gdrive"
	"github.com/ufaruq/toolbox/internal/domain"
	"github.com/ufaruq/toolbox/internal/identity"
	"github.com/ufaruq/toolbox/internal/identitylink"
	"github.com/ufaruq/toolbox/internal/keycloakrealm"
	"github.com/ufaruq/toolbox/internal/oauth"
	"github.com/ufaruq/toolbox/internal/ownerlogin"
	"github.com/ufaruq/toolbox/internal/security"
	"github.com/ufaruq/toolbox/internal/server"
	"github.com/ufaruq/toolbox/internal/store"
	"github.com/ufaruq/toolbox/internal/testutil/keycloaktest"
	"github.com/ufaruq/toolbox/internal/tokens"
)

// TestKeycloakBrokerFlow uses the real digest-pinned Keycloak server, two
// controlled HTTPS upstreams, verified TLS, the actual owner OIDC provider,
// migration linker, access verifier, owner approval handlers and MCP SDK.
// The Google-shaped upstream replaces the built-in Google provider only in
// this private test import. It does not establish live Google/Okta acceptance
// or test Google's hosted-domain policy; those require external tenants.
func TestKeycloakBrokerFlow(t *testing.T) {
	if os.Getenv("TOOLBOX_TEST_KEYCLOAK") != "1" {
		t.Skip("set TOOLBOX_TEST_KEYCLOAK=1 with local Docker access for real pinned Keycloak acceptance")
	}
	started := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	// Build a synthetic legacy data snapshot with a connected provider and grant.
	// Its primary identity is set before first persistence into the acceptance
	// repository below; persisted primary identities are never mutated.
	h := newHarness(t, nil)
	h.approve()
	legacyGrant, legacyAgent, legacyConnection := h.grant, h.agentID, h.connection
	h.ts.Close()
	h.ts = httptest.NewUnstartedServer(nil)
	t.Cleanup(h.ts.Close)
	origin := "http://" + h.ts.Listener.Addr().String()
	const realm, ownerClient, callerClient = "toolbox-e2e", "toolbox-owner", "toolbox-mcp"
	infra := keycloaktest.Start(t, realm, func(e keycloaktest.Endpoints, secrets keycloaktest.Credentials) ([]byte, error) {
		raw, err := keycloakrealm.Render(keycloakrealm.Config{Realm: realm, OwnerClientID: ownerClient, OwnerClientSecret: secrets.Owner, Origin: origin, OktaIssuer: e.OktaIssuer, OktaClientID: "upstream-okta", OktaClientSecret: secrets.Okta, GoogleClientID: "upstream-google", GoogleClientSecret: secrets.Google, GoogleHostedDomain: "example.test", MCPClients: map[string]string{callerClient: "Controlled MCP"}, MCPRedirectURIs: map[string][]string{callerClient: {origin + "/keycloak-test/callback"}}})
		if err != nil {
			return nil, err
		}
		return keycloakTestRealm(raw, e, secrets)
	})
	var oldUser domain.User
	var oldGrant domain.Grant
	const oldProfile = "legacy-caller-profile"
	var legacyJSON []byte
	if err := h.repo.Transact(ctx, func(st *domain.State) error {
		var err error
		legacyJSON, err = json.Marshal(st)
		return err
	}); err != nil {
		t.Fatal("construct synthetic legacy snapshot")
	}
	var legacy domain.State
	if err := json.Unmarshal(legacyJSON, &legacy); err != nil {
		t.Fatal("decode synthetic legacy snapshot")
	}
	oldUser = legacy.Users["11111111-1111-4111-8111-111111111111"]
	oldUser.Issuer, oldUser.Subject = infra.OktaIssuer, "okta-subject"
	legacy.Users[oldUser.ID] = oldUser
	h.repo = store.NewMemory()
	if err := h.repo.Transact(ctx, func(st *domain.State) error {
		now := st.Now
		*st = legacy
		st.Now = now
		oldGrant = st.Grants[legacyGrant]
		st.CallerProfiles[oldProfile] = domain.CallerProfile{ID: oldProfile, OwnerID: oldUser.ID, AgentID: legacyAgent, Issuer: infra.OktaIssuer, UserID: oldUser.Subject, ClientID: callerClient, Label: "Legacy approval", Status: "active", Tools: []string{domain.Tool}, ApprovedAt: st.Now, ExpiresAt: st.Now.Add(time.Hour)}
		return nil
	}); err != nil {
		t.Fatal("seed legacy owner identity")
	}
	// A real first broker login creates Keycloak's immutable Okta federation.
	// It deliberately does not visit Toolbox before the verified migration.
	accessToken, idToken := keycloakTokens(t, infra, origin, callerClient, "okta", "openid mcp")
	operatorToken := keycloakOperator(t, infra)
	linker, err := identitylink.New(ctx, identitylink.Config{RealmIssuer: infra.RealmIssuer, ClientID: "toolbox-linker", ClientSecret: infra.Credentials.Operator, SourceIssuer: infra.OktaIssuer, SourceProviderAlias: "okta", HTTPClient: infra.Client})
	if err != nil {
		t.Fatalf("construct trusted real Keycloak migration linker: %v", err)
	}
	report, err := linker.Link(ctx, h.repo, false)
	if err != nil || report.Scanned != 1 || report.Linked != 1 {
		t.Fatalf("verified real Keycloak migration dry-run failed (scanned=%d linked=%d)", report.Scanned, report.Linked)
	}
	if err := h.repo.Transact(ctx, func(st *domain.State) error {
		if len(st.IdentityAliases) != 0 {
			t.Error("migration dry-run wrote identity aliases")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	report, err = linker.Link(ctx, h.repo, true)
	if err != nil || report.Linked != 1 {
		t.Fatal("verified real Keycloak migration apply failed")
	}
	report, err = linker.Link(ctx, h.repo, true)
	if err != nil || report.Linked != 0 || report.AlreadyLinked != 1 {
		t.Fatal("verified migration was not idempotent")
	}
	t.Log("real Admin API proof: dry-run, atomic apply and idempotence passed")
	access, err := identity.NewAccess(ctx, identity.AccessConfig{Provider: "keycloak", Issuer: infra.RealmIssuer, OwnerIssuer: infra.RealmIssuer, Audience: origin + "/mcp", OwnerClientID: ownerClient, Clients: map[string]string{callerClient: "Controlled MCP"}, HTTPClient: infra.Client})
	if err != nil {
		t.Fatal("construct real Keycloak MCP verifier")
	}
	claims, err := access.VerifyAccess(ctx, accessToken)
	if err != nil || claims.Issuer != infra.RealmIssuer || claims.ClientID != callerClient || claims.UserID == "" || claims.UserID == "okta-subject" {
		t.Fatal("real broker access token did not verify as the Keycloak realm user")
	}
	if _, err := access.VerifyAccess(ctx, idToken); err == nil {
		t.Fatal("real Keycloak ID token authenticated MCP")
	}
	if _, err := access.VerifyAccess(ctx, operatorToken); err == nil {
		t.Fatal("real Keycloak operator service-account token authenticated MCP")
	}
	withoutScope, _ := keycloakTokens(t, infra, origin, callerClient, "okta", "openid")
	if _, err := access.VerifyAccess(ctx, withoutScope); err == nil {
		t.Fatal("real access token without mcp scope authenticated MCP")
	}
	t.Log("real Keycloak access verifier: user token accepted; ID token, operator token and token requested without mcp scope rejected")
	provider, err := ownerlogin.NewProvider(ctx, ownerlogin.ProviderConfig{Issuer: infra.RealmIssuer, ClientID: ownerClient, ClientSecret: infra.Credentials.Owner, RedirectURI: origin + "/auth/oidc/callback"}, infra.Client)
	if err != nil {
		t.Fatal("discover real Keycloak owner provider over verified TLS")
	}
	sessionPepper := bytes.Repeat([]byte("s"), 32)
	login, err := ownerlogin.NewService(h.repo, h.secrets, provider, ownerlogin.ServiceConfig{Issuer: infra.RealmIssuer, ClientID: ownerClient, RedirectURI: origin + "/auth/oidc/callback", Pepper: sessionPepper})
	if err != nil {
		t.Fatal(err)
	}
	google, err := oauth.NewFixtureProvider("fixture-client", origin+"/oauth/callback")
	if err != nil {
		t.Fatal(err)
	}
	flow, err := oauth.NewService(h.repo, h.secrets, google)
	if err != nil {
		t.Fatal(err)
	}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := security.NewSigner(origin, "keycloak-test", key)
	integration := &app.Integration{OAuth: flow, TokenManager: &tokens.Manager{Repository: h.repo, Secrets: h.secrets, Provider: google}, Drive: gdrive.NewFixture(h.drive)}
	h.api, err = server.New(server.Config{Repository: h.repo, Origin: origin, Signer: signer, Pepper: bytes.Repeat([]byte("c"), 32), SessionPepper: sessionPepper, WorkspaceLocal: true, OwnerLogin: login, Identity: access}, integration)
	if err != nil {
		t.Fatal(err)
	}
	h.ts.Config.Handler = h.api
	h.ts.Start()
	h.client = keycloakBrowser(t, infra)
	keycloakOwnerLogin(t, h, "okta", true)
	session := h.call("GET", "/v1/session", nil, "", "", 200)
	if session["user_id"] != oldUser.ID || session["fixture"] != false {
		t.Fatal("broker login did not preserve the legacy internal owner")
	}
	h.csrf = session["csrf_token"].(string)
	if err := h.repo.Transact(ctx, func(st *domain.State) error {
		resolved, ok := domain.ResolveIdentity(st, infra.RealmIssuer, claims.UserID)
		if !ok || resolved != oldUser || st.Users[oldUser.ID] != oldUser || !reflect.DeepEqual(st.Grants[legacyGrant], oldGrant) || st.Connections[legacyConnection].OwnerID != oldUser.ID || st.Agents[legacyAgent].OwnerID != oldUser.ID || st.CallerProfiles[oldProfile].Issuer != infra.OktaIssuer {
			t.Error("migration changed legacy identity, connection, agent, grant or approval")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// Old issuer approval must not authorize the new issuer's access token.
	keycloakMCPDenied(t, ctx, h, infra, accessToken)
	profile := h.call("POST", "/v1/callers", map[string]any{"client_id": callerClient, "label": "New Keycloak approval", "tools": []string{domain.Tool}, "duration_seconds": 3600}, "", "", 201)
	mcpSession := keycloakMCP(t, ctx, h, infra, accessToken)
	request := acceptanceRequest(t, ctx, h, mcpSession, "doc-A")
	grant := acceptanceApprove(t, ctx, h, mcpSession, request, callerClient, "doc-A")
	acceptanceRead(t, ctx, h, mcpSession, grant, "doc-A")
	acceptanceDenied(t, ctx, h, mcpSession, "google_drive_read_document_v1", map[string]any{"grant_id": grant, "file_id": "doc-B"})
	h.call("POST", "/v1/grants/"+grant+"/revoke", map[string]any{}, "", "", 200)
	acceptanceDenied(t, ctx, h, mcpSession, "google_drive_read_document_v1", map[string]any{"grant_id": grant, "file_id": "doc-A"})
	h.call("POST", "/v1/callers/"+profile["id"].(string)+"/disable", map[string]any{}, "", "", 200)
	keycloakMCPDenied(t, ctx, h, infra, accessToken)
	t.Log("real Keycloak tokens: fresh caller approval, SDK request/read, wrong-resource denial, grant revocation and caller disable passed")
	// Repeat owner login resolves the same alias. A new browser authenticating
	// the Google-shaped upstream has the same email but a separate realm sub.
	keycloakOwnerLogin(t, h, "okta", false)
	if h.call("GET", "/v1/session", nil, "", "", 200)["user_id"] != oldUser.ID {
		t.Fatal("repeat broker owner login was unstable")
	}
	googleBrowser := keycloakBrowser(t, infra)
	oldBrowser := h.client
	h.client = googleBrowser
	keycloakOwnerLogin(t, h, "google", false)
	googleSession := h.call("GET", "/v1/session", nil, "", "", 200)
	googleOwner, ok := googleSession["user_id"].(string)
	if !ok || googleOwner == "" || googleOwner == oldUser.ID {
		t.Fatal("same-email upstream identities merged")
	}
	h.csrf = googleSession["csrf_token"].(string)
	h.call("POST", "/v1/grants/"+legacyGrant+"/revoke", map[string]any{}, "", "", 403)
	if err := h.repo.Transact(ctx, func(st *domain.State) error {
		if len(st.Users) != 2 || !reflect.DeepEqual(st.Grants[legacyGrant], oldGrant) || st.Users[googleOwner].Issuer != infra.RealmIssuer || st.Users[googleOwner].Subject == claims.UserID {
			t.Error("same-email Google-shaped login inherited legacy owner state")
		}
		for _, connection := range st.Connections {
			if connection.OwnerID == googleOwner {
				t.Error("Google-shaped login inherited a Drive connection")
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	h.client = oldBrowser
	t.Logf("controlled HTTPS Okta/Google-shaped brokering and same-email separation passed in %s; live tenant and built-in Google hosted-domain acceptance remain external", time.Since(started).Round(time.Second))
}

func keycloakTestRealm(raw []byte, e keycloaktest.Endpoints, secrets keycloaktest.Credentials) ([]byte, error) {
	var realm map[string]any
	if err := json.Unmarshal(raw, &realm); err != nil {
		return nil, err
	}
	var okta map[string]any
	providers := realm["identityProviders"].([]any)
	for _, value := range providers {
		p := value.(map[string]any)
		if p["alias"] == "okta" {
			okta = p
		}
	}
	for _, value := range providers {
		p := value.(map[string]any)
		if p["alias"] == "google" {
			// Explicit test-only substitution: no request reaches real Google.
			config := map[string]any{}
			for key, value := range okta["config"].(map[string]any) {
				config[key] = value
			}
			config["issuer"], config["authorizationUrl"], config["tokenUrl"], config["jwksUrl"], config["userInfoUrl"] = e.GoogleIssuer, e.GoogleIssuer+"/v1/authorize", e.GoogleIssuer+"/v1/token", e.GoogleIssuer+"/v1/keys", e.GoogleIssuer+"/v1/userinfo"
			config["clientId"], config["clientSecret"] = "upstream-google", secrets.Google
			p["providerId"], p["config"] = "oidc", config
		}
	}
	clients := realm["clients"].([]any)
	// Keycloak 26.8.2's built-in kc-admin-api scope supplies its dedicated API
	// URL audience. Assign it only to the temporary read-only operator.
	clients = append(clients, map[string]any{
		"clientId": "toolbox-linker", "enabled": true, "protocol": "openid-connect", "publicClient": false, "secret": secrets.Operator,
		"standardFlowEnabled": false, "directAccessGrantsEnabled": false, "serviceAccountsEnabled": true, "fullScopeAllowed": true,
		"defaultClientScopes": []string{"basic", "kc-admin-api"}, "optionalClientScopes": []string{},
		// Toolbox app clients do not receive the roles scope. Only the temporary
		// read-only operator token gets these assigned admin client roles.
		"protocolMappers": []any{map[string]any{
			"name": "Read-only realm management roles", "protocol": "openid-connect", "protocolMapper": "oidc-usermodel-client-role-mapper",
			"config": map[string]string{"usermodel.clientRoleMapping.clientId": "realm-management", "claim.name": "resource_access.realm-management.roles", "jsonType.label": "String", "multivalued": "true", "access.token.claim": "true", "id.token.claim": "false", "userinfo.token.claim": "false"},
		}},
	})
	realm["clients"] = clients
	realm["users"] = []any{map[string]any{"username": "service-account-toolbox-linker", "enabled": true, "serviceAccountClientId": "toolbox-linker", "clientRoles": map[string]any{"realm-management": []string{"view-users", "query-users", "view-identity-providers"}}}}
	return json.Marshal(realm)
}

func keycloakBrowser(t *testing.T, infra *keycloaktest.Harness) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal("create isolated broker browser")
	}
	return &http.Client{Transport: infra.Client.Transport, Jar: jar, Timeout: 20 * time.Second}
}

func keycloakOperator(t *testing.T, infra *keycloaktest.Harness) string {
	t.Helper()
	response, err := infra.Client.PostForm(infra.RealmIssuer+"/protocol/openid-connect/token", url.Values{"client_id": {"toolbox-linker"}, "client_secret": {infra.Credentials.Operator}, "grant_type": {"client_credentials"}})
	if err != nil {
		t.Fatal("authenticate temporary Keycloak read-only operator")
	}
	var result struct {
		Token string `json:"access_token"`
	}
	err = json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&result)
	response.Body.Close()
	if response.StatusCode != 200 || err != nil || result.Token == "" {
		t.Fatalf("temporary operator token request failed (status=%d)", response.StatusCode)
	}
	// Decode only to diagnose provisioning of our own synthetic test client.
	// Admin API authentication independently verifies this token below.
	parts := strings.Split(result.Token, ".")
	if len(parts) != 3 {
		t.Fatal("invalid synthetic operator JWT shape")
	}
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var claims struct {
		Subject string `json:"sub"`
		Issuer  string `json:"iss"`
		Type    string `json:"typ"`
		Client  string `json:"azp"`
		Roles   map[string]struct {
			Roles []string `json:"roles"`
		} `json:"resource_access"`
	}
	if json.Unmarshal(payload, &claims) != nil {
		t.Fatal("invalid synthetic operator JWT role claims")
	}
	if claims.Subject == "" {
		t.Fatal("temporary operator token lacks its service-account subject")
	}
	t.Logf("temporary operator realm-management roles: %v", claims.Roles["realm-management"].Roles)
	if claims.Issuer != infra.RealmIssuer || claims.Type != "Bearer" || claims.Client != "toolbox-linker" {
		t.Fatal("temporary operator token does not belong to the configured realm/client")
	}
	admin := strings.TrimSuffix(infra.Broker, "/") + "/admin/realms/toolbox-e2e"
	for _, path := range []string{"/identity-provider/instances/okta", "/identity-provider/instances/okta/mappers", "/users?first=0&max=100"} {
		request, _ := http.NewRequest(http.MethodGet, admin+path, nil)
		request.Header.Set("Authorization", "Bearer "+result.Token)
		response, err := infra.Client.Do(request)
		if err != nil {
			t.Fatal("read real Keycloak operator proof endpoint")
		}
		response.Body.Close()
		if response.StatusCode != 200 {
			t.Fatalf("temporary operator proof endpoint %s failed (status=%d)", strings.Split(path, "?")[0], response.StatusCode)
		}
	}
	request, _ := http.NewRequest(http.MethodPut, admin, strings.NewReader(`{}`))
	request.Header.Set("Authorization", "Bearer "+result.Token)
	request.Header.Set("Content-Type", "application/json")
	response, err = infra.Client.Do(request)
	if err != nil {
		t.Fatal("check temporary operator write denial")
	}
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("temporary read-only operator was not denied realm writes (status=%d)", response.StatusCode)
	}
	return result.Token
}

func keycloakOwnerLogin(t *testing.T, h *harness, provider string, buttons bool) {
	t.Helper()
	start := h.call("POST", "/auth/oidc/start", map[string]any{}, "", "", 200)
	uri, err := url.Parse(start["authorization_url"].(string))
	if err != nil {
		t.Fatal("parse real Keycloak authorization URL")
	}
	if buttons {
		response, err := h.client.Get(uri.String())
		if err != nil {
			t.Fatal("load real broker login page")
		}
		body, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		response.Body.Close()
		if response.StatusCode != 200 || !bytes.Contains(body, []byte(`id="social-okta"`)) || !bytes.Contains(body, []byte(`id="social-google"`)) {
			t.Fatal("real Keycloak login page did not offer both configured upstream providers")
		}
	}
	query := uri.Query()
	query.Set("kc_idp_hint", provider)
	uri.RawQuery = query.Encode()
	response, err := h.client.Get(uri.String())
	if err != nil {
		t.Fatal("complete real broker owner login")
	}
	_, _ = io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.StatusCode != 200 || response.Request.URL.Host != h.ts.Listener.Addr().String() {
		var fields []string
		for field := range response.Request.URL.Query() {
			fields = append(fields, field)
		}
		sort.Strings(fields)
		t.Fatalf("real broker owner login failed (provider=%s status=%d final-path=%s query-fields=%v)", provider, response.StatusCode, response.Request.URL.Path, fields)
	}
}

func keycloakTokens(t *testing.T, infra *keycloaktest.Harness, origin, clientID, provider, scope string) (access, id string) {
	t.Helper()
	verifier := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte("v"), 32))
	digest := sha256.Sum256([]byte(verifier))
	state := "controlled-broker-state"
	redirect := origin + "/keycloak-test/callback"
	query := url.Values{"client_id": {clientID}, "redirect_uri": {redirect}, "response_type": {"code"}, "scope": {scope}, "state": {state}, "nonce": {"controlled-broker-nonce"}, "code_challenge_method": {"S256"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(digest[:])}, "kc_idp_hint": {provider}}
	browser := keycloakBrowser(t, infra)
	browser.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if request.URL.String() == redirect || strings.HasPrefix(request.URL.String(), redirect+"?") {
			return http.ErrUseLastResponse
		}
		if len(via) > 15 {
			return http.ErrUseLastResponse
		}
		return nil
	}
	response, err := browser.Get(infra.RealmIssuer + "/protocol/openid-connect/auth?" + query.Encode())
	if err != nil {
		t.Fatal("authorize MCP client through real Keycloak broker")
	}
	response.Body.Close()
	callback, err := response.Location()
	if err != nil || callback.Scheme+"://"+callback.Host+callback.Path != redirect || callback.Query().Get("state") != state || callback.Query().Get("code") == "" || callback.Query().Get("error") != "" {
		t.Fatalf("real broker MCP authorization failed (provider=%s status=%d final-host=%s final-path=%s)", provider, response.StatusCode, response.Request.URL.Host, response.Request.URL.Path)
	}
	response, err = infra.Client.PostForm(infra.RealmIssuer+"/protocol/openid-connect/token", url.Values{"client_id": {clientID}, "redirect_uri": {redirect}, "grant_type": {"authorization_code"}, "code": {callback.Query().Get("code")}, "code_verifier": {verifier}})
	if err != nil {
		t.Fatal("exchange real broker authorization code")
	}
	defer response.Body.Close()
	var result struct {
		Access string `json:"access_token"`
		ID     string `json:"id_token"`
	}
	if response.StatusCode != 200 || json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&result) != nil || result.Access == "" || result.ID == "" {
		t.Fatalf("real broker token exchange failed (status=%d)", response.StatusCode)
	}
	return result.Access, result.ID
}

func keycloakMCP(t *testing.T, ctx context.Context, h *harness, infra *keycloaktest.Harness, token string) *mcp.ClientSession {
	t.Helper()
	c := mcp.NewClient(&mcp.Implementation{Name: "toolbox-keycloak-acceptance", Version: "1"}, nil)
	session, err := c.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: h.ts.URL + "/mcp", HTTPClient: &http.Client{Transport: keycloakBearer{base: infra.Client.Transport, token: token}, Timeout: 15 * time.Second}, MaxRetries: -1}, nil)
	if err != nil {
		t.Fatal("connect MCP SDK with real Keycloak access token")
	}
	t.Cleanup(func() { _ = session.Close() })
	return session
}

func keycloakMCPDenied(t *testing.T, ctx context.Context, h *harness, infra *keycloaktest.Harness, token string) {
	t.Helper()
	calls, reads := h.drive.Calls.Load(), h.secrets.Reads.Load()
	c := mcp.NewClient(&mcp.Implementation{Name: "toolbox-keycloak-denied", Version: "1"}, nil)
	session, err := c.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: h.ts.URL + "/mcp", HTTPClient: &http.Client{Transport: keycloakBearer{base: infra.Client.Transport, token: token}, Timeout: 15 * time.Second}, MaxRetries: -1}, nil)
	if session != nil {
		session.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "Forbidden") || h.drive.Calls.Load() != calls || h.secrets.Reads.Load() != reads {
		t.Fatal("unapproved or disabled Keycloak caller was not denied before provider/secret access")
	}
}

type keycloakBearer struct {
	base  http.RoundTripper
	token string
}

func (b keycloakBearer) RoundTrip(r *http.Request) (*http.Response, error) {
	clone := r.Clone(r.Context())
	clone.Header.Set("Authorization", "Bearer "+b.token)
	return b.base.RoundTrip(clone)
}
