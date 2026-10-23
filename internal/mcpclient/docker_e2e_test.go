package mcpclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	pilotGatewayImage    = "docker/mcp-gateway@sha256:b0a3876ffbb352813d658cf25c137b8eae29bbe23db5944560a1c9059533bb16"
	pilotGitHubImage     = "ghcr.io/github/github-mcp-server@sha256:250bc6ce70788207608ef74cef4397230ff2e8481218da74d6093e4bd9101132"
	pilotGatewayName     = "Docker AI MCP Gateway"
	pilotGatewayVersion  = "2.0.1"
	pilotGetMeSchema     = "efddc7bd8bbcef73a14eb1ace1ffdaec81e518ef1e13c1e9271d0b8acb694a49"
	pilotIssueReadSchema = "4129cf817f37afefbc65885a75ba37817ae95f46ab9658b0b9de8c37d6b26c2e"
)

// TestDockerGatewayOwnerIsolation uses the real, digest-pinned Gateway and GitHub
// MCP server. Docker belongs to the test operator; the client receives only two
// private HTTP endpoints and their distinct gateway bearer credentials.
func TestDockerGatewayOwnerIsolation(t *testing.T) {
	if os.Getenv("TOOLBOX_TEST_DOCKER_MCP") != "1" {
		t.Skip("set TOOLBOX_TEST_DOCKER_MCP=1 to run the real Docker MCP Gateway pilot")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	h := newPilotHarness(t, ctx)
	a := h.startGateway("a", "github_pat_fixture_owner_a_"+h.suffix)
	b := h.startGateway("b", "github_pat_fixture_owner_b_"+h.suffix)
	ga := h.approveGateway(a, Binding{ID: "binding-a", OwnerID: "owner-a", ConnectionID: "connection-a", Epoch: 1})
	gb := h.approveGateway(b, Binding{ID: "binding-b", OwnerID: "owner-b", ConnectionID: "connection-b", Epoch: 1})
	client, err := New(Config{Gateways: []Gateway{ga, gb}, Timeout: 20 * time.Second})
	if err != nil {
		t.Fatal(h.redact(err.Error()))
	}
	t.Cleanup(func() { _ = client.Close() })

	// Simultaneous first calls exercise independent gateway initialization and
	// independent provider credentials in the shared outbound client.
	var wg sync.WaitGroup
	for _, tc := range []struct {
		binding Binding
		login   string
	}{{ga.Binding, "fixture-owner-a"}, {gb.Binding, "fixture-owner-b"}} {
		tc := tc
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := h.callTool(client, tc.binding, "get_me", json.RawMessage(`{}`))
			if err != nil {
				t.Errorf("get_me %s: %s", tc.login, h.redact(err.Error()))
				return
			}
			h.assertResult(result, tc.login)
		}()
	}
	wg.Wait()
	if t.Failed() {
		return
	}

	for _, tc := range []struct {
		gateway    Gateway
		own, other string
	}{{ga, "private-a", "private-b"}, {gb, "private-b", "private-a"}} {
		tools, err := client.ListTools(ctx, tc.gateway.Binding)
		if err != nil || len(tools) != 2 {
			t.Fatalf("approved tool inventory: count=%d error=%s", len(tools), h.errorText(err))
		}
		args := issueArgs(tc.own)
		result, err := h.callTool(client, tc.gateway.Binding, "issue_read", args)
		if err != nil {
			t.Fatal(h.redact(err.Error()))
		}
		h.assertResult(result, tc.own)
		before := len(h.audit())
		_, err = h.callTool(client, tc.gateway.Binding, "issue_read", issueArgs(tc.other))
		if err == nil {
			t.Fatal("provider accepted another owner's private repository")
		}
		h.assertNoTokens(err.Error())
		events := h.audit()
		if len(events) <= before || events[len(events)-1].Status != http.StatusNotFound || events[len(events)-1].Repository != "fixture/"+tc.other {
			t.Fatalf("cross-repository denial was not recorded by real provider fixture: %+v", events)
		}
	}

	for _, forged := range []Binding{
		{ID: ga.Binding.ID, OwnerID: gb.Binding.OwnerID, ConnectionID: ga.Binding.ConnectionID, Epoch: ga.Binding.Epoch},
		{ID: ga.Binding.ID, OwnerID: ga.Binding.OwnerID, ConnectionID: gb.Binding.ConnectionID, Epoch: ga.Binding.Epoch},
		{ID: ga.Binding.ID, OwnerID: ga.Binding.OwnerID, ConnectionID: ga.Binding.ConnectionID, Epoch: ga.Binding.Epoch + 1},
	} {
		before := a.requests.Load() + b.requests.Load()
		if _, err := h.callTool(client, forged, "get_me", json.RawMessage(`{}`)); err == nil {
			t.Fatal("forged binding accepted")
		}
		if after := a.requests.Load() + b.requests.Load(); after != before {
			t.Fatal("forged binding reached a gateway")
		}
	}

	// Knowing A's gateway bearer does not authorize B's independent endpoint.
	before := len(h.audit())
	h.assertWrongBearer(b.endpoint, a.bearer)
	if len(h.audit()) != before {
		t.Fatal("wrong gateway bearer reached the GitHub provider")
	}

	h.docker("stop", "--time=3", a.name)
	if _, err := h.callTool(client, ga.Binding, "get_me", json.RawMessage(`{}`)); err == nil {
		t.Fatal("stopped owner A gateway remained callable")
	}
	result, err := h.callTool(client, gb.Binding, "get_me", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(h.redact(err.Error()))
	}
	h.assertResult(result, "fixture-owner-b")
	// A new client after restart must use the same explicit owner A secret file.
	h.docker("start", a.name)
	h.refreshGateway(a)
	h.waitGateway(a)
	restarted, err := New(Config{Gateways: []Gateway{ga}, Timeout: 20 * time.Second})
	if err != nil {
		t.Fatal(h.redact(err.Error()))
	}
	defer restarted.Close()
	result, err = h.callTool(restarted, ga.Binding, "get_me", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(h.redact(err.Error()))
	}
	h.assertResult(result, "fixture-owner-a")
	if err := restarted.Close(); err != nil {
		t.Fatal(h.redact(err.Error()))
	}
	before = len(h.audit())
	beforeClosedRequests := a.requests.Load()
	if _, err := h.callTool(restarted, ga.Binding, "get_me", json.RawMessage(`{}`)); err == nil {
		t.Fatal("closed owner A client remained callable")
	}
	if len(h.audit()) != before {
		t.Fatal("closed binding reached provider")
	}
	if a.requests.Load() != beforeClosedRequests {
		t.Fatal("closed binding reached a gateway")
	}
	result, err = h.callTool(client, gb.Binding, "get_me", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(h.redact(err.Error()))
	}
	h.assertResult(result, "fixture-owner-b")
	events := h.audit()
	counts := map[string]int{}
	statusCounts := map[string]int{}
	for _, event := range events {
		if event.Principal != "fixture-owner-a" && event.Principal != "fixture-owner-b" {
			t.Fatalf("unexpected provider principal: %+v", event)
		}
		counts[event.Principal]++
		statusCounts[fmt.Sprintf("%s/status-%d", event.Principal, event.Status)]++
		if event.Status == http.StatusOK && event.Repository != "" {
			want := map[string]string{"fixture-owner-a": "fixture/private-a", "fixture-owner-b": "fixture/private-b"}[event.Principal]
			if event.Repository != want {
				t.Fatalf("provider audit found credential mixing: %+v", event)
			}
		}
	}
	t.Logf("sanitized provider audit: owner A requests=%d, owner B requests=%d; successful repository requests stayed with their credential principal", counts["fixture-owner-a"], counts["fixture-owner-b"])
	t.Logf("sanitized provider audit by principal/status: %v", statusCounts)
	t.Log("real Docker Gateway E2E passed: two owners, HTTPS provider credentials, private repositories, binding and gateway authentication denials, stop/restart/close isolation")
}

func (h *pilotHarness) callTool(client *Client, binding Binding, name string, args json.RawMessage) (Result, error) {
	h.t.Helper()
	start := time.Now()
	result, err := client.CallTool(h.ctx, binding, name, args)
	h.t.Logf("real read call: owner=%s tool=%s elapsed=%s result=%s text_bytes=%d structured_bytes=%d", binding.OwnerID, name, time.Since(start).Round(time.Millisecond), h.errorText(err), len(result.Text), len(result.StructuredContent))
	return result, err
}

func issueArgs(repository string) json.RawMessage {
	return json.RawMessage(fmt.Sprintf(`{"method":"get","owner":"fixture","repo":%q,"issue_number":1}`, repository))
}

type pilotAuditEvent struct {
	Principal  string `json:"principal"`
	Path       string `json:"path"`
	Repository string `json:"repository"`
	Status     int    `json:"status"`
}

type pilotHarness struct {
	t                                                   *testing.T
	ctx                                                 context.Context
	dir, suffix, network, image, fixtureURL, adminToken string
	secrets                                             []string
	fixtureHTTP                                         *http.Client
}

type pilotGateway struct {
	name, endpoint, bearer string
	requests               atomic.Int64
	upstream               atomic.Pointer[url.URL]
}

func newPilotHarness(t *testing.T, ctx context.Context) *pilotHarness {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatal("Docker CLI is required for explicitly enabled E2E")
	}
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	h := &pilotHarness{t: t, ctx: ctx, dir: t.TempDir(), suffix: hex.EncodeToString(b)}
	h.network = "toolbox-mcp-e2e-" + h.suffix
	h.image = "toolbox-github-fixture:" + h.suffix
	t.Cleanup(h.assertTaskResourcesRemoved)
	h.adminToken = "fixture-audit-" + h.suffix
	h.secrets = []string{"github_pat_fixture_owner_a_" + h.suffix, "github_pat_fixture_owner_b_" + h.suffix, h.adminToken}
	h.docker("info", "--format", "{{.ServerVersion}}")
	for _, image := range []string{pilotGatewayImage, pilotGitHubImage} {
		h.docker("image", "inspect", image, "--format", "{{.Id}}")
	}
	ca := h.writeCertificates()
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		t.Fatal("invalid fixture CA")
	}
	h.fixtureHTTP = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "fixture", MinVersion: tls.VersionTLS12}}, Timeout: 5 * time.Second}
	_, source, _, _ := runtime.Caller(0)
	moduleDir := filepath.Clean(filepath.Join(filepath.Dir(source), "../.."))
	build := exec.CommandContext(ctx, filepath.Join(runtime.GOROOT(), "bin/go"), "build", "-trimpath", "-o", filepath.Join(h.dir, "fixture"), "./internal/testutil/githubfixture/cmd")
	build.Dir = moduleDir
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+runtime.GOARCH)
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build fixture: %v\n%s", err, h.redact(string(output)))
	}
	h.writeFile("Dockerfile", []byte("FROM scratch\nCOPY fixture /fixture\nENTRYPOINT [\"/fixture\"]\n"), 0600)
	h.docker("build", "--network=none", "--tag", h.image, h.dir)
	t.Cleanup(func() { h.cleanupDocker("image", "rm", h.image) })
	// Docker suppresses published ports on an internal bridge. A dedicated bridge
	// with loopback-only published ports keeps both real HTTP endpoints private.
	h.docker("network", "create", "--label", "toolbox.mcp.e2e="+h.suffix, h.network)
	t.Cleanup(func() { h.cleanupNetwork() })
	config := map[string]any{"admin_token": h.adminToken, "principals": []map[string]any{
		{"token": h.secrets[0], "login": "fixture-owner-a", "id": 101, "repository": "fixture/private-a"},
		{"token": h.secrets[1], "login": "fixture-owner-b", "id": 202, "repository": "fixture/private-b"},
	}}
	configJSON, _ := json.Marshal(config)
	h.writeFile("fixture-config.json", configJSON, 0600)
	name := "toolbox-mcp-fixture-" + h.suffix
	h.docker("run", "--detach", "--name", name, "--label", "toolbox.mcp.e2e="+h.suffix, "--network", h.network, "--network-alias", "fixture", "--publish", "127.0.0.1::9443", "--mount", "type=bind,src="+h.dir+",dst=/run/fixture,readonly", h.image, "-config", "/run/fixture/fixture-config.json", "-cert", "/run/fixture/server.crt", "-key", "/run/fixture/server.key")
	t.Cleanup(func() { h.cleanupDocker("rm", "--force", name) })
	h.fixtureURL = "https://" + h.containerPort(name, "9443/tcp")
	h.wait("fixture HTTPS", func() error {
		res, err := h.fixtureHTTP.Get(h.fixtureURL + "/__health")
		if err != nil {
			return err
		}
		defer res.Body.Close()
		if res.StatusCode != 200 {
			return fmt.Errorf("status %d", res.StatusCode)
		}
		return nil
	})
	return h
}

func (h *pilotHarness) startGateway(owner, githubToken string) *pilotGateway {
	h.t.Helper()
	g := &pilotGateway{name: "toolbox-mcp-gateway-" + owner + "-" + h.suffix, bearer: "gateway-" + owner + "-" + h.suffix}
	h.secrets = append(h.secrets, g.bearer)
	state := filepath.Join(h.dir, "owner-"+owner)
	if err := os.MkdirAll(filepath.Join(state, "catalogs"), 0700); err != nil {
		h.t.Fatal(err)
	}
	caPath := filepath.Join(h.dir, "ca.pem")
	catalog := fmt.Sprintf(`registry:
  github-official:
    type: server
    title: GitHub Official fixture
    description: controlled HTTPS GitHub fixture
    image: %s
    env:
      - {name: GITHUB_HOST, value: 'https://fixture:9443'}
      - {name: SSL_CERT_FILE, value: /run/fixture-ca.pem}
      - {name: GITHUB_READ_ONLY, value: '1'}
      - {name: GITHUB_TOOLS, value: 'get_me,issue_read'}
    volumes:
      - '%s:/run/fixture-ca.pem:ro'
    secrets:
      - {name: github.personal_access_token, env: GITHUB_PERSONAL_ACCESS_TOKEN}
`, pilotGitHubImage, caPath)
	if err := os.WriteFile(filepath.Join(state, "catalogs/pilot.yaml"), []byte(catalog), 0600); err != nil {
		h.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "secrets.env"), []byte("github.personal_access_token="+githubToken+"\n"), 0600); err != nil {
		h.t.Fatal(err)
	}
	h.docker("run", "--detach", "--name", g.name, "--label", "toolbox.mcp.e2e="+h.suffix, "--network", h.network, "--publish", "127.0.0.1::8811", "--mount", "type=bind,src=/var/run/docker.sock,dst=/var/run/docker.sock", "--mount", "type=bind,src="+state+",dst=/root/.docker/mcp", "--mount", "type=bind,src="+caPath+",dst="+caPath+",readonly", "--env", "MCP_GATEWAY_AUTH_TOKEN="+g.bearer, "--env", "MCP_GATEWAY_DOCKER_BIND_ALLOWED_PATHS="+h.dir, pilotGatewayImage, "--watch=false", "--log-calls=false", "--verbose=false", "--transport=streaming", "--host=0.0.0.0", "--port=8811", "--catalog=pilot.yaml", "--servers=github-official", "--tools=github-official:get_me,github-official:issue_read", "--secrets=/root/.docker/mcp/secrets.env")
	h.t.Cleanup(func() {
		if h.t.Failed() {
			h.logContainer(g.name)
		}
		h.cleanupDocker("rm", "--force", g.name)
	})
	h.verifyExplicitSecrets(g, state)
	h.refreshGateway(g)
	proxy := &httputil.ReverseProxy{Rewrite: func(r *httputil.ProxyRequest) { r.SetURL(g.upstream.Load()) }}
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		http.Error(w, "gateway unavailable", http.StatusBadGateway)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { g.requests.Add(1); proxy.ServeHTTP(w, r) }))
	h.t.Cleanup(server.Close)
	g.endpoint = server.URL + "/mcp"
	h.waitGateway(g)
	return g
}

func (h *pilotHarness) verifyExplicitSecrets(g *pilotGateway, state string) {
	h.t.Helper()
	var command []string
	if err := json.Unmarshal([]byte(h.docker("inspect", "--format", "{{json .Config.Cmd}}", g.name)), &command); err != nil {
		h.t.Fatal(err)
	}
	explicit := 0
	for _, arg := range command {
		if strings.HasPrefix(arg, "--secrets") {
			if arg != "--secrets=/root/.docker/mcp/secrets.env" {
				h.t.Fatal("gateway has an unexpected secret source")
			}
			explicit++
		}
		if strings.Contains(arg, "docker-desktop") {
			h.t.Fatal("gateway enabled Docker Desktop's default secret source")
		}
	}
	if explicit != 1 {
		h.t.Fatal("gateway must use exactly one explicit private secret file")
	}
	info, err := os.Stat(filepath.Join(state, "secrets.env"))
	if err != nil || info.Mode().Perm() != 0600 {
		h.t.Fatal("owner secret file must exist with mode 0600")
	}
	h.t.Log("gateway uses a distinct owner state directory and an explicit 0600 secret file; Docker Desktop default secrets are disabled")
}

func (h *pilotHarness) refreshGateway(g *pilotGateway) {
	h.t.Helper()
	// Docker reallocates a randomly published host port when a container starts.
	// Keep the client-facing endpoint stable while the test operator refreshes
	// the private upstream address after restarting its own container.
	u, err := url.Parse("http://" + h.containerPort(g.name, "8811/tcp"))
	if err != nil {
		h.t.Fatal(err)
	}
	g.upstream.Store(u)
}

func (h *pilotHarness) waitGateway(g *pilotGateway) {
	h.wait("gateway "+g.name, func() error {
		req, _ := http.NewRequestWithContext(h.ctx, "POST", g.endpoint, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"toolbox-e2e-health","version":"1"}}}`))
		req.Header.Set("Authorization", "Bearer "+g.bearer)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		response, err := (&http.Client{Timeout: 8 * time.Second}).Do(req)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(response.Body, 8192))
		if response.StatusCode != 200 || !strings.Contains(string(body), "serverInfo") {
			return fmt.Errorf("status %d: %s", response.StatusCode, h.redact(string(body)))
		}
		return nil
	})
}

type pilotBearerTransport string

func (b pilotBearerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.Header = req.Header.Clone()
	clone.Header.Set("Authorization", "Bearer "+string(b))
	return http.DefaultTransport.RoundTrip(clone)
}

func (h *pilotHarness) approveGateway(g *pilotGateway, binding Binding) Gateway {
	h.t.Helper()
	ctx, cancel := context.WithTimeout(h.ctx, 45*time.Second)
	defer cancel()
	session, err := mcp.NewClient(&mcp.Implementation{Name: "toolbox-pinned-pilot-inventory", Version: "1"}, nil).Connect(ctx, &mcp.StreamableClientTransport{Endpoint: g.endpoint, HTTPClient: &http.Client{Transport: pilotBearerTransport(g.bearer)}, MaxRetries: -1, DisableStandaloneSSE: true}, &mcp.ClientSessionOptions{ProtocolVersion: ProtocolVersion})
	if err != nil {
		h.t.Fatal(h.redact(err.Error()))
	}
	defer session.Close()
	info := session.InitializeResult().ServerInfo
	if info.Name != pilotGatewayName || info.Version != pilotGatewayVersion || session.InitializeResult().ProtocolVersion != ProtocolVersion {
		h.t.Fatal("pinned gateway identity or protocol changed")
	}
	h.t.Logf("pinned gateway initialize: name=%q version=%q protocol=%q image=%s GitHub=%s", info.Name, info.Version, session.InitializeResult().ProtocolVersion, pilotGatewayImage, pilotGitHubImage)
	inventory, err := session.ListTools(ctx, nil)
	if err != nil {
		h.t.Fatal(h.redact(err.Error()))
	}
	if inventory.NextCursor != "" {
		h.t.Fatal("unexpected paginated pinned gateway inventory")
	}
	var approved []Tool
	for _, tool := range inventory.Tools {
		if tool.Name != "get_me" && tool.Name != "issue_read" {
			h.t.Fatalf("pinned gateway exposed unapproved tool %q", tool.Name)
		}
		schema, err := json.Marshal(tool.InputSchema)
		if err != nil {
			h.t.Fatal(err)
		}
		digest, err := SchemaDigest(schema)
		if err != nil {
			h.t.Fatal(err)
		}
		if digest != map[string]string{"get_me": pilotGetMeSchema, "issue_read": pilotIssueReadSchema}[tool.Name] {
			h.t.Fatalf("pinned schema changed for %s: %s", tool.Name, digest)
		}
		h.t.Logf("approved tool %s schema sha256=%s", tool.Name, digest)
		approved = append(approved, Tool{Name: tool.Name, InputSchema: schema})
	}
	if len(approved) != 2 {
		h.t.Fatalf("pinned gateway inventory has %d approved tools; want 2", len(approved))
	}
	sort.Slice(approved, func(i, j int) bool { return approved[i].Name < approved[j].Name })
	return Gateway{Binding: binding, Endpoint: g.endpoint, BearerToken: g.bearer, ServerName: info.Name, ServerVersion: info.Version, Tools: approved}
}

func (h *pilotHarness) assertWrongBearer(endpoint, bearer string) {
	h.t.Helper()
	req, _ := http.NewRequestWithContext(h.ctx, "POST", endpoint, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_me","arguments":{}}}`))
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	res, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		h.t.Fatal(h.redact(err.Error()))
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 8192))
	h.assertNoTokens(string(body))
	if res.StatusCode != http.StatusUnauthorized && res.StatusCode != http.StatusForbidden {
		h.t.Fatalf("wrong gateway bearer status=%d", res.StatusCode)
	}
}

func (h *pilotHarness) audit() []pilotAuditEvent {
	h.t.Helper()
	req, _ := http.NewRequestWithContext(h.ctx, "GET", h.fixtureURL+"/__audit", nil)
	req.Header.Set("Authorization", "Bearer "+h.adminToken)
	res, err := h.fixtureHTTP.Do(req)
	if err != nil {
		h.t.Fatal(h.redact(err.Error()))
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		h.t.Fatalf("audit status %d", res.StatusCode)
	}
	var events []pilotAuditEvent
	if err := json.NewDecoder(res.Body).Decode(&events); err != nil {
		h.t.Fatal(err)
	}
	return events
}

func (h *pilotHarness) assertResult(result Result, want string) {
	h.t.Helper()
	value := result.Text + string(result.StructuredContent)
	h.assertNoTokens(value)
	if !strings.Contains(value, want) {
		h.t.Errorf("result does not contain expected fixture value %q: %s", want, h.redact(value))
	}
}
func (h *pilotHarness) assertNoTokens(value string) {
	h.t.Helper()
	if strings.Contains(value, "github_pat_") {
		h.t.Fatal("provider credential appeared in tool result or error")
	}
	for _, secret := range h.secrets {
		if strings.Contains(value, secret) {
			h.t.Fatal("credential appeared in tool result or error")
		}
	}
}
func (h *pilotHarness) redact(value string) string {
	for _, secret := range h.secrets {
		value = strings.ReplaceAll(value, secret, "[REDACTED]")
	}
	return value
}
func (h *pilotHarness) errorText(err error) string {
	if err == nil {
		return "<nil>"
	}
	return h.redact(err.Error())
}

func (h *pilotHarness) docker(args ...string) string {
	h.t.Helper()
	ctx, cancel := context.WithTimeout(h.ctx, 60*time.Second)
	defer cancel()
	out, err := h.dockerCommand(ctx, args...).CombinedOutput()
	if err != nil {
		h.t.Fatalf("docker %s failed: %v\n%s", safeDockerVerb(args), err, h.redact(string(out)))
	}
	return strings.TrimSpace(string(out))
}
func (h *pilotHarness) dockerCommand(ctx context.Context, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, "docker", append([]string{"--host=unix:///var/run/docker.sock"}, args...)...)
	for _, v := range os.Environ() {
		key, _, _ := strings.Cut(v, "=")
		switch key {
		case "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH":
			continue
		}
		cmd.Env = append(cmd.Env, v)
	}
	return cmd
}
func safeDockerVerb(args []string) string {
	if len(args) > 1 {
		return args[0] + " " + args[1]
	}
	return args[0]
}
func (h *pilotHarness) cleanupDocker(args ...string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := h.dockerCommand(ctx, args...).CombinedOutput()
	if err != nil {
		h.t.Logf("cleanup docker %s: %v %s", safeDockerVerb(args), err, h.redact(string(out)))
	}
}

func (h *pilotHarness) cleanupNetwork() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// This uniquely named network is created solely for this test. The gateway
	// attaches its otherwise unlabelled child servers here, so remove only those
	// remaining task containers before deleting our network.
	out, err := h.dockerCommand(ctx, "network", "inspect", "--format", "{{range $id, $container := .Containers}}{{$id}} {{end}}", h.network).CombinedOutput()
	if err == nil {
		for _, id := range strings.Fields(string(out)) {
			h.cleanupDocker("rm", "--force", id)
		}
	}
	h.cleanupDocker("network", "rm", h.network)
}

func (h *pilotHarness) assertTaskResourcesRemoved() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	checks := [][]string{
		{"ps", "--all", "--quiet", "--filter", "label=toolbox.mcp.e2e=" + h.suffix},
		{"network", "ls", "--quiet", "--filter", "name=^" + h.network + "$"},
		{"image", "ls", "--quiet", "--filter", "reference=" + h.image},
	}
	for _, args := range checks {
		out, err := h.dockerCommand(ctx, args...).CombinedOutput()
		if err != nil || strings.TrimSpace(string(out)) != "" {
			h.t.Errorf("task Docker cleanup verification failed for %s: %v %s", safeDockerVerb(args), err, h.redact(string(out)))
			return
		}
	}
	if _, err := h.dockerCommand(ctx, "image", "inspect", pilotGatewayImage, pilotGitHubImage, "--format", "{{.Id}}").CombinedOutput(); err != nil {
		h.t.Errorf("pinned upstream image preservation check failed: %v", err)
		return
	}
	h.t.Log("cleanup verified: no task-labelled containers, task network, or generated fixture image remain; pinned upstream images were preserved")
}
func (h *pilotHarness) logContainer(name string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, _ := h.dockerCommand(ctx, "logs", "--tail=80", name).CombinedOutput()
	h.t.Logf("gateway diagnostic %s:\n%s", name, h.redact(string(out)))
}
func (h *pilotHarness) containerPort(name, port string) string {
	value := h.docker("port", name, port)
	if _, _, err := net.SplitHostPort(value); err != nil {
		h.t.Fatalf("invalid published loopback port %q", value)
	}
	if !strings.HasPrefix(value, "127.0.0.1:") {
		h.t.Fatalf("gateway port is not private loopback: %q", value)
	}
	return value
}
func (h *pilotHarness) wait(description string, check func() error) {
	h.t.Helper()
	deadline := time.Now().Add(45 * time.Second)
	var err error
	for time.Now().Before(deadline) {
		if err = check(); err == nil {
			return
		}
		select {
		case <-h.ctx.Done():
			h.t.Fatal(h.ctx.Err())
		case <-time.After(250 * time.Millisecond):
		}
	}
	h.t.Fatalf("waiting for %s: %s", description, h.errorText(err))
}
func (h *pilotHarness) writeFile(name string, data []byte, mode os.FileMode) {
	h.t.Helper()
	if err := os.WriteFile(filepath.Join(h.dir, name), data, mode); err != nil {
		h.t.Fatal(err)
	}
}

func (h *pilotHarness) writeCertificates() []byte {
	h.t.Helper()
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		h.t.Fatal(err)
	}
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "toolbox controlled GitHub fixture CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		h.t.Fatal(err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	h.writeFile("ca.pem", caPEM, 0600)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		h.t.Fatal(err)
	}
	server := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "fixture"}, DNSNames: []string{"fixture"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, server, caTemplate, &key.PublicKey, caKey)
	if err != nil {
		h.t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		h.t.Fatal(err)
	}
	h.writeFile("server.crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600)
	h.writeFile("server.key", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0600)
	return caPEM
}
