package githubruntime

import (
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/ufaruq/toolbox/internal/mcpclient"
	githubpolicy "github.com/ufaruq/toolbox/internal/servicepolicy/github"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const gatewayImage = "docker/mcp-gateway@sha256:b0a3876ffbb352813d658cf25c137b8eae29bbe23db5944560a1c9059533bb16"
const githubImage = "ghcr.io/github/github-mcp-server@sha256:250bc6ce70788207608ef74cef4397230ff2e8481218da74d6093e4bd9101132"

//go:embed testdata/tools.json
var schemas []byte

type dockerSession struct {
	client             *mcpclient.Client
	binding            mcpclient.Binding
	name, network, dir string
}

func command(ctx context.Context, args ...string) ([]byte, error) {
	out, e := exec.CommandContext(ctx, "docker", args...).Output()
	if e != nil {
		return nil, ErrUnavailable
	}
	return out, nil
}
func (s *dockerSession) Close() error {
	failed := false
	if s.client != nil {
		if s.client.Close() != nil {
			failed = true
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ids, e := command(ctx, "network", "inspect", "--format", "{{range $id, $container := .Containers}}{{$id}} {{end}}", s.network)
	if e != nil {
		failed = true
	}
	for _, id := range strings.Fields(string(ids)) {
		if _, e = command(ctx, "rm", "--force", id); e != nil {
			failed = true
		}
	}
	// Gateway may already have been removed as a network member.
	if !strings.Contains(string(ids), s.name) {
		command(ctx, "rm", "--force", s.name)
	}
	if _, e = command(ctx, "network", "rm", s.network); e != nil {
		failed = true
	}
	if os.RemoveAll(s.dir) != nil {
		failed = true
	}
	if failed {
		return ErrUnavailable
	}
	return nil
}

func (s *dockerSession) Call(ctx context.Context, c githubpolicy.Call, check func(context.Context) error) (json.RawMessage, error) {
	out, e := s.client.CallToolChecked(ctx, s.binding, c.Tool, c.Arguments, check)
	return out.Raw, e
}

type gatewayEndpoint func(context.Context, *dockerSession) (string, error)

func dockerLauncher(parent string) launcher { return dockerLauncherEndpoint(parent, nil) }
func dockerLauncherEndpoint(parent string, resolve gatewayEndpoint) launcher {
	return func(ctx context.Context, token, tool string) (session, error) {
		var inventory []struct {
			Name   string          `json:"name"`
			Schema json.RawMessage `json:"inputSchema"`
		}
		if json.Unmarshal(schemas, &inventory) != nil {
			return nil, ErrUnavailable
		}
		var pin mcpclient.Tool
		for _, t := range inventory {
			if t.Name == tool {
				pin = mcpclient.Tool{Name: t.Name, InputSchema: t.Schema, AllowTextResources: tool == "get_file_contents"}
			}
		}
		if pin.Name == "" {
			return nil, ErrDenied
		}
		nonce := make([]byte, 16)
		if _, e := rand.Read(nonce); e != nil {
			return nil, ErrUnavailable
		}
		suffix := hex.EncodeToString(nonce)
		bearer := "gateway-" + suffix
		if e := validateStateDirectory(parent); e != nil {
			return nil, ErrUnavailable
		}
		dir, e := os.MkdirTemp(parent, "operation-")
		if e != nil {
			return nil, ErrUnavailable
		}
		s := &dockerSession{name: "toolbox-github-" + suffix, network: "toolbox-github-" + suffix, dir: dir}
		success := false
		defer func() {
			if !success {
				s.Close()
			}
		}()
		if os.MkdirAll(filepath.Join(dir, "catalogs"), 0700) != nil {
			return nil, ErrUnavailable
		}
		catalog := fmt.Sprintf("registry:\n  github-official:\n    type: server\n    title: GitHub Official\n    image: %s\n    env:\n      - {name: GITHUB_TOOLS, value: '%s'}\n    secrets:\n      - {name: github.personal_access_token, env: GITHUB_PERSONAL_ACCESS_TOKEN}\n", githubImage, tool)
		if os.WriteFile(filepath.Join(dir, "catalogs/runtime.yaml"), []byte(catalog), 0600) != nil || os.WriteFile(filepath.Join(dir, "secrets.env"), []byte("github.personal_access_token="+token+"\n"), 0600) != nil {
			return nil, ErrUnavailable
		}
		if _, e = command(ctx, "network", "create", s.network); e != nil {
			return nil, e
		}
		if _, e = command(ctx, "run", "--detach", "--name", s.name, "--network", s.network, "--publish", "127.0.0.1::8811", "--mount", "type=bind,src=/var/run/docker.sock,dst=/var/run/docker.sock", "--mount", "type=bind,src="+dir+",dst=/root/.docker/mcp", "--env", "MCP_GATEWAY_AUTH_TOKEN="+bearer, gatewayImage, "--watch=false", "--log-calls=false", "--verbose=false", "--transport=streaming", "--host=0.0.0.0", "--port=8811", "--catalog=runtime.yaml", "--servers=github-official", "--tools=github-official:"+tool, "--secrets=/root/.docker/mcp/secrets.env"); e != nil {
			return nil, e
		}
		port, e := command(ctx, "port", s.name, "8811/tcp")
		if e != nil {
			return nil, e
		}
		endpoint := strings.TrimSpace(string(port))
		if resolve != nil {
			endpoint, e = resolve(ctx, s)
			if e != nil {
				return nil, ErrUnavailable
			}
		}
		if _, _, e = net.SplitHostPort(endpoint); e != nil {
			return nil, ErrUnavailable
		}
		s.binding = mcpclient.Binding{ID: suffix, OwnerID: suffix, ConnectionID: suffix, Epoch: 1}
		s.client, e = mcpclient.New(mcpclient.Config{Gateways: []mcpclient.Gateway{{Binding: s.binding, Endpoint: "http://" + endpoint + "/mcp", BearerToken: bearer, ServerName: "Docker AI MCP Gateway", ServerVersion: "2.0.1", Tools: []mcpclient.Tool{pin}}}})
		if e != nil {
			return nil, ErrUnavailable
		}
		for {
			if _, e = s.client.ListTools(ctx, s.binding); e == nil {
				break
			}
			select {
			case <-ctx.Done():
				return nil, ErrUnavailable
			case <-time.After(100 * time.Millisecond):
			}
		}
		success = true
		return s, nil
	}
}
