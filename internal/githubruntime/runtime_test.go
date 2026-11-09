package githubruntime

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/ufaruq/toolbox/internal/githubapp"
	githubpolicy "github.com/ufaruq/toolbox/internal/servicepolicy/github"
	"os"
	"strings"
	"testing"
	"time"
)

func TestDeniedPolicyNeverLaunches(t *testing.T) {
	r := &Runtime{config: Config{OwnerID: "owner", InstallationID: 1}, launch: func(context.Context, string, string) (session, error) {
		t.Fatal("denied policy launched gateway")
		return nil, nil
	}}
	g := githubpolicy.Grant{OwnerID: "owner", AgentID: "agent", ConnectionID: "connection", RepositoryID: 2, Epoch: 1, Owner: "owner", Repository: "repo", Actions: []string{"files.read"}, Branches: []string{"main"}, Paths: []string{"safe.txt"}, ExpiresAt: time.Now().Add(time.Hour)}
	for _, raw := range []string{`{"branch":"main","path":"unsafe.txt"}`, `{"branch":"other","path":"safe.txt"}`} {
		if _, e := r.Execute(context.Background(), 1, g, "files.read", json.RawMessage(raw), func(context.Context) error { return nil }); e != ErrDenied {
			t.Fatal(e)
		}
	}
	if _, e := r.Execute(context.Background(), 1, g, "files.read", json.RawMessage(`{"branch":"main","path":"safe.txt"}`), func(context.Context) error { return ErrDenied }); e != ErrDenied {
		t.Fatal(e)
	}
}
func TestRepositoryOwnerBinding(t *testing.T) {
	r := &Runtime{config: Config{OwnerID: "owner"}}
	if _, e := r.Repositories(context.Background(), "other"); e != ErrDenied {
		t.Fatal(e)
	}
}
func TestReviewedInventory(t *testing.T) {
	var tools []struct {
		Name        string
		InputSchema json.RawMessage
	}
	if json.Unmarshal(schemas, &tools) != nil || len(tools) != 10 {
		t.Fatal("missing reviewed inventory")
	}
	seen := map[string]bool{}
	for _, tool := range tools {
		if tool.Name == "" || len(tool.InputSchema) == 0 || seen[tool.Name] {
			t.Fatal("invalid inventory")
		}
		seen[tool.Name] = true
	}
}
func TestDockerReviewedRuntimeStartup(t *testing.T) {
	if os.Getenv("TOOLBOX_TEST_DOCKER_MCP") != "1" {
		t.Skip("requires pinned Docker runtime acceptance")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	s, e := dockerLauncher(t.TempDir())(ctx, "fixture-not-a-provider-secret", "issue_read")
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
}

type fakeIssuer struct {
	revokes     int
	issues      []map[string]string
	symlink     bool
	revokeError bool
	fork        bool
}

func (f *fakeIssuer) Issue(_ context.Context, _, _ int64, p map[string]string) (githubapp.Credential, error) {
	f.issues = append(f.issues, p)
	return githubapp.Credential{Token: "fixture-installation-token"}, nil
}
func (f *fakeIssuer) Revoke(ctx context.Context, _ string) error {
	if ctx.Err() != nil {
		panic("canceled cleanup")
	}
	f.revokes++
	if f.revokeError {
		return ErrUnavailable
	}
	return nil
}
func (f *fakeIssuer) Repositories(context.Context, int64) ([]githubapp.Repository, error) {
	return nil, nil
}
func (f *fakeIssuer) GetRepositoryMetadata(_ context.Context, _, _, _, suffix string, out any) error {
	raw := `{"id":2,"name":"repo","owner":{"login":"owner"}}`
	switch {
	case strings.Contains(suffix, "/git/ref/"):
		raw = `{"ref":"refs/heads/main","object":{"type":"commit","sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}`
	case strings.Contains(suffix, "/git/commits/"):
		raw = `{"tree":{"sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}`
	case strings.Contains(suffix, "/git/trees/"):
		mode := "100644"
		if f.symlink {
			mode = "120000"
		}
		raw = fmt.Sprintf(`{"tree":[{"path":"safe.txt","mode":%q,"type":"blob","sha":"cccccccccccccccccccccccccccccccccccccccc"}]}`, mode)
	case strings.Contains(suffix, "/pulls/"):
		id := 2
		if f.fork {
			id = 3
		}
		raw = fmt.Sprintf(`{"head":{"ref":"feature","sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","repo":{"id":%d}},"base":{"ref":"main","repo":{"id":2}}}`, id)
	}
	return json.Unmarshal([]byte(raw), out)
}
func TestSymlinkPreflightDeniesAndRevokes(t *testing.T) {
	f := &fakeIssuer{symlink: true}
	r := &Runtime{config: Config{OwnerID: "owner", InstallationID: 1}, issuer: f, launch: func(context.Context, string, string) (session, error) {
		t.Fatal("symlink reached gateway")
		return nil, nil
	}}
	g := githubpolicy.Grant{OwnerID: "owner", AgentID: "agent", ConnectionID: "c", Epoch: 1, RepositoryID: 2, Owner: "owner", Repository: "repo", Actions: []string{"files.read"}, Paths: []string{"safe.txt"}, Branches: []string{"main"}, ExpiresAt: time.Now().Add(time.Hour)}
	if _, e := r.Execute(context.Background(), 1, g, "files.read", json.RawMessage(`{"branch":"main","path":"safe.txt"}`), func(context.Context) error { return nil }); e != ErrDenied || f.revokes != 1 {
		t.Fatalf("preflight=%v revokes=%d", e, f.revokes)
	}
}
func TestCrossRepositoryPRDenied(t *testing.T) {
	f := &fakeIssuer{fork: true}
	r := &Runtime{issuer: f}
	g := githubpolicy.Grant{RepositoryID: 2, Owner: "owner", Repository: "repo", Branches: []string{"feature"}, BaseBranches: []string{"main"}, PullRequests: []int64{1}}
	_, e := r.preflight(context.Background(), "token", g, "prs.read", githubpolicy.Call{Arguments: json.RawMessage(`{"pullNumber":1}`)})
	if e != ErrDenied {
		t.Fatal("fork PR accepted")
	}
}

type fakeSession struct {
	closed     bool
	cancel     context.CancelFunc
	closeError bool
	fail       bool
}

func (s *fakeSession) Close() error {
	s.closed = true
	if s.closeError {
		return ErrUnavailable
	}
	return nil
}
func (s *fakeSession) Call(ctx context.Context, _ githubpolicy.Call, check func(context.Context) error) (json.RawMessage, error) {
	if check(ctx) != nil {
		return nil, ErrDenied
	}
	if s.cancel != nil {
		s.cancel()
	}
	if s.fail {
		return nil, ErrUnavailable
	}
	return json.RawMessage(`{"content":[{"type":"text","text":"SHA: cccccccccccccccccccccccccccccccccccccccc"},{"type":"resource","resource":{"uri":"https://untrusted.invalid","text":"safe contents"}}]}`), nil
}
func TestResultProjectionAndCanceledCleanup(t *testing.T) {
	for _, cancelDuring := range []bool{false, true} {
		t.Run(fmt.Sprint(cancelDuring), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			f := &fakeIssuer{}
			s := &fakeSession{}
			if cancelDuring {
				s.cancel = cancel
			}
			r := &Runtime{config: Config{OwnerID: "owner", InstallationID: 1}, issuer: f, launch: func(context.Context, string, string) (session, error) { return s, nil }}
			g := githubpolicy.Grant{OwnerID: "owner", AgentID: "agent", ConnectionID: "c", Epoch: 1, RepositoryID: 2, Owner: "owner", Repository: "repo", Actions: []string{"files.read"}, Paths: []string{"safe.txt"}, Branches: []string{"main"}, ExpiresAt: time.Now().Add(time.Hour)}
			out, e := r.Execute(ctx, 1, g, "files.read", json.RawMessage(`{"branch":"main","path":"safe.txt"}`), func(ctx context.Context) error { return ctx.Err() })
			if f.revokes != 2 || !s.closed {
				t.Fatal("cleanup missing")
			}
			if cancelDuring {
				if e == nil || out != nil {
					t.Fatal("canceled result released")
				}
			} else if e != nil || strings.Contains(string(out), "untrusted.invalid") || !strings.Contains(string(out), "safe contents") {
				t.Fatalf("unsafe projection: %v", e)
			}
		})
	}
}

func TestCleanupFailureSuppressesResult(t *testing.T) {
	for _, tokenFailure := range []bool{false, true} {
		f := &fakeIssuer{revokeError: tokenFailure}
		s := &fakeSession{closeError: !tokenFailure}
		r := &Runtime{config: Config{OwnerID: "owner", InstallationID: 1}, issuer: f, launch: func(context.Context, string, string) (session, error) { return s, nil }}
		g := githubpolicy.Grant{OwnerID: "owner", AgentID: "agent", ConnectionID: "c", Epoch: 1, RepositoryID: 2, Owner: "owner", Repository: "repo", Actions: []string{"files.read"}, Paths: []string{"safe.txt"}, Branches: []string{"main"}, ExpiresAt: time.Now().Add(time.Hour)}
		out, e := r.Execute(context.Background(), 1, g, "files.read", json.RawMessage(`{"branch":"main","path":"safe.txt"}`), func(context.Context) error { return nil })
		if out != nil || e != ErrUnavailable {
			t.Fatalf("cleanup failure returned success: %v", e)
		}
	}
}
