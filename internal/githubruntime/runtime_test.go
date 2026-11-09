package githubruntime

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/ufaruq/toolbox/internal/githubapp"
	githubpolicy "github.com/ufaruq/toolbox/internal/servicepolicy/github"
	"net"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDeniedPolicyNeverLaunches(t *testing.T) {
	r := &Runtime{config: Config{OwnerID: "owner", InstallationID: 1, StateDirectory: privateTemp(t)}, launch: func(context.Context, string, string) (session, error) {
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
	launch := dockerLauncher(privateTemp(t))
	if os.Getenv("TOOLBOX_TEST_DOCKER_BRIDGE") == "1" {
		launch = dockerLauncherEndpoint(privateTemp(t), func(ctx context.Context, s *dockerSession) (string, error) {
			address, e := command(ctx, "inspect", "--format", fmt.Sprintf("{{(index .NetworkSettings.Networks %q).IPAddress}}", s.network), s.name)
			if e != nil {
				return "", e
			}
			ip := net.ParseIP(strings.TrimSpace(string(address)))
			if ip == nil || !ip.IsPrivate() {
				return "", ErrUnavailable
			}
			target := &url.URL{Scheme: "http", Host: net.JoinHostPort(ip.String(), "8811")}
			proxy := httptest.NewServer(httputil.NewSingleHostReverseProxy(target))
			t.Cleanup(proxy.Close)
			u, _ := url.Parse(proxy.URL)
			return u.Host, nil
		})
	}
	s, e := launch(ctx, "fixture-not-a-provider-secret", "issue_read")
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
	r := &Runtime{config: Config{OwnerID: "owner", InstallationID: 1, StateDirectory: privateTemp(t)}, issuer: f, launch: func(context.Context, string, string) (session, error) {
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
			r := &Runtime{config: Config{OwnerID: "owner", InstallationID: 1, StateDirectory: privateTemp(t)}, issuer: f, launch: func(context.Context, string, string) (session, error) { return s, nil }}
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
		r := &Runtime{config: Config{OwnerID: "owner", InstallationID: 1, StateDirectory: privateTemp(t)}, issuer: f, launch: func(context.Context, string, string) (session, error) { return s, nil }}
		g := githubpolicy.Grant{OwnerID: "owner", AgentID: "agent", ConnectionID: "c", Epoch: 1, RepositoryID: 2, Owner: "owner", Repository: "repo", Actions: []string{"files.read"}, Paths: []string{"safe.txt"}, Branches: []string{"main"}, ExpiresAt: time.Now().Add(time.Hour)}
		out, e := r.Execute(context.Background(), 1, g, "files.read", json.RawMessage(`{"branch":"main","path":"safe.txt"}`), func(context.Context) error { return nil })
		if out != nil || e != ErrUnavailable {
			t.Fatalf("cleanup failure returned success: %v", e)
		}
	}
}

func privateTemp(t *testing.T) string {
	t.Helper()
	p, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(p, 0700); e != nil {
		t.Fatal(e)
	}
	return p
}
func TestStateDirectoryRejectsUnsafePaths(t *testing.T) {
	base := privateTemp(t)
	shared := filepath.Join(base, "shared")
	os.Mkdir(shared, 0770)
	os.Chmod(shared, 0770)
	link := filepath.Join(base, "link")
	os.Symlink(base, link)
	file := filepath.Join(base, "file")
	os.WriteFile(file, []byte("x"), 0600)
	for _, p := range []string{"relative", "/", shared, filepath.Join(shared, "private"), link, filepath.Join(link, "child"), file} {
		if e := validateStateDirectory(p); e == nil {
			t.Errorf("accepted unsafe directory %q", p)
		}
	}
	if e := validateStateDirectory(filepath.Join(base, "private")); e != nil {
		t.Fatal(e)
	}
}

type treeIssuer struct {
	fakeIssuer
	treeJSON  string
	treeReads int
	nested    bool
	ancestor  bool
}

func (f *treeIssuer) GetRepositoryMetadata(ctx context.Context, token, owner, repo, suffix string, out any) error {
	if strings.Contains(suffix, "/git/trees/") {
		f.treeReads++
		if f.nested && strings.HasSuffix(suffix, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb") {
			mode, kind := "040000", "tree"
			if f.ancestor {
				mode, kind = "100644", "blob"
			}
			return json.Unmarshal([]byte(fmt.Sprintf(`{"tree":[{"path":"docs","mode":%q,"type":%q,"sha":"cccccccccccccccccccccccccccccccccccccccc"}]}`, mode, kind)), out)
		}
		return json.Unmarshal([]byte(f.treeJSON), out)
	}
	return f.fakeIssuer.GetRepositoryMetadata(ctx, token, owner, repo, suffix, out)
}
func TestMultiFileTreePreflight(t *testing.T) {
	for name, tree := range map[string]string{"directory": `{"tree":[{"path":"safe.txt","type":"tree","mode":"040000","sha":"cccccccccccccccccccccccccccccccccccccccc"}]}`, "symlink": `{"tree":[{"path":"safe.txt","type":"blob","mode":"120000"}]}`, "submodule": `{"tree":[{"path":"safe.txt","type":"commit","mode":"160000"}]}`, "blob ancestor": `{"tree":[{"path":"safe.txt","type":"blob","mode":"100644"}]}`} {
		t.Run(name, func(t *testing.T) {
			f := &treeIssuer{treeJSON: tree, nested: true, ancestor: name == "blob ancestor"}
			r := &Runtime{config: Config{OwnerID: "owner", InstallationID: 1, StateDirectory: privateTemp(t)}, issuer: f, launch: func(context.Context, string, string) (session, error) {
				t.Fatal("unsafe tree launched")
				return nil, nil
			}}
			g := githubpolicy.Grant{OwnerID: "owner", AgentID: "agent", ConnectionID: "c", Epoch: 1, RepositoryID: 2, Owner: "owner", Repository: "repo", Actions: []string{"files.write"}, Paths: []string{"docs", "docs/"}, Branches: []string{"main"}, AllowUnconditionalWrites: true, ExpiresAt: time.Now().Add(time.Hour)}
			path := "docs/safe.txt"
			if name == "blob ancestor" {
				path += "/new.txt"
			}
			raw := json.RawMessage(fmt.Sprintf(`{"branch":"main","message":"change","files":[{"path":%q,"content":"new"}]}`, path))
			_, e := r.Execute(context.Background(), 1, g, "files.write", raw, func(context.Context) error { return nil })
			if e != ErrDenied || len(f.issues) != 1 || f.treeReads < 1 {
				t.Fatalf("preflight=%v issued=%d reads=%d", e, len(f.issues), f.treeReads)
			}
		})
	}
	f := &treeIssuer{treeJSON: `{"tree":[]}`}
	r := &Runtime{issuer: f}
	g := githubpolicy.Grant{RepositoryID: 2, Owner: "owner", Repository: "repo"}
	_, e := r.preflight(context.Background(), "token", g, "files.write", githubpolicy.Call{Arguments: json.RawMessage(`{"branch":"main","files":[{"path":"new/a.txt"},{"path":"new/b.txt"}]}`)})
	if e != nil || f.treeReads != 1 {
		t.Fatalf("missing new paths/cache: %v reads=%d", e, f.treeReads)
	}
}

func TestUnsafeStateRejectedBeforeCredential(t *testing.T) {
	path := privateTemp(t)
	os.Chmod(path, 0770)
	f := &fakeIssuer{}
	r := &Runtime{config: Config{OwnerID: "owner", InstallationID: 1, StateDirectory: path}, issuer: f, launch: func(context.Context, string, string) (session, error) {
		t.Fatal("unsafe state launched")
		return nil, nil
	}}
	g := githubpolicy.Grant{OwnerID: "owner", AgentID: "agent", ConnectionID: "c", Epoch: 1, RepositoryID: 2, Owner: "owner", Repository: "repo", Actions: []string{"files.read"}, Paths: []string{"safe.txt"}, Branches: []string{"main"}, ExpiresAt: time.Now().Add(time.Hour)}
	_, e := r.Execute(context.Background(), 1, g, "files.read", json.RawMessage(`{"branch":"main","path":"safe.txt"}`), func(context.Context) error { return nil })
	if e != ErrDenied || len(f.issues) != 0 {
		t.Fatal("unsafe state issued credential")
	}
}

type issueClassificationIssuer struct {
	fakeIssuer
	metadata    string
	metadataErr error
}

func (f *issueClassificationIssuer) GetRepositoryMetadata(ctx context.Context, token, owner, repo, suffix string, out any) error {
	if strings.HasPrefix(suffix, "/issues/") {
		if f.metadataErr != nil {
			return f.metadataErr
		}
		return json.Unmarshal([]byte(f.metadata), out)
	}
	return f.fakeIssuer.GetRepositoryMetadata(ctx, token, owner, repo, suffix, out)
}

type issueResultSession struct{ closed bool }

func (s *issueResultSession) Close() error { s.closed = true; return nil }
func (s *issueResultSession) Call(ctx context.Context, _ githubpolicy.Call, check func(context.Context) error) (json.RawMessage, error) {
	if e := check(ctx); e != nil {
		return nil, e
	}
	return json.RawMessage(`{"content":[{"type":"text","text":"{\"id\":777,\"number\":7,\"title\":\"ordinary issue\",\"body\":\"approved issue text\"}"}]}`), nil
}
func TestIssueOnlyGrantRejectsPullRequestsBeforeDispatch(t *testing.T) {
	ordinary := `{"id":777,"number":7,"url":"https://api.github.com/repos/owner/repo/issues/7","repository_url":"https://api.github.com/repos/owner/repo"}`
	for name, metadata := range map[string]string{"ordinary": ordinary, "unapproved PR": strings.TrimSuffix(ordinary, "}") + `,"pull_request":{"url":"https://api.github.com/repos/owner/repo/pulls/7"}}`, "fork PR": strings.TrimSuffix(ordinary, "}") + `,"pull_request":{"url":"https://api.github.com/repos/owner/repo/pulls/7","head":{"repo":{"id":999}}}}`, "unknown null PR": strings.TrimSuffix(ordinary, "}") + `,"pull_request":null}`, "missing classification metadata": `{}`, "wrong issue number": strings.Replace(ordinary, `"number":7`, `"number":8`, 1), "invalid issue ID": strings.Replace(ordinary, `"id":777`, `"id":0`, 1), "wrong issue locator": strings.Replace(ordinary, "/issues/7", "/issues/8", 1), "other repo": strings.ReplaceAll(ordinary, "/owner/repo", "/owner/other"), "metadata failure": "failure"} {
		t.Run(name, func(t *testing.T) {
			f := &issueClassificationIssuer{metadata: metadata}
			if metadata == "failure" {
				f.metadataErr = ErrUnavailable
			}
			launched := 0
			s := &issueResultSession{}
			r := &Runtime{config: Config{OwnerID: "owner", InstallationID: 1, StateDirectory: privateTemp(t)}, issuer: f, launch: func(context.Context, string, string) (session, error) { launched++; return s, nil }}
			g := githubpolicy.Grant{OwnerID: "owner", AgentID: "agent", ConnectionID: "connection", Epoch: 1, RepositoryID: 2, Owner: "owner", Repository: "repo", Actions: []string{"issues.read"}, ExpiresAt: time.Now().Add(time.Hour)}
			out, e := r.Execute(context.Background(), 1, g, "issues.read", json.RawMessage(`{"issue_number":7}`), func(context.Context) error { return nil })
			if name == "ordinary" {
				if e != nil || launched != 1 || len(f.issues) != 2 || !s.closed || !strings.Contains(string(out), "approved issue text") {
					t.Fatalf("ordinary issue failed: %v launch=%d issue=%d", e, launched, len(f.issues))
				}
				for _, p := range f.issues {
					if len(p) != 2 || p["metadata"] != "read" || p["issues"] != "read" {
						t.Fatalf("unexpected permission scope: %v", p)
					}
				}
			} else if e != ErrDenied || out != nil || launched != 0 || len(f.issues) != 1 || f.revokes != 1 {
				t.Fatalf("issue classification did not deny pre-dispatch: err=%v launch=%d issued=%d revoked=%d", e, launched, len(f.issues), f.revokes)
			}
		})
	}
}
