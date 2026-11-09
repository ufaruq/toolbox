package github

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestOperations(t *testing.T) {
	sha := strings.Repeat("a", 40)
	for _, tc := range []struct{ action, raw, tool string }{
		{"files.update", `{"branch":"agent/task","path":"src/a","content":"x","message":"fix","sha":"` + sha + `"}`, "create_or_update_file"},
		{"branches.create", `{"branch":"agent/task","from_branch":"main"}`, "create_branch"},
		{"prs.read", `{"pull_number":7}`, "pull_request_read"},
		{"prs.create", `{"head":"agent/task","base":"main","title":"Fix","body":"Details"}`, "create_pull_request"},
		{"prs.update", `{"pull_number":7,"state":"closed"}`, "update_pull_request"},
		{"prs.review", `{"pull_number":7,"event":"APPROVE","commit_id":"` + sha + `","body":"Reviewed"}`, "pull_request_review_write"},
		{"prs.merge", `{"pull_number":7,"expected_head":"` + sha + `","merge_method":"squash"}`, "merge_pull_request"},
		{"issues.read", `{"issue_number":3}`, "issue_read"},
	} {
		t.Run(tc.action, func(t *testing.T) {
			g := operationGrant()
			c, e := Build(g, tc.action, json.RawMessage(tc.raw), time.Now())
			if e != nil || c.Tool != tc.tool {
				t.Fatalf("%+v %v", c, e)
			}
			var a map[string]any
			json.Unmarshal(c.Arguments, &a)
			if a["owner"] != "org" || a["repo"] != "repo" {
				t.Fatal("trusted scope lost")
			}
			if tc.action == "prs.merge" && a["expectedHeadSha"] != sha {
				t.Fatal("missing merge CAS")
			}
		})
	}
}
func operationGrant() Grant {
	g := approved()
	g.Actions = []string{"files.read", "files.write", "files.update", "branches.create", "prs.read", "prs.create", "prs.update", "prs.review", "prs.merge", "issues.read"}
	g.BaseBranches = []string{"main"}
	g.PullRequests = []int64{7}
	g.ExpectedHead = strings.Repeat("a", 40)
	g.AllowUnconditionalWrites = true
	return g
}
func TestOperationDenials(t *testing.T) {
	for _, tc := range []struct{ action, raw string }{
		{"files.update", `{"branch":"agent/task","path":"src/a","content":"x","message":"fix"}`},
		{"branches.create", `{"branch":"agent/task","from_branch":"other"}`},
		{"prs.create", `{"head":"other:agent/task","base":"main","title":"Fix"}`},
		{"prs.update", `{"pull_number":8,"state":"closed"}`},
		{"prs.update", `{"pull_number":7,"base":"unapproved"}`},
		{"prs.review", `{"pull_number":7,"method":"resolve_thread","threadId":"other"}`},
		{"prs.merge", `{"pull_number":7,"expected_head":"` + strings.Repeat("b", 40) + `"}`},
		{"prs.read", `{"pull_number":7,"method":"get_diff"}`},
		{"issues.read", `{"issue_number":3,"repo":"other"}`},
	} {
		t.Run(tc.action+tc.raw, func(t *testing.T) {
			if _, e := Build(operationGrant(), tc.action, json.RawMessage(tc.raw), time.Now()); e == nil {
				t.Fatal("accepted")
			}
		})
	}
}
func TestWriteRequiresExplicitUnconditionalPolicy(t *testing.T) {
	g := operationGrant()
	g.AllowUnconditionalWrites = false
	if _, e := Build(g, "files.write", json.RawMessage(`{"branch":"agent/task","message":"fix","files":[{"path":"src/a","content":"x"}]}`), time.Now()); e == nil {
		t.Fatal("accepted unconditional write")
	}
}
func TestPermissions(t *testing.T) {
	for _, a := range operationGrant().Actions {
		p, e := Permissions(a)
		if e != nil || p["metadata"] != "read" || len(p) != 2 {
			t.Fatalf("%s: %v %v", a, p, e)
		}
	}
	if _, e := Permissions("repositories.delete"); e == nil {
		t.Fatal("unknown accepted")
	}
}

func TestTrustedPRMetadata(t *testing.T) {
	g := operationGrant()
	sha := g.ExpectedHead
	for _, tc := range []struct {
		n               int64
		head, base, sha string
	}{{8, "agent/task", "main", sha}, {7, "other", "main", sha}, {7, "agent/task", "other", sha}, {7, "agent/task", "main", strings.Repeat("b", 40)}} {
		if ValidatePullRequest(g, tc.n, tc.head, tc.base, tc.sha) == nil {
			t.Fatal("wrong PR target or stale approval accepted")
		}
	}
	if e := ValidatePullRequest(g, 7, "agent/task", "main", sha); e != nil {
		t.Fatal(e)
	}
}
func TestGrantRestrictions(t *testing.T) {
	if e := ValidateGrant(operationGrant()); e != nil {
		t.Fatal(e)
	}
	for _, change := range []func(*Grant){func(g *Grant) { g.Paths = []string{"src/../"} }, func(g *Grant) { g.Branches = []string{"refs/heads/main"} }, func(g *Grant) { g.Actions = []string{"force_push"} }, func(g *Grant) { g.PullRequests = []int64{-1} }, func(g *Grant) { g.ExpectedHead = "abc" }, func(g *Grant) { g.AllowUnconditionalWrites = false }} {
		g := operationGrant()
		change(&g)
		if ValidateGrant(g) == nil {
			t.Fatal("invalid restriction accepted")
		}
	}
}
func TestReadRejectsPathAndBranchAmbiguity(t *testing.T) {
	for _, p := range []string{"src/../x", "src/%2e%2e/x", "src/.git/config", ".github/workflows/x", "/src/x", "src\\x", "src/./x"} {
		raw, _ := json.Marshal(map[string]any{"branch": "agent/task", "path": p})
		if _, e := Build(operationGrant(), "files.read", raw, time.Now()); e == nil {
			t.Fatalf("accepted %s", p)
		}
	}
	for _, b := range []string{"refs/heads/task", "task..bad", "task.lock", "task@{x}", "task\n"} {
		g := operationGrant()
		g.Branches = []string{b}
		raw, _ := json.Marshal(map[string]any{"branch": b, "path": "src/a"})
		if _, e := Build(g, "files.read", raw, time.Now()); e == nil {
			t.Fatalf("accepted branch %q", b)
		}
	}
}
func TestInputBoundsAndStrictness(t *testing.T) {
	g := operationGrant()
	for _, raw := range []string{`{"pull_number":7,"pull_number":7}`, `{"Pull_number":7}`, `{"pull_number":7} {}`, `null`, strings.Repeat(" ", 16385) + `{}`} {
		if _, e := Build(g, "prs.read", json.RawMessage(raw), time.Now()); e == nil {
			t.Fatal("invalid JSON accepted")
		}
	}
	files := make([]map[string]string, 21)
	for i := range files {
		files[i] = map[string]string{"path": "src/a", "content": "x"}
	}
	raw, _ := json.Marshal(map[string]any{"branch": "agent/task", "message": "fix", "files": files})
	if _, e := Build(g, "files.write", raw, time.Now()); e == nil {
		t.Fatal("file limit accepted")
	}
}
func TestReadPinsExactBranch(t *testing.T) {
	c, e := Build(operationGrant(), "files.read", json.RawMessage(`{"branch":"agent/task","path":"src/a"}`), time.Now())
	if e != nil {
		t.Fatal(e)
	}
	c, e = PinRead(c, strings.Repeat("b", 40))
	if e != nil || !strings.Contains(string(c.Arguments), `"sha":"`+strings.Repeat("b", 40)+`"`) {
		t.Fatalf("%s %v", c.Arguments, e)
	}
	if _, e := PinRead(c, "bad"); e == nil {
		t.Fatal("bad commit accepted")
	}
}

func TestMultiFileWriteRequiresSubtreeAndAncestorAuthorization(t *testing.T) {
	raw := json.RawMessage(`{"branch":"agent/task","message":"fix","files":[{"path":"src/config","content":"x"}]}`)
	for _, paths := range [][]string{{"src/config"}, {"src/"}, {"src/config/"}} {
		g := operationGrant()
		g.Paths = paths
		if _, e := Build(g, "files.write", raw, time.Now()); e == nil {
			t.Fatalf("accepted potentially out-of-scope tree replacement with %v", paths)
		}
	}
	g := operationGrant()
	g.Paths = []string{"src", "src/"}
	if _, e := Build(g, "files.write", raw, time.Now()); e != nil {
		t.Fatal(e)
	}
	raw = json.RawMessage(`{"branch":"agent/task","message":"fix","files":[{"path":"src","content":"x"}]}`)
	if _, e := Build(g, "files.write", raw, time.Now()); e == nil {
		t.Fatal("subtree boundary replacement accepted")
	}
	raw = json.RawMessage(`{"branch":"agent/task","message":"fix","files":[{"path":"src/config","content":"x"},{"path":"src/config/a","content":"y"}]}`)
	if _, e := Build(g, "files.write", raw, time.Now()); e == nil {
		t.Fatal("conflicting ancestor descendant paths accepted")
	}
	g.Paths = []string{".github", ".github/"}
	raw = json.RawMessage(`{"branch":"agent/task","message":"fix","files":[{"path":".github","content":"x"}]}`)
	if _, e := Build(g, "files.write", raw, time.Now()); e == nil {
		t.Fatal("workflow parent replacement accepted")
	}
}
func TestWhitespaceOnlyFileUpdates(t *testing.T) {
	for _, content := range []string{"\n", " ", "\t\n"} {
		raw, _ := json.Marshal(map[string]any{"branch": "agent/task", "path": "src/a", "message": "fix", "content": content, "sha": strings.Repeat("a", 40)})
		if _, e := Build(operationGrant(), "files.update", raw, time.Now()); e != nil {
			t.Fatalf("valid nonempty content %q rejected: %v", content, e)
		}
	}
}

func TestMultiFileNestedAncestorsAndGrantValidation(t *testing.T) {
	raw := json.RawMessage(`{"branch":"agent/task","message":"fix","files":[{"path":"src/deep/config","content":"x"}]}`)
	g := operationGrant()
	g.Paths = []string{"src/deep", "src/deep/"}
	if _, e := Build(g, "files.write", raw, time.Now()); e == nil {
		t.Fatal("unapproved root ancestor accepted")
	}
	g.Paths = []string{"src", "src/deep", "src/deep/"}
	if _, e := Build(g, "files.write", raw, time.Now()); e != nil {
		t.Fatal(e)
	}
	g.Paths = []string{"src/config"}
	if ValidateGrant(g) == nil {
		t.Fatal("exact-file-only multi-file grant accepted")
	}
	g.Actions = []string{"files.update"}
	if e := ValidateGrant(g); e != nil {
		t.Fatalf("exact-file CAS grant rejected: %v", e)
	}
}
