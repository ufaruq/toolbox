package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/ufaruq/toolbox/internal/githubruntime"
	"github.com/ufaruq/toolbox/internal/security"
	policy "github.com/ufaruq/toolbox/internal/servicepolicy/github"
)

// This explicit operator acceptance command does not claim to exercise owner
// login/approval. It uses real short-lived App tokens through the MCP runtime.
func runGitHubLive(getenv func(string) string, write bool, out io.Writer) (err error) {
	stage := "configuration"
	defer func() {
		if err != nil {
			fmt.Fprintf(out, "FAIL: GitHub acceptance stage=%s; inspect any printed branch/PR before retrying writes\n", stage)
		}
	}()
	cfg, e := loadGitHubConfig(getenv, "workspace-local")
	if e != nil || cfg == nil {
		return errors.New("GitHub acceptance requires complete private App configuration")
	}
	id, e := strconv.ParseInt(getenv("TOOLBOX_GITHUB_ACCEPTANCE_REPOSITORY_ID"), 10, 64)
	if e != nil || id <= 0 {
		return errors.New("GitHub acceptance requires an explicit repository ID")
	}
	integration, e := newGitHubIntegration(cfg)
	if e != nil {
		return e
	}
	r := integration.Runtime
	defer r.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	stage = "repository discovery"
	repos, e := r.Repositories(ctx, cfg.ownerID)
	if e != nil {
		return e
	}
	var owner, name string
	for _, repo := range repos {
		if repo.RepositoryID == id {
			owner, name = repo.Owner, repo.Name
		}
	}
	if owner == "" {
		return errors.New("acceptance repository is not installed")
	}
	fmt.Fprintln(out, "PASS: verified App installation and metadata-only repository discovery")
	g := policy.Grant{OwnerID: cfg.ownerID, AgentID: "operator-acceptance", ConnectionID: "operator-acceptance", RepositoryID: id, Epoch: 1, Owner: owner, Repository: name, Actions: []string{"files.read"}, Branches: []string{"main"}, Paths: []string{"README.md"}, ExpiresAt: time.Now().Add(10 * time.Minute)}
	check := func(ctx context.Context) error { return ctx.Err() }
	call := func(action string, args any) (map[string]json.RawMessage, error) {
		stage = action
		raw, e := json.Marshal(args)
		if e != nil {
			return nil, e
		}
		result, e := r.Execute(ctx, cfg.installationID, g, action, raw, check)
		if e != nil {
			return nil, e
		}
		var resultMap map[string]json.RawMessage
		e = json.Unmarshal(result, &resultMap)
		return resultMap, e
	}
	result, e := call("files.read", map[string]any{"branch": "main", "path": "README.md"})
	if e != nil {
		return e
	}
	if len(result["content"]) == 0 {
		return errors.New("missing live read result")
	}
	fmt.Fprintln(out, "PASS: real App token → Docker MCP Gateway → GitHub file read")
	negative := g
	negative.Owner = "octocat"
	negative.Repository = "Hello-World"
	if _, e = r.Execute(ctx, cfg.installationID, negative, "files.read", json.RawMessage(`{"branch":"main","path":"README.md"}`), check); !errors.Is(e, githubruntime.ErrDenied) {
		return errors.New("public cross-repository negative check failed")
	}
	fmt.Fprintln(out, "PASS: public repository locator mismatch rejected by Toolbox runtime")
	if !write {
		return nil
	}
	branch := "toolbox-acceptance/" + security.ID()
	// This dedicated branch is never merged; writes affect only synthetic files.
	// The branch is retained for inspection. The temporary draft PR is closed.
	fmt.Fprintf(out, "Acceptance branch: %s\n", branch)
	g.Branches = []string{branch}
	g.BaseBranches = []string{"main"}
	g.Paths = []string{".toolbox-acceptance", ".toolbox-acceptance/"}
	g.AllowUnconditionalWrites = true
	g.Actions = []string{"branches.create", "files.write", "files.read", "files.update", "prs.create"}
	if _, e = call("branches.create", map[string]any{"branch": branch, "from_branch": "main"}); e != nil {
		return e
	}
	fmt.Fprintln(out, "PASS: created dedicated acceptance branch")
	path := ".toolbox-acceptance/probe-a.txt"
	if _, e = call("files.write", map[string]any{"branch": branch, "message": "Test Toolbox MCP multi-file commit", "files": []map[string]string{{"path": path, "content": "synthetic acceptance A\n"}, {"path": ".toolbox-acceptance/probe-b.txt", "content": "synthetic acceptance B\n"}}}); e != nil {
		return e
	}
	result, e = call("files.read", map[string]any{"branch": branch, "path": path})
	if e != nil {
		return e
	}
	var sha, content string
	json.Unmarshal(result["sha"], &sha)
	json.Unmarshal(result["content"], &content)
	if content != "synthetic acceptance A\n" || sha == "" {
		return errors.New("multi-file write verification failed")
	}
	second, e := call("files.read", map[string]any{"branch": branch, "path": ".toolbox-acceptance/probe-b.txt"})
	if e != nil {
		return e
	}
	var secondContent string
	if json.Unmarshal(second["content"], &secondContent) != nil || secondContent != "synthetic acceptance B\n" {
		return errors.New("second committed file verification failed")
	}
	fmt.Fprintln(out, "PASS: multi-file commit and both exact-path readbacks")
	if _, e = call("files.update", map[string]any{"branch": branch, "path": path, "sha": sha, "content": "synthetic acceptance updated\n", "message": "Test Toolbox MCP conditional file update"}); e != nil {
		return e
	}
	result, e = call("files.read", map[string]any{"branch": branch, "path": path})
	if e != nil {
		return e
	}
	json.Unmarshal(result["content"], &content)
	if content != "synthetic acceptance updated\n" {
		return errors.New("conditional file update verification failed")
	}
	fmt.Fprintln(out, "PASS: conditional file update and readback")
	result, e = call("prs.create", map[string]any{"head": branch, "base": "main", "title": "Toolbox GitHub connector acceptance (do not merge)", "body": "Automated live validation of the Toolbox MCP connector using a dedicated test branch. Contains synthetic files only. This draft is closed after validation and must not be merged.", "draft": true})
	if e != nil {
		return e
	}
	stage = "created PR result validation"
	var number int64
	if json.Unmarshal(result["number"], &number) != nil || number <= 0 {
		return errors.New("missing created PR number; inspect acceptance branch")
	}
	fmt.Fprintf(out, "Acceptance PR: https://github.com/%s/%s/pull/%d\n", owner, name, number)
	g.Actions = append(g.Actions, "prs.read", "prs.update")
	g.PullRequests = []int64{number}
	// Close even if read validation fails. Never repeat a dispatched mutation.
	readResult, readErr := call("prs.read", map[string]any{"pull_number": number})
	_, closeErr := call("prs.update", map[string]any{"pull_number": number, "state": "closed"})
	if closeErr != nil {
		return errors.New("acceptance PR close uncertain; inspect printed PR")
	}
	if readErr != nil {
		return readErr
	}
	if len(readResult["number"]) == 0 {
		return errors.New("PR read result invalid")
	}
	closed, e := call("prs.read", map[string]any{"pull_number": number})
	if e != nil {
		return e
	}
	var state string
	if json.Unmarshal(closed["state"], &state) != nil || state != "closed" {
		return errors.New("acceptance PR closure not confirmed")
	}
	fmt.Fprintln(out, "PASS: draft PR creation, read, close and closed-state verification; no merge performed")
	return nil
}
