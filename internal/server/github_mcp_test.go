package server

import (
	"context"
	"encoding/json"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/ufaruq/toolbox/internal/domain"
	"strings"
	"testing"
	"time"
)

func TestGitHubMCPAuthorizationAndCatalog(t *testing.T) {
	s, r, ts := mcpFixture(t)
	stub := &githubStub{}
	s.GitHub = stub
	if err := r.Transact(context.Background(), func(st *domain.State) error {
		p := st.CallerProfiles["web-profile"]
		p.Tools = []string{domain.GitHubTool}
		st.CallerProfiles[p.ID] = p
		st.GitHubConnections["ghc"] = domain.GitHubConnection{ID: "ghc", OwnerID: "owner", InstallationID: 42, RepositoryID: 99, RepositoryOwner: "org", RepositoryName: "repo", Epoch: 1, Status: "active"}
		st.GitHubGrants["ghg"] = domain.GitHubGrant{ID: "ghg", OwnerID: "owner", AgentID: "agent", ConnectionID: "ghc", RepositoryID: 99, Epoch: 1, Scope: domain.GitHubScope{Actions: []string{"files.read"}, Branches: []string{"main"}, Paths: []string{"src/"}}, NotBefore: st.Now, ExpiresAt: st.Now.Add(time.Hour)}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	web := connectMCP(t, ts, "web", "")
	code := connectMCP(t, ts, "code", "")
	tools, e := web.ListTools(context.Background(), nil)
	if e != nil || len(tools.Tools) != 4 {
		t.Fatalf("catalog=%+v err=%v", tools, e)
	}
	var discovered jsonschema.Schema
	for _, tool := range tools.Tools {
		if tool.Name == "github_operation_v1" {
			b, err := json.Marshal(tool.InputSchema)
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(b, &discovered); err != nil {
				t.Fatal(err)
			}
		}
	}
	resolved, err := discovered.Resolve(nil)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]map[string]any{
		"files.read":      {"branch": "main", "path": "src/a.go"},
		"files.update":    {"branch": "main", "path": "src/a.go", "content": "x", "message": "edit", "sha": strings.Repeat("a", 40)},
		"files.write":     {"branch": "main", "message": "edit", "files": []any{map[string]any{"path": "src/a.go", "content": ""}}},
		"branches.create": {"branch": "feature", "from_branch": "main"},
		"prs.read":        {"pull_number": 1},
		"prs.create":      {"head": "feature", "base": "main", "title": "title"},
		"prs.update":      {"pull_number": 1, "draft": false},
		"prs.review":      {"pull_number": 1, "event": "COMMENT", "body": "review", "commit_id": strings.Repeat("a", 40)},
		"prs.merge":       {"pull_number": 1, "expected_head": strings.Repeat("a", 40)},
		"issues.read":     {"issue_number": 1},
	}
	for action, arguments := range cases {
		t.Run(action, func(t *testing.T) {
			input := map[string]any{"grant_id": "ghg", "action": action, "arguments": arguments}
			if err := resolved.Validate(input); err != nil {
				t.Fatalf("valid input: %v", err)
			}
			arguments["unknown"] = true
			if err := resolved.Validate(input); err == nil {
				t.Error("discovery accepts unknown action field")
			}
			result, callErr := web.CallTool(context.Background(), &mcp.CallToolParams{Name: "github_operation_v1", Arguments: input})
			if callErr == nil && !result.IsError {
				t.Error("unknown action field reached successful dispatch")
			}
			if stub.calls != 0 {
				t.Error("invalid action reached provider")
			}
			delete(arguments, "unknown")
			input["arguments"] = map[string]any{}
			if err := resolved.Validate(input); err == nil {
				t.Error("discovery accepts missing required arguments")
			}
		})
	}
	hidden, e := code.ListTools(context.Background(), nil)
	if e != nil || len(hidden.Tools) != 0 {
		t.Fatalf("other catalog=%+v %v", hidden, e)
	}
	for _, bad := range []bool{false, true} {
		args := map[string]any{"branch": "main", "path": "src/a.go"}
		if bad {
			args["owner"] = "other"
		}
		result, e := web.CallTool(context.Background(), &mcp.CallToolParams{Name: "github_operation_v1", Arguments: map[string]any{"grant_id": "ghg", "action": "files.read", "arguments": args}})
		if e != nil {
			t.Fatal(e)
		}
		if result.IsError != bad {
			t.Fatalf("bad=%v result=%+v", bad, result)
		}
	}
	if stub.calls != 1 {
		t.Fatal("invalid operation reached provider")
	}
	res, e := web.CallTool(context.Background(), &mcp.CallToolParams{Name: "toolbox_request_github_access", Arguments: map[string]any{"connection_id": "ghc", "duration_seconds": 60, "scope": map[string]any{"actions": []string{"files.read"}, "branches": []string{"main"}, "paths": []string{"src/"}}}})
	if e != nil || res.IsError {
		t.Fatalf("create %+v %v", res, e)
	}
	var made map[string]any
	json.Unmarshal([]byte(res.Content[0].(*mcp.TextContent).Text), &made)
	cookie, csrf := ownerCookie(t, s, "owner")
	review := ownerPost(s, "/v1/github/requests/"+made["request_id"].(string)+"/review", `{}`, cookie, csrf)
	if review.Code != 200 {
		t.Fatal(review.Body.String())
	}
}

func TestGitHubOperationSchemaBounds(t *testing.T) {
	b, err := json.Marshal(githubOperationSchema())
	if err != nil {
		t.Fatal(err)
	}
	var schema jsonschema.Schema
	if err := json.Unmarshal(b, &schema); err != nil {
		t.Fatal(err)
	}
	if len(schema.OneOf) != 10 {
		t.Fatalf("action variants=%d", len(schema.OneOf))
	}
	resolved, err := schema.Resolve(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		action string
		args   map[string]any
	}{
		{"files.read", map[string]any{"branch": strings.Repeat("b", 201), "path": "a"}},
		{"files.update", map[string]any{"branch": "main", "path": "a", "content": "x", "message": "edit", "sha": "bad"}},
		{"files.write", map[string]any{"branch": "main", "message": "edit", "files": []any{map[string]any{"path": "a", "content": "x", "mode": "symlink"}}}},
		{"files.write", map[string]any{"branch": "main", "message": "edit", "files": []any{}}},
		{"branches.create", map[string]any{"branch": "feature", "from_branch": true}},
		{"prs.create", map[string]any{"head": "feature", "base": "main", "title": strings.Repeat("x", 257)}},
		{"prs.create", map[string]any{"head": "feature", "base": "main", "title": "   "}},
		{"prs.read", map[string]any{"pull_number": 1.5}},
		{"prs.update", map[string]any{"pull_number": 1}},
		{"prs.update", map[string]any{"pull_number": 1, "state": "merged"}},
		{"prs.review", map[string]any{"pull_number": 1, "commit_id": strings.Repeat("a", 40), "event": "DELETE", "body": "review"}},
		{"prs.merge", map[string]any{"pull_number": 1, "expected_head": strings.Repeat("a", 40), "merge_method": "delete"}},
		{"issues.read", map[string]any{"issue_number": 0}},
	} {
		t.Run(tc.action, func(t *testing.T) {
			if err := resolved.Validate(map[string]any{"grant_id": "ghg", "action": tc.action, "arguments": tc.args}); err == nil {
				t.Fatalf("accepted invalid arguments: %+v", tc.args)
			}
		})
	}
}
