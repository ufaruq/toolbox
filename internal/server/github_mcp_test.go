package server

import (
	"context"
	"encoding/json"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/ufaruq/toolbox/internal/domain"
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
