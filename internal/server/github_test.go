package server

import (
	"context"
	"encoding/json"
	"github.com/ufaruq/toolbox/internal/domain"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type githubStub struct {
	calls        int
	during       func()
	repositories []GitHubRepository
}

func (g *githubStub) Repositories(context.Context, string) ([]GitHubRepository, error) {
	return g.repositories, nil
}
func (g *githubStub) Execute(ctx context.Context, c domain.GitHubConnection, grant domain.GitHubGrant, action string, args json.RawMessage, check func(context.Context) error) (any, error) {
	if err := check(ctx); err != nil {
		return nil, err
	}
	g.calls++
	if g.during != nil {
		g.during()
	}
	return map[string]any{"content": "bounded fixture"}, nil
}
func githubInvocationFixture(t *testing.T) (*Server, *invocationAuditRepository, string, *githubStub) {
	s, r, request := invocationFixture(t)
	stub := &githubStub{}
	s.GitHub = stub
	e := r.Transact(context.Background(), func(st *domain.State) error {
		st.GitHubConnections["ghc"] = domain.GitHubConnection{ID: "ghc", OwnerID: "owner", InstallationID: 42, RepositoryID: 99, RepositoryOwner: "org", RepositoryName: "repo", Status: "active", Epoch: 1}
		st.GitHubGrants["ghg"] = domain.GitHubGrant{ID: "ghg", OwnerID: "owner", AgentID: "agent", ConnectionID: "ghc", RepositoryID: 99, Epoch: 1, Scope: domain.GitHubScope{Actions: []string{"files.read"}, Branches: []string{"main"}, Paths: []string{"src/"}}, NotBefore: st.Now, ExpiresAt: st.Now.Add(time.Hour)}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	return s, r, request.Header.Get("Authorization"), stub
}
func TestGitHubInvocationAuthorization(t *testing.T) {
	for _, scenario := range []string{"success", "wrong-grant", "revoked", "invalid-path", "disconnect-during-call"} {
		t.Run(scenario, func(t *testing.T) {
			s, r, auth, stub := githubInvocationFixture(t)
			grant, path := "ghg", "src/main.go"
			if scenario == "wrong-grant" {
				grant = "grant"
			}
			if scenario == "invalid-path" {
				path = "private/key"
			}
			if scenario == "revoked" {
				r.Transact(context.Background(), func(st *domain.State) error {
					g := st.GitHubGrants[grant]
					g.RevokedAt = &st.Now
					st.GitHubGrants[grant] = g
					return nil
				})
			}
			if scenario == "disconnect-during-call" {
				stub.during = func() {
					r.Transact(context.Background(), func(st *domain.State) error {
						c := st.GitHubConnections["ghc"]
						c.Status = "disconnected"
						c.Epoch++
						st.GitHubConnections[c.ID] = c
						return nil
					})
				}
			}
			req := httptest.NewRequest("POST", "/v1/github/invoke", strings.NewReader(`{"grant_id":"`+grant+`","action":"files.read","arguments":{"branch":"main","path":"`+path+`"}}`))
			req.Header.Set("Authorization", auth)
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			s.ServeHTTP(w, req)
			if scenario == "success" {
				if w.Code != 200 || stub.calls != 1 {
					t.Fatalf("%d %s calls=%d", w.Code, w.Body.String(), stub.calls)
				}
			} else {
				if w.Code == 200 || strings.Contains(w.Body.String(), "bounded fixture") {
					t.Fatalf("released unauthorized content: %d %s", w.Code, w.Body.String())
				}
				if scenario != "disconnect-during-call" && stub.calls != 0 {
					t.Fatal("denied request dispatched")
				}
			}
		})
	}
}

func TestGitHubCallerTools(t *testing.T) {
	if !validCallerTools([]string{domain.Tool, domain.GitHubTool}, 3600) || !validCallerTools([]string{domain.GitHubTool}, 3600) {
		t.Fatal("GitHub cannot be explicitly approved")
	}
	for _, tools := range [][]string{{domain.GitHubTool, domain.GitHubTool}, {"github.arbitrary"}, {domain.Tool, domain.GitHubTool, "other"}} {
		if validCallerTools(tools, 3600) {
			t.Fatal("invalid caller tool approved")
		}
	}
}
func TestGitHubCallerDisableRevokesGrants(t *testing.T) {
	s, r, _, _ := githubInvocationFixture(t)
	if err := r.Transact(context.Background(), func(st *domain.State) error { invalidateCaller(st, domain.CallerProfile{AgentID: "agent"}); return nil }); err != nil {
		t.Fatal(err)
	}
	if err := s.Repository.Transact(context.Background(), func(st *domain.State) error {
		if st.GitHubGrants["ghg"].RevokedAt == nil {
			t.Fatal("GitHub grant survived caller disable")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestGitHubMutationOutcomeUnknown(t *testing.T) {
	s, r, auth, stub := githubInvocationFixture(t)
	if e := r.Transact(context.Background(), func(st *domain.State) error {
		g := st.GitHubGrants["ghg"]
		g.ID = "writegrant"
		g.Scope.Actions = []string{"files.update"}
		st.GitHubGrants[g.ID] = g
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	stub.during = func() {
		if e := r.Transact(context.Background(), func(st *domain.State) error {
			g := st.GitHubGrants["writegrant"]
			g.RevokedAt = &st.Now
			st.GitHubGrants[g.ID] = g
			return nil
		}); e != nil {
			t.Error(e)
		}
	}
	req := httptest.NewRequest("POST", "/v1/github/invoke", strings.NewReader(`{"grant_id":"writegrant","action":"files.update","arguments":{"branch":"main","path":"src/a.go","sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","content":"new","message":"change"}}`))
	req.Header.Set("Authorization", auth)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	if w.Code != 503 || !strings.Contains(w.Body.String(), "GITHUB_WRITE_OUTCOME_UNKNOWN") || strings.Contains(w.Body.String(), "bounded fixture") || stub.calls != 1 {
		t.Fatalf("%d %s calls=%d", w.Code, w.Body.String(), stub.calls)
	}
	events := invocationEvents(t, r)
	if len(events) != 2 || events[1].Outcome != "unknown" {
		t.Fatalf("missing unknown outcome audit: %+v", events)
	}
}

func TestGitHubDynamicCallerAdmissionRollback(t *testing.T) {
	s, repo, _ := mcpFixture(t)
	s.Identity = onboardingIdentity{enabled: true}
	pendingMCP(s, "new-client")
	id := candidateID(t, s)
	cookie, csrf := ownerCookie(t, s, "owner")
	w := ownerPost(s, "/v1/callers/pending/"+id+"/approve", `{"label":"GitHub client","tools":["github.operation.v1"],"duration_seconds":3600}`, cookie, csrf)
	if w.Code != 201 {
		t.Fatal(w.Code, w.Body)
	}
	var profile map[string]any
	if e := json.Unmarshal(w.Body.Bytes(), &profile); e != nil {
		t.Fatal(e)
	}
	agentID := profile["agent_id"].(string)
	access := agentAccess{AgentID: agentID, CallerProfileID: profile["id"].(string), TokenExpiresAt: time.Now().Add(time.Hour)}
	stub := &githubStub{}
	s.GitHub = stub
	if e := repo.Transact(context.Background(), func(st *domain.State) error {
		st.GitHubConnections["ghc"] = domain.GitHubConnection{ID: "ghc", OwnerID: "owner", InstallationID: 42, RepositoryID: 99, RepositoryOwner: "org", RepositoryName: "repo", Status: "active", Epoch: 1}
		st.GitHubGrants["ghg"] = domain.GitHubGrant{ID: "ghg", OwnerID: "owner", AgentID: agentID, ConnectionID: "ghc", RepositoryID: 99, Epoch: 1, Scope: domain.GitHubScope{Actions: []string{"files.read"}, Branches: []string{"main"}, Paths: []string{"README.md"}}, NotBefore: st.Now, ExpiresAt: st.Now.Add(time.Hour)}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	invoke := func() (map[string]any, error) {
		return s.githubOperation(context.Background(), access, "ghg", "files.read", json.RawMessage(`{"branch":"main","path":"README.md"}`))
	}
	if _, e := invoke(); e != nil || stub.calls != 1 {
		t.Fatalf("approved dynamic caller: %v calls=%d", e, stub.calls)
	}
	s.Identity = onboardingIdentity{enabled: false}
	if result, e := invoke(); e == nil || result != nil || stub.calls != 1 {
		t.Fatal("disabled dynamic admission dispatched GitHub")
	}
	s.Identity = onboardingIdentity{enabled: true}
	stub.during = func() { s.Identity = onboardingIdentity{enabled: false} }
	if result, e := invoke(); e == nil || result != nil || stub.calls != 2 {
		t.Fatal("GitHub released result after dynamic admission rollback")
	}
}
