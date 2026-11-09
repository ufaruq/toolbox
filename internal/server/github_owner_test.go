package server

import (
	"context"
	"encoding/json"
	"github.com/ufaruq/toolbox/internal/domain"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestGitHubOwnerApprovalLifecycle(t *testing.T) {
	for _, scenario := range []string{"approve", "csrf", "cross-owner", "changed-digest", "disconnect", "deny", "expire", "revoke"} {
		t.Run(scenario, func(t *testing.T) {
			s, repo, auth, stub := githubInvocationFixture(t)
			cookie, csrf := ownerCookie(t, s, "owner")
			stub.repositories = []GitHubRepository{{InstallationID: 42, RepositoryID: 100, Owner: "org", Name: "other"}}
			w := ownerPost(s, "/v1/github/connections", `{"repository_id":100}`, cookie, csrf)
			if w.Code != 201 {
				t.Fatalf("connect: %d %s", w.Code, w.Body.String())
			}
			var conn domain.GitHubConnection
			if err := json.Unmarshal(w.Body.Bytes(), &conn); err != nil {
				t.Fatal(err)
			}
			payload, _ := json.Marshal(map[string]any{"connection_id": conn.ID, "duration_seconds": 3600, "scope": githubScopeInput{Actions: []string{"files.read"}, Branches: []string{"main"}, Paths: []string{"src/"}}})
			r := httptest.NewRequest("POST", "/v1/github/requests", strings.NewReader(string(payload)))
			r.Header.Set("Authorization", auth)
			r.Header.Set("Content-Type", "application/json")
			w = httptest.NewRecorder()
			s.ServeHTTP(w, r)
			if w.Code != 201 {
				t.Fatalf("request: %d %s", w.Code, w.Body.String())
			}
			var q struct {
				RequestID string `json:"request_id"`
			}
			json.Unmarshal(w.Body.Bytes(), &q)
			w = ownerPost(s, "/v1/github/requests/"+q.RequestID+"/review", `{}`, cookie, csrf)
			if w.Code != 200 {
				t.Fatalf("review: %d %s", w.Code, w.Body.String())
			}
			var review struct {
				Digest string `json:"digest"`
			}
			json.Unmarshal(w.Body.Bytes(), &review)
			switch scenario {
			case "csrf":
				csrf = "invalid"
			case "cross-owner":
				if err := repo.Transact(context.Background(), func(st *domain.State) error {
					st.Users["other"] = domain.User{ID: "other", Issuer: "test", Subject: "other", Status: "active"}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				cookie, csrf = ownerCookie(t, s, "other")
			case "changed-digest":
				review.Digest = "changed"
			case "disconnect":
				w = ownerPost(s, "/v1/github/connections/"+conn.ID+"/disconnect", `{}`, cookie, csrf)
				if w.Code != 200 {
					t.Fatal(w.Body.String())
				}
			case "expire":
				// Expire the authenticated owner session without changing immutable request data.
				if err := repo.Transact(context.Background(), func(st *domain.State) error {
					for id, v := range st.Sessions {
						v.ExpiresAt = st.Now.Add(-time.Second)
						st.Sessions[id] = v
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			}
			endpoint := "/approve"
			if scenario == "deny" {
				endpoint = "/deny"
			}
			b, _ := json.Marshal(map[string]string{"digest": review.Digest})
			w = ownerPost(s, "/v1/github/requests/"+q.RequestID+endpoint, string(b), cookie, csrf)
			if scenario != "approve" && scenario != "revoke" && scenario != "deny" {
				if w.Code != 403 {
					t.Fatalf("unsafe approval %d %s", w.Code, w.Body.String())
				}
				return
			}
			if w.Code != 201 && w.Code != 200 {
				t.Fatalf("decision %d %s", w.Code, w.Body.String())
			}
			if scenario == "deny" {
				return
			}
			var decision struct {
				GrantID string `json:"grant_id"`
			}
			json.Unmarshal(w.Body.Bytes(), &decision)
			if decision.GrantID == "" {
				t.Fatal("missing grant")
			}
			if scenario == "revoke" {
				w = ownerPost(s, "/v1/github/grants/"+decision.GrantID+"/revoke", `{}`, cookie, csrf)
				if w.Code != 200 {
					t.Fatal(w.Body.String())
				}
			}
			r = httptest.NewRequest("POST", "/v1/github/invoke", strings.NewReader(`{"grant_id":"`+decision.GrantID+`","action":"files.read","arguments":{"branch":"main","path":"src/a.go"}}`))
			r.Header.Set("Authorization", auth)
			r.Header.Set("Content-Type", "application/json")
			w = httptest.NewRecorder()
			s.ServeHTTP(w, r)
			if scenario == "approve" {
				if w.Code != 200 || stub.calls != 1 {
					t.Fatalf("invoke %d %s", w.Code, w.Body.String())
				}
			} else if w.Code != 403 || stub.calls != 0 {
				t.Fatalf("revoked invoke %d calls=%d", w.Code, stub.calls)
			}
		})
	}
}
func TestGitHubConnectRejectsUninstalledRepository(t *testing.T) {
	s, _, _, stub := githubInvocationFixture(t)
	cookie, csrf := ownerCookie(t, s, "owner")
	stub.repositories = []GitHubRepository{{InstallationID: 42, RepositoryID: 99, Owner: "org", Name: "repo"}}
	w := ownerPost(s, "/v1/github/connections", `{"repository_id":100}`, cookie, csrf)
	if w.Code != 403 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
}

func TestGitHubBrowserFlow(t *testing.T) {
	if os.Getenv("TOOLBOX_TEST_WORKSPACE_BROWSER") != "1" {
		t.Skip("requires pinned Playwright and Chromium")
	}
	s, repo, auth, stub := githubInvocationFixture(t)
	stub.repositories = []GitHubRepository{{InstallationID: 42, RepositoryID: 100, Owner: "org", Name: "browser-repo"}}
	cookie, csrf := ownerCookie(t, s, "owner")
	ts := httptest.NewServer(s)
	defer ts.Close()
	s.Origin = ts.URL
	// Use a distinctive untrusted name to prove the UI renders text, not HTML.
	if e := repo.Transact(context.Background(), func(st *domain.State) error {
		a := st.Agents["agent"]
		a.Name = "<img src=x onerror=alert(1)>"
		st.Agents[a.ID] = a
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	_, source, _, _ := runtime.Caller(0)
	command := exec.CommandContext(ctx, "python3", filepath.Join(filepath.Dir(source), "../../tests/browser/github_e2e.py"))
	command.Env = append(os.Environ(), "TOOLBOX_GITHUB_TEST_ORIGIN="+ts.URL, "TOOLBOX_GITHUB_TEST_COOKIE="+cookie.Value, "TOOLBOX_GITHUB_TEST_CSRF="+csrf, "TOOLBOX_GITHUB_TEST_AGENT="+auth)
	if out, e := command.CombinedOutput(); e != nil {
		t.Fatalf("GitHub browser flow: %s", out)
	} else {
		t.Log(strings.TrimSpace(string(out)))
	}
}
