package github

import (
	"encoding/json"
	"testing"
	"time"
)

func approved() Grant {
	return Grant{OwnerID: "owner-a", AgentID: "agent-a", ConnectionID: "connection-a", RepositoryID: 99, Owner: "org", Repository: "repo", Epoch: 1, AllowUnconditionalWrites: true, Actions: []string{"files.read", "files.write", "branches.create", "prs.create"}, Branches: []string{"agent/task"}, Paths: []string{"src", "src/"}, ExpiresAt: time.Now().Add(time.Hour)}
}
func TestPolicyConstructsBoundedCall(t *testing.T) {
	g := approved()
	c, e := Build(g, "files.write", json.RawMessage(`{"branch":"agent/task","message":"fix","files":[{"path":"src/main.go","content":"package main"}]}`), time.Now())
	if e != nil || c.Tool != "push_files" {
		t.Fatalf("call rejected: %v", e)
	}
	var args map[string]any
	json.Unmarshal(c.Arguments, &args)
	if args["owner"] != "org" || args["repo"] != "repo" || args["branch"] != "agent/task" {
		t.Fatal("missing trusted scope")
	}
}
func TestPolicyRejectsScopeEscape(t *testing.T) {
	for name, raw := range map[string]string{
		"main branch":    `{"branch":"main","message":"x","files":[{"path":"src/a","content":"x"}]}`,
		"path escape":    `{"branch":"agent/task","message":"x","files":[{"path":"src/../.github/workflows/build.yml","content":"x"}]}`,
		"outside prefix": `{"branch":"agent/task","message":"x","files":[{"path":"src-other/a","content":"x"}]}`,
		"injected repo":  `{"repo":"other","branch":"agent/task","message":"x","files":[{"path":"src/a","content":"x"}]}`,
		"duplicate path": `{"branch":"agent/task","message":"x","files":[{"path":"src/a","content":"x"},{"path":"src/a","content":"y"}]}`,
		"duplicate key":  `{"branch":"main","branch":"agent/task","message":"x","files":[{"path":"src/a","content":"x"}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, e := Build(approved(), "files.write", json.RawMessage(raw), time.Now()); e == nil {
				t.Fatal("scope escape accepted")
			}
		})
	}
}
func TestPolicyRejectsExpiredRevokedAndUnknownActions(t *testing.T) {
	for _, action := range []string{"unknown", "prs.merge", "repositories.delete"} {
		if _, e := Build(approved(), action, json.RawMessage(`{}`), time.Now()); e == nil {
			t.Fatal("unauthorized action accepted")
		}
	}
	g := approved()
	g.ExpiresAt = time.Now().Add(-time.Second)
	if _, e := Build(g, "files.read", json.RawMessage(`{"branch":"agent/task","path":"src/a"}`), time.Now()); e == nil {
		t.Fatal("expired grant accepted")
	}
	g = approved()
	g.Revoked = true
	if _, e := Build(g, "files.read", json.RawMessage(`{"branch":"agent/task","path":"src/a"}`), time.Now()); e == nil {
		t.Fatal("revoked grant accepted")
	}
}
