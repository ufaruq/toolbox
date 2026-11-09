package server

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/ufaruq/toolbox/internal/domain"
	"github.com/ufaruq/toolbox/internal/security"
	policy "github.com/ufaruq/toolbox/internal/servicepolicy/github"
	"net/http"
	"strconv"
	"time"
)

var ErrGitHubOutcomeUnknown = errors.New("GITHUB_WRITE_OUTCOME_UNKNOWN")

type GitHubRepository struct {
	InstallationID, RepositoryID int64
	Owner, Name                  string
}

// GitHubProvider only exposes repositories independently bound to the given
// owner by trusted operator configuration or verified provider onboarding.
type GitHubProvider interface {
	Repositories(context.Context, string) ([]GitHubRepository, error)
	Execute(context.Context, domain.GitHubConnection, domain.GitHubGrant, string, json.RawMessage, func(context.Context) error) (any, error)
}

// GitHubPolicyGrant translates immutable application scope for the execution adapter.
func GitHubPolicyGrant(g domain.GitHubGrant, c domain.GitHubConnection) policy.Grant {
	return policy.Grant{OwnerID: g.OwnerID, AgentID: g.AgentID, ConnectionID: g.ConnectionID, RepositoryID: g.RepositoryID, Epoch: g.Epoch, Owner: c.RepositoryOwner, Repository: c.RepositoryName, Actions: g.Scope.Actions, Branches: g.Scope.Branches, Paths: g.Scope.Paths, BaseBranches: g.Scope.BaseBranches, PullRequests: g.Scope.PullRequests, ExpectedHead: g.Scope.ExpectedHead, AllowUnconditionalWrites: g.Scope.AllowUnconditionalWrites, ExpiresAt: g.ExpiresAt, Revoked: g.RevokedAt != nil}
}
func (s *Server) githubAccess(st *domain.State, a agentAccess, id string) (domain.GitHubGrant, domain.GitHubConnection, error) {
	g, ok := st.GitHubGrants[id]
	c, cok := st.GitHubConnections[g.ConnectionID]
	if !ok || !cok || s.authorizeAgent(st, a, domain.GitHubTool) != nil || g.AgentID != a.AgentID || g.OwnerID != st.Agents[a.AgentID].OwnerID || c.OwnerID != g.OwnerID || c.Status != "active" || g.Epoch != c.Epoch || g.RepositoryID != c.RepositoryID || g.RevokedAt != nil || st.Now.Before(g.NotBefore) || !st.Now.Before(g.ExpiresAt) {
		return g, c, domain.ErrDenied
	}
	return g, c, nil
}
func (s *Server) githubInvoke(w http.ResponseWriter, r *http.Request) {
	if s.GitHub == nil {
		fail(w, 503, "FEATURE_DISABLED")
		return
	}
	a, cred, ok := s.requireAgent(w, r)
	if !ok {
		return
	}
	var in struct {
		GrantID   string          `json:"grant_id"`
		Action    string          `json:"action"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if !body(w, r, &in) {
		return
	}
	result, e := s.githubOperation(r.Context(), agentAccess{AgentID: a.ID, CredentialID: cred}, in.GrantID, in.Action, in.Arguments)
	if e != nil {
		operationFailure(w, e)
		return
	}
	jsonOut(w, 200, result)
}
func (s *Server) githubOperation(ctx context.Context, a agentAccess, id, action string, args json.RawMessage) (map[string]any, error) {
	if s.GitHub == nil {
		return nil, opError(503, "FEATURE_DISABLED")
	}
	if !s.allowed("github:"+a.AgentID, 30) {
		return nil, opError(429, "RATE_LIMITED")
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	invocation := security.ID()
	var g domain.GitHubGrant
	var c domain.GitHubConnection
	var denied bool
	e := s.Repository.Transact(ctx, func(st *domain.State) error {
		var err error
		g, c, err = s.githubAccess(st, a, id)
		if err == nil {
			_, err = policy.Build(GitHubPolicyGrant(g, c), action, args, st.Now)
		}
		if err != nil {
			denied = true
			addAudit(st, "agent", a.AgentID, st.Agents[a.AgentID].OwnerID, "tool.invocation", "", "", "", "denied", invocation, 0)
			return nil
		}
		addAudit(st, "agent", a.AgentID, g.OwnerID, "tool.invocation", g.ID, c.ID, strconv.FormatInt(g.RepositoryID, 10), "started", invocation, 0)
		return nil
	})
	if e != nil {
		return nil, opError(503, "DEPENDENCY_UNAVAILABLE")
	}
	if denied {
		return nil, opError(403, "NOT_AUTHORIZED")
	}
	finishFailure := func(code int, label string) error {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer stop()
		if err := s.Repository.Transact(cleanup, func(st *domain.State) error {
			outcome := "failed"
			if label == "GITHUB_WRITE_OUTCOME_UNKNOWN" {
				outcome = "unknown"
			}
			addAudit(st, "agent", a.AgentID, g.OwnerID, "tool.invocation", g.ID, c.ID, strconv.FormatInt(g.RepositoryID, 10), outcome, invocation, 0)
			return nil
		}); err != nil {
			return opError(503, "DEPENDENCY_UNAVAILABLE")
		}
		return opError(code, label)
	}
	check := func(ctx context.Context) error {
		return s.Repository.Transact(ctx, func(st *domain.State) error {
			current, conn, e := s.githubAccess(st, a, id)
			if e != nil {
				return e
			}
			_, e = policy.Build(GitHubPolicyGrant(current, conn), action, args, st.Now)
			return e
		})
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	case <-ctx.Done():
		return nil, finishFailure(503, "INVOCATION_TIMEOUT")
	}
	if e = check(ctx); e != nil {
		return nil, finishFailure(403, "NOT_AUTHORIZED")
	}
	result, e := s.GitHub.Execute(ctx, c, g, action, args, check)
	if e != nil {
		if errors.Is(e, ErrGitHubOutcomeUnknown) {
			return nil, finishFailure(503, "GITHUB_WRITE_OUTCOME_UNKNOWN")
		}
		if errors.Is(e, domain.ErrDenied) || errors.Is(e, policy.ErrDenied) {
			return nil, finishFailure(403, "NOT_AUTHORIZED")
		}
		return nil, finishFailure(503, "GITHUB_OPERATION_FAILED")
	}
	encoded, e := json.Marshal(result)
	if e != nil || len(encoded) > domain.MaxBytes {
		return nil, finishFailure(503, "INVALID_PROVIDER_RESULT")
	}
	e = s.Repository.Transact(ctx, func(st *domain.State) error {
		if _, _, e := s.githubAccess(st, a, id); e != nil {
			return e
		}
		addAudit(st, "agent", a.AgentID, g.OwnerID, "tool.invocation", g.ID, c.ID, strconv.FormatInt(g.RepositoryID, 10), "succeeded", invocation, len(encoded))
		return nil
	})
	if e != nil {
		if action != "files.read" && action != "prs.read" && action != "issues.read" {
			return nil, finishFailure(503, "GITHUB_WRITE_OUTCOME_UNKNOWN")
		}
		return nil, finishFailure(403, "RESULT_NOT_AUTHORIZED")
	}
	return map[string]any{"invocation_id": invocation, "action": action, "repository_id": g.RepositoryID, "result": result, "untrusted_content": true}, nil
}
