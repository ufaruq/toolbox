package server

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/ufaruq/toolbox/internal/domain"
	"github.com/ufaruq/toolbox/internal/security"
	policy "github.com/ufaruq/toolbox/internal/servicepolicy/github"
)

func (s *Server) githubRoutes() {
	for path, asset := range map[string]string{"/github": "github.html", "/github/approve/{id}": "github.html", "/github.js": "github.js", "/github.css": "workspace.css"} {
		s.mux.HandleFunc("GET "+path, func(w http.ResponseWriter, r *http.Request) {
			contentType := "text/html; charset=utf-8"
			if asset == "github.js" {
				contentType = "text/javascript; charset=utf-8"
			}
			if asset == "workspace.css" {
				contentType = "text/css; charset=utf-8"
			}
			w.Header().Set("Content-Type", contentType)
			b, _ := web.ReadFile("web/" + asset)
			_, _ = w.Write(b)
		})
	}
	s.mux.HandleFunc("POST /v1/github/invoke", s.githubInvoke)
	s.mux.HandleFunc("GET /v1/github/repositories", s.githubRepositories)
	s.mux.HandleFunc("GET /v1/github/state", s.githubState)
	s.mux.HandleFunc("POST /v1/github/connections", s.githubConnect)
	s.mux.HandleFunc("POST /v1/github/connections/{id}/disconnect", s.githubDisconnect)
	s.mux.HandleFunc("POST /v1/github/requests", s.githubRequest)
	s.mux.HandleFunc("GET /v1/github/requests/{id}", s.githubPoll)
	s.mux.HandleFunc("POST /v1/github/requests/{id}/review", s.githubReview)
	s.mux.HandleFunc("POST /v1/github/requests/{id}/approve", s.githubDecision)
	s.mux.HandleFunc("POST /v1/github/requests/{id}/deny", s.githubDecision)
	s.mux.HandleFunc("POST /v1/github/grants/{id}/revoke", s.githubRevoke)
}
func (s *Server) githubOwner(w http.ResponseWriter, r *http.Request, mutate bool) (domain.Session, bool) {
	if s.GitHub == nil {
		fail(w, 503, "FEATURE_DISABLED")
		return domain.Session{}, false
	}
	return s.requireOwner(w, r, mutate)
}
func (s *Server) githubSession(st *domain.State, owner domain.Session) error {
	current := st.Sessions[owner.ID]
	if current.UserID != owner.UserID || st.Users[owner.UserID].Status != "active" || !st.Now.Before(current.ExpiresAt) || s.OwnerLogin != nil && !s.OwnerLogin.SessionBound(st, owner.ID) {
		return domain.ErrDenied
	}
	return nil
}
func (s *Server) githubRepositories(w http.ResponseWriter, r *http.Request) {
	owner, ok := s.githubOwner(w, r, false)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	repos, e := s.GitHub.Repositories(ctx, owner.UserID)
	if e == nil {
		e = s.Repository.Transact(ctx, func(st *domain.State) error { return s.githubSession(st, owner) })
	}
	if e != nil || len(repos) > 1000 {
		fail(w, 503, "GITHUB_UNAVAILABLE")
		return
	}
	jsonOut(w, 200, repos)
}
func (s *Server) githubConnect(w http.ResponseWriter, r *http.Request) {
	owner, ok := s.githubOwner(w, r, true)
	if !ok {
		return
	}
	var in struct {
		RepositoryID int64 `json:"repository_id"`
	}
	if !body(w, r, &in) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	repos, e := s.GitHub.Repositories(ctx, owner.UserID)
	if e != nil || len(repos) > 1000 {
		fail(w, 503, "GITHUB_UNAVAILABLE")
		return
	}
	var selected GitHubRepository
	for _, v := range repos {
		if v.RepositoryID == in.RepositoryID {
			selected = v
		}
	}
	if selected.RepositoryID <= 0 || selected.InstallationID <= 0 {
		fail(w, 403, "NOT_AUTHORIZED")
		return
	}
	c := domain.GitHubConnection{ID: security.ID(), OwnerID: owner.UserID, InstallationID: selected.InstallationID, RepositoryID: selected.RepositoryID, RepositoryOwner: selected.Owner, RepositoryName: selected.Name, Epoch: 1, Status: "active"}
	e = s.Repository.Transact(ctx, func(st *domain.State) error {
		if err := s.githubSession(st, owner); err != nil {
			return err
		}
		for _, old := range st.GitHubConnections {
			if old.OwnerID == c.OwnerID && old.RepositoryID == c.RepositoryID && old.Status == "active" {
				return domain.ErrDenied
			}
		}
		st.GitHubConnections[c.ID] = c
		addAudit(st, "user", owner.UserID, owner.UserID, "github.connected", "", c.ID, "", "allowed", "", 0)
		return nil
	})
	if e != nil {
		fail(w, 403, "NOT_AUTHORIZED")
		return
	}
	jsonOut(w, 201, c)
}
func (s *Server) githubState(w http.ResponseWriter, r *http.Request) {
	owner, ok := s.githubOwner(w, r, false)
	if !ok {
		return
	}
	cs := []domain.GitHubConnection{}
	qs := []domain.GitHubRequest{}
	gs := []domain.GitHubGrant{}
	e := s.Repository.Transact(r.Context(), func(st *domain.State) error {
		if err := s.githubSession(st, owner); err != nil {
			return err
		}
		for _, c := range st.GitHubConnections {
			if c.OwnerID == owner.UserID {
				cs = append(cs, c)
			}
		}
		for _, q := range st.GitHubRequests {
			if q.OwnerID == owner.UserID {
				qs = append(qs, q)
			}
		}
		for _, g := range st.GitHubGrants {
			if g.OwnerID == owner.UserID {
				gs = append(gs, g)
			}
		}
		return nil
	})
	if e != nil {
		fail(w, 503, "DEPENDENCY_UNAVAILABLE")
		return
	}
	sort.Slice(cs, func(i, j int) bool { return cs[i].ID < cs[j].ID })
	sort.Slice(qs, func(i, j int) bool { return qs[i].ID < qs[j].ID })
	sort.Slice(gs, func(i, j int) bool { return gs[i].ID < gs[j].ID })
	jsonOut(w, 200, map[string]any{"connections": cs, "requests": qs, "grants": gs})
}
func (s *Server) githubDisconnect(w http.ResponseWriter, r *http.Request) {
	owner, ok := s.githubOwner(w, r, true)
	if !ok {
		return
	}
	var in struct{}
	if !body(w, r, &in) {
		return
	}
	e := s.Repository.Transact(r.Context(), func(st *domain.State) error {
		if err := s.githubSession(st, owner); err != nil {
			return err
		}
		c, ok := st.GitHubConnections[r.PathValue("id")]
		if !ok || c.OwnerID != owner.UserID {
			return domain.ErrDenied
		}
		if c.Status == "disconnected" {
			return nil
		}
		c.Status = "disconnected"
		c.Epoch++
		st.GitHubConnections[c.ID] = c
		for id, g := range st.GitHubGrants {
			if g.ConnectionID == c.ID && g.RevokedAt == nil {
				now := st.Now
				g.RevokedAt = &now
				st.GitHubGrants[id] = g
			}
		}
		for id, q := range st.GitHubRequests {
			if q.ConnectionID == c.ID && q.Status == "pending" {
				q.Status = "denied"
				st.GitHubRequests[id] = q
			}
		}
		addAudit(st, "user", owner.UserID, owner.UserID, "github.disconnected", "", c.ID, "", "allowed", "", 0)
		return nil
	})
	if e != nil {
		fail(w, 403, "NOT_AUTHORIZED")
		return
	}
	jsonOut(w, 200, map[string]string{"status": "disconnected"})
}

type githubScopeInput struct {
	Actions                  []string `json:"actions"`
	Branches                 []string `json:"branches,omitempty"`
	BaseBranches             []string `json:"base_branches,omitempty"`
	Paths                    []string `json:"paths,omitempty"`
	PullRequests             []int64  `json:"pull_requests,omitempty"`
	ExpectedHead             string   `json:"expected_head,omitempty"`
	AllowUnconditionalWrites bool     `json:"allow_unconditional_writes,omitempty"`
}

type githubRequestInput struct {
	ConnectionID    string           `json:"connection_id"`
	Scope           githubScopeInput `json:"scope"`
	DurationSeconds int64            `json:"duration_seconds"`
}

func githubDigest(q domain.GitHubRequest) string {
	q.Digest = ""
	q.Status = ""
	q.GrantID = ""
	b, _ := json.Marshal(q)
	return security.Hash(string(b))
}
func (s *Server) githubCreateRequest(ctx context.Context, access agentAccess, in githubRequestInput) (map[string]any, error) {
	if s.GitHub == nil {
		return nil, opError(503, "FEATURE_DISABLED")
	}
	if in.DurationSeconds < 1 || in.DurationSeconds > 7*24*3600 {
		return nil, opError(400, "INVALID_SCHEMA")
	}
	var q domain.GitHubRequest
	e := s.Repository.Transact(ctx, func(st *domain.State) error {
		if err := authorizeAgent(st, access, domain.GitHubTool); err != nil {
			return err
		}
		a := st.Agents[access.AgentID]
		c, ok := st.GitHubConnections[in.ConnectionID]
		if !ok || c.Status != "active" || c.OwnerID != a.OwnerID {
			return domain.ErrDenied
		}
		expiry := st.Now.Add(time.Duration(in.DurationSeconds) * time.Second)
		if p, ok := profileForAgent(st, a.ID); ok && expiry.After(p.ExpiresAt) {
			return domain.ErrDenied
		}
		g := domain.GitHubGrant{OwnerID: a.OwnerID, AgentID: a.ID, ConnectionID: c.ID, RepositoryID: c.RepositoryID, Epoch: c.Epoch, Scope: domain.GitHubScope(in.Scope), ExpiresAt: expiry}
		if err := policy.ValidateGrant(policyGrant(g, c)); err != nil {
			return err
		}
		count := 0
		for _, old := range st.GitHubRequests {
			if old.AgentID == a.ID && old.Status == "pending" && st.Now.Before(old.ReviewExpiresAt) {
				count++
			}
		}
		if count >= 32 {
			return domain.ErrDenied
		}
		q = domain.GitHubRequest{ID: security.ID(), OwnerID: a.OwnerID, AgentID: a.ID, ConnectionID: c.ID, RepositoryID: c.RepositoryID, Epoch: c.Epoch, Scope: domain.GitHubScope(in.Scope), ExpiresAt: expiry, ReviewExpiresAt: st.Now.Add(15 * time.Minute), Status: "pending"}
		q.Digest = githubDigest(q)
		st.GitHubRequests[q.ID] = q
		addAudit(st, "agent", a.ID, a.OwnerID, "github.requested", "", c.ID, "", "allowed", "", 0)
		return nil
	})
	if e != nil {
		return nil, opError(403, "NOT_AUTHORIZED")
	}
	return map[string]any{"request_id": q.ID, "status": q.Status, "approval_url": s.Origin + "/github/approve/" + q.ID}, nil
}
func (s *Server) githubRequest(w http.ResponseWriter, r *http.Request) {
	a, cred, ok := s.requireAgent(w, r)
	if !ok {
		return
	}
	var in githubRequestInput
	if !body(w, r, &in) {
		return
	}
	v, e := s.githubCreateRequest(r.Context(), agentAccess{AgentID: a.ID, CredentialID: cred}, in)
	if e != nil {
		operationFailure(w, e)
		return
	}
	jsonOut(w, 201, v)
}
func (s *Server) githubPollRequest(ctx context.Context, access agentAccess, id string) (map[string]any, error) {
	var q domain.GitHubRequest
	e := s.Repository.Transact(ctx, func(st *domain.State) error {
		if err := authorizeAgent(st, access, domain.GitHubTool); err != nil {
			return err
		}
		var ok bool
		q, ok = st.GitHubRequests[id]
		if !ok || q.AgentID != access.AgentID {
			return domain.ErrDenied
		}
		if q.Status == "pending" && (!st.Now.Before(q.ReviewExpiresAt) || !st.Now.Before(q.ExpiresAt)) {
			q.Status = "expired"
			st.GitHubRequests[id] = q
		}
		return nil
	})
	if e != nil {
		return nil, opError(403, "NOT_AUTHORIZED")
	}
	return map[string]any{"request_id": q.ID, "status": q.Status, "grant_id": q.GrantID}, nil
}
func (s *Server) githubPoll(w http.ResponseWriter, r *http.Request) {
	a, cred, ok := s.requireAgent(w, r)
	if !ok {
		return
	}
	v, e := s.githubPollRequest(r.Context(), agentAccess{AgentID: a.ID, CredentialID: cred}, r.PathValue("id"))
	if e != nil {
		operationFailure(w, e)
		return
	}
	jsonOut(w, 200, v)
}
func (s *Server) githubPending(st *domain.State, owner domain.Session, id string) (domain.GitHubRequest, domain.GitHubConnection, error) {
	q, ok := st.GitHubRequests[id]
	c := st.GitHubConnections[q.ConnectionID]
	a := st.Agents[q.AgentID]
	if s.githubSession(st, owner) != nil || !ok || q.OwnerID != owner.UserID || q.Status != "pending" || q.Digest != githubDigest(q) || !st.Now.Before(q.ExpiresAt) || !st.Now.Before(q.ReviewExpiresAt) || c.Status != "active" || c.OwnerID != owner.UserID || q.Epoch != c.Epoch || q.RepositoryID != c.RepositoryID || a.OwnerID != owner.UserID || a.Status != "active" {
		return q, c, domain.ErrDenied
	}
	if p, ok := profileForAgent(st, a.ID); ok && (!profileActive(st, p, domain.GitHubTool) || q.ExpiresAt.After(p.ExpiresAt)) {
		return q, c, domain.ErrDenied
	}
	return q, c, nil
}
func (s *Server) githubReview(w http.ResponseWriter, r *http.Request) {
	owner, ok := s.githubOwner(w, r, true)
	if !ok {
		return
	}
	var in struct{}
	if !body(w, r, &in) {
		return
	}
	var q domain.GitHubRequest
	var c domain.GitHubConnection
	var agentName string
	e := s.Repository.Transact(r.Context(), func(st *domain.State) error {
		var e error
		q, c, e = s.githubPending(st, owner, r.PathValue("id"))
		agentName = st.Agents[q.AgentID].Name
		return e
	})
	if e != nil {
		fail(w, 403, "NOT_AUTHORIZED")
		return
	}
	jsonOut(w, 200, map[string]any{"request": q, "repository": c.RepositoryOwner + "/" + c.RepositoryName, "repository_id": c.RepositoryID, "installation_id": c.InstallationID, "agent_name": agentName, "digest": q.Digest, "notice": "Installation access is not an agent grant. Approve only the actions, paths, branches and revisions shown. Provider branch rules still apply."})
}
func (s *Server) githubDecision(w http.ResponseWriter, r *http.Request) {
	owner, ok := s.githubOwner(w, r, true)
	if !ok {
		return
	}
	var in struct {
		Digest string `json:"digest"`
	}
	if !body(w, r, &in) {
		return
	}
	decision := "approved"
	if strings.HasSuffix(r.URL.Path, "/deny") {
		decision = "denied"
	}
	var q domain.GitHubRequest
	e := s.Repository.Transact(r.Context(), func(st *domain.State) error {
		var c domain.GitHubConnection
		var e error
		q, c, e = s.githubPending(st, owner, r.PathValue("id"))
		if e != nil || !security.Equal(q.Digest, in.Digest) {
			return domain.ErrDenied
		}
		q.Status = decision
		if decision == "approved" {
			g := domain.GitHubGrant{ID: security.ID(), OwnerID: q.OwnerID, AgentID: q.AgentID, ConnectionID: q.ConnectionID, RepositoryID: q.RepositoryID, Epoch: q.Epoch, Scope: q.Scope, NotBefore: st.Now, ExpiresAt: q.ExpiresAt}
			if e := policy.ValidateGrant(policyGrant(g, c)); e != nil {
				return e
			}
			st.GitHubGrants[g.ID] = g
			q.GrantID = g.ID
		}
		st.GitHubRequests[q.ID] = q
		addAudit(st, "user", owner.UserID, owner.UserID, "github."+decision, q.GrantID, q.ConnectionID, "", decision, "", 0)
		return nil
	})
	if e != nil {
		fail(w, 403, "APPROVAL_CHANGED_OR_EXPIRED")
		return
	}
	jsonOut(w, 201, map[string]string{"status": q.Status, "grant_id": q.GrantID})
}
func (s *Server) githubRevoke(w http.ResponseWriter, r *http.Request) {
	owner, ok := s.githubOwner(w, r, true)
	if !ok {
		return
	}
	var in struct{}
	if !body(w, r, &in) {
		return
	}
	e := s.Repository.Transact(r.Context(), func(st *domain.State) error {
		if e := s.githubSession(st, owner); e != nil {
			return e
		}
		g, ok := st.GitHubGrants[r.PathValue("id")]
		if !ok || g.OwnerID != owner.UserID {
			return domain.ErrDenied
		}
		if g.RevokedAt == nil {
			now := st.Now
			g.RevokedAt = &now
			st.GitHubGrants[g.ID] = g
		}
		addAudit(st, "user", owner.UserID, owner.UserID, "github.revoked", g.ID, g.ConnectionID, "", "allowed", "", 0)
		return nil
	})
	if e != nil {
		fail(w, 403, "NOT_AUTHORIZED")
		return
	}
	jsonOut(w, 200, map[string]string{"status": "revoked"})
}
