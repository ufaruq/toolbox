package server

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ufaruq/toolbox/internal/domain"
	"github.com/ufaruq/toolbox/internal/security"
)

func (s *Server) session(w http.ResponseWriter, r *http.Request) {
	v, ok := s.requireOwner(w, r, false)
	if !ok {
		return
	}
	c, _ := r.Cookie(s.sessionCookieName())
	jsonOut(w, 200, map[string]any{"user_id": v.UserID, "csrf_token": security.KeyedHash(s.sessionPepper(), c.Value), "fixture": s.Fixture, "owner_only": s.OwnerOnly})
}
func (s *Server) fixtureLogin(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Origin") != s.Origin {
		fail(w, 403, "NOT_AUTHORIZED")
		return
	}
	raw := security.Random()
	id := security.Hash(raw)
	csrf := security.KeyedHash(s.Pepper, raw)
	e := s.Repository.Transact(r.Context(), func(st *domain.State) error {
		const uid = "11111111-1111-4111-8111-111111111111"
		st.Users[uid] = domain.User{ID: uid, Issuer: "fixture://local", Subject: "local-owner", Status: "active"}
		st.Sessions[id] = domain.Session{ID: id, UserID: uid, CSRFHash: security.Hash(csrf), ExpiresAt: st.Now.Add(8 * time.Hour)}
		return nil
	})
	if e != nil {
		fail(w, 503, "DEPENDENCY_UNAVAILABLE")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: s.sessionCookieName(), Value: raw, Path: "/", HttpOnly: true, Secure: !s.Fixture, SameSite: http.SameSiteLaxMode, MaxAge: 8 * 3600})
	jsonOut(w, 200, map[string]string{"csrf_token": csrf})
}
func (s *Server) createAgent(w http.ResponseWriter, r *http.Request) {
	owner, ok := s.requireOwner(w, r, true)
	if !ok {
		return
	}
	var in struct {
		Name string `json:"name"`
	}
	if !body(w, r, &in) {
		return
	}
	if len(in.Name) < 1 || len(in.Name) > 80 || strings.ContainsAny(in.Name, "\r\n\x00") {
		fail(w, 400, "INVALID_SCHEMA")
		return
	}
	id, raw, hash := security.NewCredential(s.Pepper)
	a := domain.Agent{ID: security.ID(), OwnerID: owner.UserID, Name: in.Name, Status: "active"}
	e := s.Repository.Transact(r.Context(), func(st *domain.State) error {
		st.Agents[a.ID] = a
		st.Credentials[id] = domain.Credential{ID: id, AgentID: a.ID, Hash: hash, Status: "active", ExpiresAt: st.Now.Add(30 * 24 * time.Hour)}
		addAudit(st, "user", owner.UserID, owner.UserID, "agent.created", "", "", "", "allowed", "", 0)
		return nil
	})
	if e != nil {
		fail(w, 503, "DEPENDENCY_UNAVAILABLE")
		return
	}
	jsonOut(w, 201, map[string]string{"agent_id": a.ID, "credential_id": id, "credential": raw})
}
func (s *Server) rotateCredential(w http.ResponseWriter, r *http.Request) {
	owner, ok := s.requireOwner(w, r, true)
	if !ok {
		return
	}
	var in struct{}
	if !body(w, r, &in) {
		return
	}
	id, raw, hash := security.NewCredential(s.Pepper)
	e := s.Repository.Transact(r.Context(), func(st *domain.State) error {
		a := st.Agents[r.PathValue("id")]
		if a.OwnerID != owner.UserID || a.Status != "active" {
			return domain.ErrDenied
		}
		n := 0
		for _, c := range st.Credentials {
			if c.AgentID == a.ID && c.Status == "active" && st.Now.Before(c.ExpiresAt) {
				n++
			}
		}
		if n >= 2 {
			return domain.ErrDenied
		}
		st.Credentials[id] = domain.Credential{ID: id, AgentID: a.ID, Hash: hash, Status: "active", ExpiresAt: st.Now.Add(30 * 24 * time.Hour)}
		addAudit(st, "user", owner.UserID, owner.UserID, "credential.created", "", "", "", "allowed", "", 0)
		return nil
	})
	if e != nil {
		fail(w, 403, "NOT_AUTHORIZED")
		return
	}
	jsonOut(w, 201, map[string]string{"credential_id": id, "credential": raw})
}
func (s *Server) revokeCredential(w http.ResponseWriter, r *http.Request) {
	owner, ok := s.requireOwner(w, r, true)
	if !ok {
		return
	}
	var in struct{}
	if !body(w, r, &in) {
		return
	}
	e := s.Repository.Transact(r.Context(), func(st *domain.State) error {
		c, ok := st.Credentials[r.PathValue("id")]
		if !ok || st.Agents[c.AgentID].OwnerID != owner.UserID {
			return domain.ErrDenied
		}
		c.Status = "revoked"
		st.Credentials[c.ID] = c
		addAudit(st, "user", owner.UserID, owner.UserID, "credential.revoked", "", "", "", "allowed", "", 0)
		return nil
	})
	if e != nil {
		fail(w, 403, "NOT_AUTHORIZED")
		return
	}
	jsonOut(w, 200, map[string]string{"status": "revoked"})
}
func (s *Server) startConnection(w http.ResponseWriter, r *http.Request) {
	owner, ok := s.requireOwner(w, r, true)
	if !ok {
		return
	}
	var in struct{}
	if !body(w, r, &in) {
		return
	}
	u, e := s.integration.Start(r.Context(), owner.UserID, owner.ID)
	if e != nil {
		fail(w, 503, "CONNECTION_SETUP_FAILED")
		return
	}
	if s.Fixture {
		u = s.Origin + "/fixture/authorize?request=" + url.QueryEscape(u)
	}
	jsonOut(w, 200, map[string]string{"authorization_url": u})
}
func (s *Server) fixtureAuthorize(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireOwner(w, r, false); !ok {
		return
	}
	if len(r.URL.Query()) != 1 || len(r.URL.Query()["request"]) != 1 {
		fail(w, 400, "INVALID_QUERY")
		return
	}
	u, e := s.integration.FixtureAuthorize(r.Context(), r.URL.Query().Get("request"))
	if e != nil {
		fail(w, 400, "FIXTURE_AUTH_FAILED")
		return
	}
	target, e := url.Parse(u)
	origin, _ := url.Parse(s.Origin)
	if e != nil || target.Scheme != origin.Scheme || target.Host != origin.Host || target.Path != "/oauth/callback" {
		fail(w, 400, "INVALID_CALLBACK")
		return
	}
	http.Redirect(w, r, u, 303)
}
func (s *Server) completeConnection(w http.ResponseWriter, r *http.Request) {
	if s.WorkspaceLocal {
		s.workspaceCallback(w, r)
		return
	}
	owner, ok := s.requireOwner(w, r, false)
	if !ok {
		return
	}
	q := r.URL.Query()
	if len(q) != 2 || len(q["state"]) != 1 || len(q["code"]) != 1 || len(q.Get("code")) > 4096 {
		fail(w, 400, "INVALID_CALLBACK")
		return
	}
	_, e := s.integration.Complete(r.Context(), owner.UserID, owner.ID, q.Get("state"), q.Get("code"))
	if e != nil {
		fail(w, 400, "OAUTH_CALLBACK_REJECTED")
		return
	}
	http.Redirect(w, r, "/", 303)
}
func (s *Server) connections(w http.ResponseWriter, r *http.Request) {
	owner, ok := s.requireOwner(w, r, false)
	if !ok {
		return
	}
	items := []map[string]any{}
	e := s.Repository.Transact(r.Context(), func(st *domain.State) error {
		for _, c := range st.Connections {
			if c.OwnerID == owner.UserID {
				items = append(items, map[string]any{"id": c.ID, "provider": c.Provider, "account_subject": c.Subject, "status": c.Status, "epoch": c.Epoch})
			}
		}
		return nil
	})
	if e != nil {
		fail(w, 503, "DEPENDENCY_UNAVAILABLE")
		return
	}
	jsonOut(w, 200, items)
}
func (s *Server) disconnect(w http.ResponseWriter, r *http.Request) {
	owner, ok := s.requireOwner(w, r, true)
	if !ok {
		return
	}
	var in struct{}
	if !body(w, r, &in) {
		return
	}
	e := s.Repository.Transact(r.Context(), func(st *domain.State) error {
		c, ok := st.Connections[r.PathValue("id")]
		if !ok || c.OwnerID != owner.UserID {
			return domain.ErrDenied
		}
		if c.Status == "disconnected" || c.Status == "disconnecting" {
			return nil
		}
		c.Status = "disconnecting"
		c.Epoch++
		st.Connections[c.ID] = c
		for id, g := range st.Grants {
			if g.ConnectionID == c.ID && g.RevokedAt == nil {
				now := st.Now
				g.RevokedAt = &now
				st.Grants[id] = g
			}
		}
		job := domain.Cleanup{ID: security.ID(), ConnectionID: c.ID, OwnerID: owner.UserID, Epoch: c.Epoch, Status: "pending"}
		st.Cleanup[job.ID] = job
		addAudit(st, "user", owner.UserID, owner.UserID, "connection.disconnected", "", c.ID, "", "blocked_pending_cleanup", "", 0)
		return nil
	})
	if e != nil {
		fail(w, 403, "NOT_AUTHORIZED")
		return
	}
	jsonOut(w, 202, map[string]string{"status": "disconnecting", "notice": "Google revocation can remove this app's broader authorization to the connected account."})
}

// CleanupOnce processes durable pending jobs. A cleanup failure keeps access blocked.
func (s *Server) CleanupOnce(ctx context.Context) error {
	jobs := []domain.Cleanup{}
	if e := s.Repository.Transact(ctx, func(st *domain.State) error {
		for _, j := range st.Cleanup {
			if j.Status == "pending" {
				jobs = append(jobs, j)
			}
		}
		return nil
	}); e != nil {
		return e
	}
	for _, j := range jobs {
		if e := s.integration.Cleanup(ctx, j.ConnectionID, j.Epoch); e != nil {
			continue
		}
		if e := s.Repository.Transact(ctx, func(st *domain.State) error {
			c := st.Connections[j.ConnectionID]
			if c.Epoch != j.Epoch || c.Status != "disconnecting" {
				return domain.ErrDenied
			}
			c.Status = "disconnected"
			st.Connections[c.ID] = c
			j.Status = "complete"
			st.Cleanup[j.ID] = j
			addAudit(st, "service", "cleanup", j.OwnerID, "connection.cleanup", "", c.ID, "", "complete", "", 0)
			return nil
		}); e != nil {
			return e
		}
	}
	return nil
}
func (s *Server) revokeGrant(w http.ResponseWriter, r *http.Request) {
	owner, ok := s.requireOwner(w, r, true)
	if !ok {
		return
	}
	var in struct{}
	if !body(w, r, &in) {
		return
	}
	e := s.Repository.Transact(r.Context(), func(st *domain.State) error {
		g, ok := st.Grants[r.PathValue("id")]
		if !ok || g.OwnerID != owner.UserID {
			return domain.ErrDenied
		}
		if g.RevokedAt == nil {
			now := st.Now
			g.RevokedAt = &now
			st.Grants[g.ID] = g
			addAudit(st, "user", owner.UserID, owner.UserID, "grant.revoked", g.ID, g.ConnectionID, g.FileID, "allowed", "", 0)
		}
		return nil
	})
	if e != nil {
		fail(w, 403, "NOT_AUTHORIZED")
		return
	}
	jsonOut(w, 200, map[string]string{"status": "revoked"})
}
func (s *Server) audit(w http.ResponseWriter, r *http.Request) {
	owner, ok := s.requireOwner(w, r, false)
	if !ok {
		return
	}
	events := []domain.Audit{}
	e := s.Repository.Transact(r.Context(), func(st *domain.State) error {
		for _, a := range st.Audits {
			if a.SubjectID == owner.UserID {
				events = append(events, a)
			}
		}
		return nil
	})
	if e != nil {
		fail(w, 503, "DEPENDENCY_UNAVAILABLE")
		return
	}
	jsonOut(w, 200, events)
}
