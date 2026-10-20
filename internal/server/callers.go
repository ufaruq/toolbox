package server

import (
	"net/http"
	"strings"
	"time"

	"github.com/ufaruq/toolbox/internal/domain"
	"github.com/ufaruq/toolbox/internal/security"
)

func pendingProfileAllowed(st *domain.State, q domain.Request) bool {
	p, ok := profileForAgent(st, q.AgentID)
	return !ok || (profileActive(st, p, q.Tool) && !q.RequestedExpiry.After(p.ExpiresAt))
}
func (s *Server) ownerRoutes() {
	s.mux.HandleFunc("GET /v1/config", func(w http.ResponseWriter, r *http.Request) {
		available := true
		if v, ok := s.integration.(interface{ Available() bool }); ok {
			available = v.Available()
		}
		jsonOut(w, 200, map[string]bool{"fixture": s.Fixture, "identity_enabled": s.Identity != nil, "google_available": available})
	})
	s.mux.HandleFunc("GET /v1/callers", s.callers)
	s.mux.HandleFunc("POST /v1/callers", s.createCaller)
	s.mux.HandleFunc("POST /v1/callers/{id}/disable", s.disableCaller)
	s.mux.HandleFunc("POST /v1/callers/{id}/enable", s.enableCaller)
}
func (s *Server) callers(w http.ResponseWriter, r *http.Request) {
	owner, ok := s.requireOwner(w, r, false)
	if !ok {
		return
	}
	profiles := []map[string]any{}
	clients := map[string]string{}
	if s.Identity != nil {
		clients = s.Identity.Clients()
	}
	e := s.Repository.Transact(r.Context(), func(st *domain.State) error {
		for _, p := range st.CallerProfiles {
			if p.OwnerID == owner.UserID {
				p.Tools = append([]string{}, p.Tools...)
				profiles = append(profiles, callerView(p))
			}
		}
		return nil
	})
	if e != nil {
		fail(w, 503, "DEPENDENCY_UNAVAILABLE")
		return
	}
	jsonOut(w, 200, map[string]any{"callers": profiles, "clients": clients})
}

type callerInput struct {
	ClientID        string   `json:"client_id"`
	Label           string   `json:"label"`
	Tools           []string `json:"tools"`
	DurationSeconds int64    `json:"duration_seconds"`
}
type callerEnableInput struct {
	Tools           []string `json:"tools"`
	DurationSeconds int64    `json:"duration_seconds"`
}

func validCallerTools(tools []string, duration int64) bool {
	return tools != nil && len(tools) <= 1 && (len(tools) == 0 || tools[0] == domain.Tool) && duration >= 1 && duration <= 30*24*3600
}
func (s *Server) createCaller(w http.ResponseWriter, r *http.Request) {
	owner, ok := s.requireOwner(w, r, true)
	if !ok {
		return
	}
	var in callerInput
	if !body(w, r, &in) {
		return
	}
	if s.Identity == nil {
		fail(w, 503, "IDENTITY_UNAVAILABLE")
		return
	}
	_, configured := s.Identity.Clients()[in.ClientID]
	if !configured || len(in.Label) < 1 || len(in.Label) > 80 || strings.ContainsAny(in.Label, "\r\n\x00") || !validCallerTools(in.Tools, in.DurationSeconds) {
		fail(w, 400, "INVALID_SCHEMA")
		return
	}
	var profile domain.CallerProfile
	e := s.Repository.Transact(r.Context(), func(st *domain.State) error {
		u := st.Users[owner.UserID]
		if u.Status != "active" || u.Issuer != s.identityOwnerIssuer() {
			return domain.ErrDenied
		}
		for _, p := range st.CallerProfiles {
			if p.Issuer == u.Issuer && p.UserID == u.Subject && p.ClientID == in.ClientID {
				return domain.ErrDenied
			}
		}
		a := domain.Agent{ID: security.ID(), OwnerID: u.ID, Name: in.Label, Status: "active"}
		st.Agents[a.ID] = a
		profile = domain.CallerProfile{ID: security.ID(), OwnerID: u.ID, AgentID: a.ID, Issuer: u.Issuer, UserID: u.Subject, ClientID: in.ClientID, Label: in.Label, Status: "active", Tools: append([]string{}, in.Tools...), ApprovedAt: st.Now, ExpiresAt: st.Now.Add(time.Duration(in.DurationSeconds) * time.Second)}
		st.CallerProfiles[profile.ID] = profile
		addCallerAudit(st, profile, "caller.approved")
		return nil
	})
	if e != nil {
		fail(w, 403, "NOT_AUTHORIZED")
		return
	}
	jsonOut(w, 201, callerView(profile))
}
func invalidateCaller(st *domain.State, p domain.CallerProfile) {
	for id, g := range st.Grants {
		if g.AgentID == p.AgentID && g.RevokedAt == nil {
			now := st.Now
			g.RevokedAt = &now
			st.Grants[id] = g
		}
	}
	for id, q := range st.Requests {
		if q.AgentID == p.AgentID && q.Status == "pending" {
			q.Status = "cancelled"
			st.Requests[id] = q
		}
	}
}
func (s *Server) disableCaller(w http.ResponseWriter, r *http.Request) {
	owner, ok := s.requireOwner(w, r, true)
	if !ok {
		return
	}
	var in struct{}
	if !body(w, r, &in) {
		return
	}
	e := s.Repository.Transact(r.Context(), func(st *domain.State) error {
		p, ok := st.CallerProfiles[r.PathValue("id")]
		if !ok || p.OwnerID != owner.UserID {
			return domain.ErrDenied
		}
		p.Status = "disabled"
		st.CallerProfiles[p.ID] = p
		a := st.Agents[p.AgentID]
		a.Status = "disabled"
		st.Agents[a.ID] = a
		invalidateCaller(st, p)
		addCallerAudit(st, p, "caller.disabled")
		return nil
	})
	if e != nil {
		fail(w, 403, "NOT_AUTHORIZED")
		return
	}
	jsonOut(w, 200, map[string]string{"status": "disabled"})
}
func (s *Server) enableCaller(w http.ResponseWriter, r *http.Request) {
	owner, ok := s.requireOwner(w, r, true)
	if !ok {
		return
	}
	var in callerEnableInput
	if !body(w, r, &in) {
		return
	}
	if !validCallerTools(in.Tools, in.DurationSeconds) {
		fail(w, 400, "INVALID_SCHEMA")
		return
	}
	e := s.Repository.Transact(r.Context(), func(st *domain.State) error {
		p, ok := st.CallerProfiles[r.PathValue("id")]
		if !ok || p.OwnerID != owner.UserID || s.Identity == nil {
			return domain.ErrDenied
		}
		if _, ok := s.Identity.Clients()[p.ClientID]; !ok {
			return domain.ErrDenied
		}
		invalidateCaller(st, p)
		p.Status = "active"
		p.Tools = append([]string{}, in.Tools...)
		p.ApprovedAt = st.Now
		p.ExpiresAt = st.Now.Add(time.Duration(in.DurationSeconds) * time.Second)
		st.CallerProfiles[p.ID] = p
		a := st.Agents[p.AgentID]
		a.Status = "active"
		st.Agents[a.ID] = a
		addCallerAudit(st, p, "caller.enabled")
		return nil
	})
	if e != nil {
		fail(w, 403, "NOT_AUTHORIZED")
		return
	}
	jsonOut(w, 200, map[string]string{"status": "active"})
}

func callerView(p domain.CallerProfile) map[string]any {
	return map[string]any{"id": p.ID, "agent_id": p.AgentID, "issuer": p.Issuer, "user_id": p.UserID, "client_id": p.ClientID, "label": p.Label, "status": p.Status, "tools": append([]string{}, p.Tools...), "approved_at": p.ApprovedAt, "expires_at": p.ExpiresAt}
}
func addCallerAudit(st *domain.State, p domain.CallerProfile, action string) {
	addAudit(st, "user", p.OwnerID, p.OwnerID, action, "", "", "", "allowed", "", 0)
	event := &st.Audits[len(st.Audits)-1]
	event.AgentID = p.AgentID
	event.CallerProfileID = p.ID
	event.ClientID = p.ClientID
}
