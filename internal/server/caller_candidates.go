package server

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/ufaruq/toolbox/internal/domain"
	"github.com/ufaruq/toolbox/internal/identity"
	"github.com/ufaruq/toolbox/internal/security"
)

type onboardingVerifier interface {
	DynamicClientOnboarding() bool
	VerifyOnboardingAccess(context.Context, string) (identity.Claims, error)
}

func (s *Server) dynamicOnboarding() bool {
	v, ok := s.Identity.(onboardingVerifier)
	return ok && v.DynamicClientOnboarding()
}
func (s *Server) clientAdmitted(st *domain.State, p domain.CallerProfile) bool {
	if s.Identity == nil {
		return false
	}
	if _, ok := s.Identity.Clients()[p.ClientID]; ok {
		return true
	}
	return s.dynamicOnboarding() && approvedCandidateForProfile(st, p)
}
func approvedCandidateForProfile(st *domain.State, p domain.CallerProfile) bool {
	for _, c := range st.CallerCandidates {
		if c.Status == "approved" && c.OwnerID == p.OwnerID && c.Issuer == p.Issuer && c.UserID == p.UserID && c.ClientID == p.ClientID {
			return true
		}
	}

	return false
}
func (s *Server) resolveCaller(ctx context.Context, claims identity.Claims) (agentAccess, error) {
	var access agentAccess
	denied := opError(403, "CALLER_NOT_APPROVED")
	if s.Identity == nil || claims.Issuer != s.Identity.Issuer() || claims.UserID == "" || claims.ClientID == "" {
		return access, denied
	}
	var result error
	err := s.Repository.Transact(ctx, func(st *domain.State) error {
		if claims.ExpiresAt.IsZero() || !st.Now.Before(claims.ExpiresAt) {
			return denied
		}
		issuer := s.identityOwnerIssuer()
		for _, p := range st.CallerProfiles {
			if p.Issuer == issuer && p.UserID == claims.UserID && p.ClientID == claims.ClientID {
				if !s.clientAdmitted(st, p) {
					return denied
				}
				access = agentAccess{AgentID: p.AgentID, CallerProfileID: p.ID, TokenExpiresAt: claims.ExpiresAt}
				if s.authorizeAgent(st, access, "") != nil {
					return denied
				}
				return nil
			}
		}
		if !s.dynamicOnboarding() {
			return denied
		}
		owner, ok := domain.ResolveIdentity(st, issuer, claims.UserID)
		if !ok || owner.Status != "active" {
			return denied
		}
		count := 0
		for _, c := range st.CallerCandidates {
			if c.OwnerID == owner.ID {
				count++
			}
			if c.Issuer == issuer && c.UserID == claims.UserID && c.ClientID == claims.ClientID {
				if c.Status != "pending" {
					return denied
				}
				result = opError(403, "CALLER_PENDING_APPROVAL")
				return nil
			}
		}
		if count >= 64 || len(st.CallerCandidates) >= 4096 {
			return opError(429, "CALLER_CAPACITY_REACHED")
		}
		if !s.allowed("candidate:"+owner.ID, 10) {
			return opError(429, "RATE_LIMITED")
		}
		c := domain.CallerCandidate{ID: security.ID(), OwnerID: owner.ID, Issuer: issuer, UserID: claims.UserID, ClientID: claims.ClientID, Status: "pending", FirstSeenAt: st.Now}
		st.CallerCandidates[c.ID] = c
		candidateAudit(st, c, "caller.pending")
		// Intentional denial is returned AFTER commit, so the queue entry persists.
		result = opError(403, "CALLER_PENDING_APPROVAL")
		return nil
	})
	if err != nil {
		return agentAccess{}, err
	}
	return access, result
}
func candidateView(c domain.CallerCandidate) map[string]any {
	return map[string]any{"id": c.ID, "issuer": c.Issuer, "user_id": c.UserID, "client_id": c.ClientID, "status": c.Status, "first_seen_at": c.FirstSeenAt, "decided_at": c.DecidedAt}
}
func candidateAudit(st *domain.State, c domain.CallerCandidate, action string) {
	addAudit(st, "user", c.OwnerID, c.OwnerID, action, "", "", "", c.Status, "", 0)
	st.Audits[len(st.Audits)-1].ClientID = c.ClientID
}
func (s *Server) decideCallerCandidate(w http.ResponseWriter, r *http.Request) {
	owner, ok := s.requireOwner(w, r, true)
	if !ok {
		return
	}
	if !s.dynamicOnboarding() {
		fail(w, 403, "ONBOARDING_DISABLED")
		return
	}
	decision := r.PathValue("decision")
	var in struct {
		Label           string   `json:"label"`
		Tools           []string `json:"tools"`
		DurationSeconds int64    `json:"duration_seconds"`
	}
	if decision == "approve" {
		if !body(w, r, &in) {
			return
		}
		if strings.TrimSpace(in.Label) == "" || len(in.Label) > 80 || strings.ContainsAny(in.Label, "\r\n\x00") || !validCallerTools(in.Tools, in.DurationSeconds) {
			fail(w, 400, "INVALID_SCHEMA")
			return
		}
	} else if decision == "reject" || decision == "reopen" {
		var empty struct{}
		if !body(w, r, &empty) {
			return
		}
	} else {
		fail(w, 404, "NOT_FOUND")
		return
	}
	var result map[string]any
	err := s.Repository.Transact(r.Context(), func(st *domain.State) error {
		c, ok := st.CallerCandidates[r.PathValue("id")]
		session, live := st.Sessions[owner.ID]
		if !live || session.UserID != owner.UserID || !st.Now.Before(session.ExpiresAt) || !security.Equal(session.CSRFHash, owner.CSRFHash) || (s.OwnerLogin != nil && !s.OwnerLogin.SessionBound(st, owner.ID)) {
			return domain.ErrDenied
		}
		if !ok || c.OwnerID != owner.UserID || st.Users[owner.UserID].Status != "active" {
			return domain.ErrDenied
		}
		if decision == "reopen" && c.Status != "rejected" || decision != "reopen" && c.Status != "pending" {
			return opError(409, "CALLER_DECISION_CONFLICT")
		}
		c.DecidedAt = st.Now
		switch decision {
		case "approve":
			binding, ok := domain.ResolveIdentity(st, c.Issuer, c.UserID)
			if !ok || binding.ID != owner.UserID || c.Issuer != s.identityOwnerIssuer() {
				return domain.ErrDenied
			}
			for _, p := range st.CallerProfiles {
				if p.Issuer == c.Issuer && p.UserID == c.UserID && p.ClientID == c.ClientID {
					return opError(409, "CALLER_DECISION_CONFLICT")
				}
			}
			a := domain.Agent{ID: security.ID(), OwnerID: c.OwnerID, Name: in.Label, Status: "active"}
			st.Agents[a.ID] = a
			p := domain.CallerProfile{ID: security.ID(), OwnerID: c.OwnerID, AgentID: a.ID, Issuer: c.Issuer, UserID: c.UserID, ClientID: c.ClientID, Label: in.Label, Status: "active", Tools: append([]string{}, in.Tools...), ApprovedAt: st.Now, ExpiresAt: st.Now.Add(time.Duration(in.DurationSeconds) * time.Second)}
			st.CallerProfiles[p.ID] = p
			c.Status = "approved"
			result = callerView(p)
			addCallerAudit(st, p, "caller.approved")
		case "reject":
			c.Status = "rejected"
			candidateAudit(st, c, "caller.rejected")
		case "reopen":
			c.Status = "pending"
			c.DecidedAt = time.Time{}
			candidateAudit(st, c, "caller.reopened")
		}
		st.CallerCandidates[c.ID] = c
		if result == nil {
			result = candidateView(c)
		}
		return nil
	})
	if errors.Is(err, domain.ErrDenied) {
		fail(w, 403, "NOT_AUTHORIZED")
		return
	}
	if err != nil {
		operationFailure(w, err)
		return
	}
	status := 200
	if decision == "approve" {
		status = 201
	}
	jsonOut(w, status, result)
}
