package server

import (
	"context"
	"time"

	"github.com/ufaruq/toolbox/internal/domain"
	"github.com/ufaruq/toolbox/internal/identity"
	"github.com/ufaruq/toolbox/internal/security"
)

// agentAccess contains only identity established by a trusted authentication path.
// An empty credential ID is never treated as an authentication bypass.
type agentAccess struct {
	AgentID, CredentialID, CallerProfileID string
	TokenExpiresAt                         time.Time
}

type Identity interface {
	VerifyAccess(context.Context, string) (identity.Claims, error)
	Clients() map[string]string
	Issuer() string
}

// OwnerIssuer is supplied only by the configured verifier after validating the
// same-tenant org/custom-server binding. Fixtures retain their single issuer.
func (s *Server) identityOwnerIssuer() string {
	if s.Identity == nil {
		return ""
	}
	if binding, ok := s.Identity.(interface{ OwnerIssuer() string }); ok {
		return binding.OwnerIssuer()
	}
	return s.Identity.Issuer()
}

func profileForAgent(st *domain.State, agentID string) (domain.CallerProfile, bool) {
	for _, p := range st.CallerProfiles {
		if p.AgentID == agentID {
			return p, true
		}
	}
	return domain.CallerProfile{}, false
}
func profileActive(st *domain.State, p domain.CallerProfile, tool string) bool {
	a := st.Agents[p.AgentID]
	u, ok := domain.ResolveIdentity(st, p.Issuer, p.UserID)
	return ok && u.ID == p.OwnerID && p.Status == "active" && st.Now.Before(p.ExpiresAt) && a.Status == "active" && a.OwnerID == p.OwnerID && u.Status == "active" && (tool == "" || domain.HasScope(p.Tools, tool))
}
func (s *Server) authorizeAgent(st *domain.State, access agentAccess, tool string) error {
	a := st.Agents[access.AgentID]
	if a.ID == "" || a.Status != "active" || st.Users[a.OwnerID].Status != "active" {
		return domain.ErrDenied
	}
	if access.CredentialID != "" {
		if access.CallerProfileID != "" || !credentialActive(st, access.CredentialID, a.ID) {
			return domain.ErrDenied
		}
	} else {
		p, ok := st.CallerProfiles[access.CallerProfileID]
		if !ok || p.AgentID != a.ID || access.TokenExpiresAt.IsZero() || !st.Now.Before(access.TokenExpiresAt) {
			return domain.ErrDenied
		}
	}
	if p, ok := profileForAgent(st, a.ID); ok {
		if !profileActive(st, p, tool) || (approvedCandidateForProfile(st, p) && !s.clientAdmitted(st, p)) {
			return domain.ErrDenied
		}
	} else if access.CallerProfileID != "" {
		return domain.ErrDenied
	}
	return nil
}
func (s *Server) grantAccessCheck(st *domain.State, access agentAccess, grantID, fileID string, c *security.Claims) (domain.Grant, error) {
	if e := s.authorizeAgent(st, access, domain.Tool); e != nil {
		return domain.Grant{}, e
	}
	return grantRules(st, access.AgentID, grantID, fileID, c)
}
