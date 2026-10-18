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
	AuthorizationURL(state, nonce, verifier string) (string, error)
	Complete(ctx context.Context, code, verifier, nonceHash string) (identity.Owner, error)
	Clients() map[string]string
	Issuer() string
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
	u := st.Users[p.OwnerID]
	return p.Status == "active" && st.Now.Before(p.ExpiresAt) && a.Status == "active" && a.OwnerID == p.OwnerID && u.Status == "active" && u.Issuer == p.Issuer && u.Subject == p.UserID && (tool == "" || domain.HasScope(p.Tools, tool))
}
func authorizeAgent(st *domain.State, access agentAccess, tool string) error {
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
		if !profileActive(st, p, tool) {
			return domain.ErrDenied
		}
	} else if access.CallerProfileID != "" {
		return domain.ErrDenied
	}
	return nil
}
func (s *Server) resolveCaller(ctx context.Context, claims identity.Claims) (agentAccess, error) {
	var access agentAccess
	if s.Identity == nil || claims.Issuer != s.Identity.Issuer() || claims.UserID == "" || claims.ClientID == "" {
		return access, domain.ErrDenied
	}
	if _, ok := s.Identity.Clients()[claims.ClientID]; !ok {
		return access, domain.ErrDenied
	}
	e := s.Repository.Transact(ctx, func(st *domain.State) error {
		for _, p := range st.CallerProfiles {
			if p.Issuer == claims.Issuer && p.UserID == claims.UserID && p.ClientID == claims.ClientID {
				access = agentAccess{AgentID: p.AgentID, CallerProfileID: p.ID, TokenExpiresAt: claims.ExpiresAt}
				return authorizeAgent(st, access, "")
			}
		}
		return domain.ErrDenied
	})
	return access, e
}
func grantAccessCheck(st *domain.State, access agentAccess, grantID, fileID string, c *security.Claims) (domain.Grant, error) {
	if e := authorizeAgent(st, access, domain.Tool); e != nil {
		return domain.Grant{}, e
	}
	return grantRules(st, access.AgentID, grantID, fileID, c)
}
