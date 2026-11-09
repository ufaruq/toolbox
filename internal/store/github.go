package store

import (
	"github.com/ufaruq/toolbox/internal/domain"
	"reflect"
)

func validateGitHub(old, s *domain.State) error {
	if s.GitHubConnections == nil || s.GitHubRequests == nil || s.GitHubGrants == nil {
		return invalid("nil github collection")
	}
	for k, c := range s.GitHubConnections {
		if k == "" || k != c.ID || c.OwnerID == "" || s.Users[c.OwnerID].ID == "" || c.InstallationID <= 0 || c.RepositoryID <= 0 || c.Epoch < 1 || c.RepositoryOwner == "" || c.RepositoryName == "" || (c.Status != "active" && c.Status != "disconnected") {
			return invalid("github connection")
		}
		if prev, ok := old.GitHubConnections[k]; ok {
			p, n := prev, c
			p.Status, n.Status = "", ""
			p.Epoch, n.Epoch = 0, 0
			if p != n || c.Epoch < prev.Epoch || (prev.Status == "disconnected" && c.Status != "disconnected") || (prev.Status != c.Status && c.Epoch <= prev.Epoch) {
				return invalid("github connection mutation")
			}
		}
	}
	for k, prev := range old.GitHubConnections {
		if _, ok := s.GitHubConnections[k]; !ok && prev.ID != "" {
			return invalid("github connection deletion")
		}
	}
	validBinding := func(owner, agent, conn string, repo, epoch int64) bool {
		a, aok := s.Agents[agent]
		c, cok := s.GitHubConnections[conn]
		return aok && cok && a.OwnerID == owner && c.OwnerID == owner && repo == c.RepositoryID && epoch > 0 && epoch <= c.Epoch
	}
	validScope := func(scope domain.GitHubScope) bool {
		return len(scope.Actions) > 0 && len(scope.Actions) <= 32 && len(scope.Branches) <= 64 && len(scope.Paths) <= 128 && len(scope.BaseBranches) <= 64 && len(scope.PullRequests) <= 128
	}
	for k, g := range s.GitHubGrants {
		if k == "" || k != g.ID || !validBinding(g.OwnerID, g.AgentID, g.ConnectionID, g.RepositoryID, g.Epoch) || !validScope(g.Scope) || g.NotBefore.IsZero() || !g.ExpiresAt.After(g.NotBefore) {
			return invalid("github grant")
		}
	}
	for k, p := range old.GitHubGrants {
		n, ok := s.GitHubGrants[k]
		if !ok {
			return invalid("github grant deletion")
		}
		pRev := p.RevokedAt
		nRev := n.RevokedAt
		p.RevokedAt = nil
		n.RevokedAt = nil
		if !reflect.DeepEqual(p, n) || (pRev != nil && (nRev == nil || !pRev.Equal(*nRev))) {
			return invalid("github grant mutation")
		}
	}
	approvals := map[string]bool{}
	for k, q := range s.GitHubRequests {
		if k == "" || k != q.ID || !validBinding(q.OwnerID, q.AgentID, q.ConnectionID, q.RepositoryID, q.Epoch) || !validScope(q.Scope) || q.Digest == "" || q.ExpiresAt.IsZero() || q.ReviewExpiresAt.IsZero() {
			return invalid("github request")
		}
		switch q.Status {
		case "pending", "approved", "denied", "expired":
		default:
			return invalid("github request status")
		}
		if (q.Status == "approved") != (q.GrantID != "") {
			return invalid("github approval")
		}
		if q.GrantID != "" {
			g, ok := s.GitHubGrants[q.GrantID]
			if !ok || approvals[g.ID] || q.OwnerID != g.OwnerID || q.AgentID != g.AgentID || q.ConnectionID != g.ConnectionID || q.RepositoryID != g.RepositoryID || q.Epoch != g.Epoch || !reflect.DeepEqual(q.Scope, g.Scope) || !q.ExpiresAt.Equal(g.ExpiresAt) {
				return invalid("github approval binding")
			}
			approvals[g.ID] = true
		}
	}
	for k, p := range old.GitHubRequests {
		q, ok := s.GitHubRequests[k]
		if !ok {
			return invalid("github request deletion")
		}
		if p.Status != "pending" {
			if !reflect.DeepEqual(p, q) {
				return invalid("github completed request mutation")
			}
			continue
		}
		p.Status, q.Status = "", ""
		p.GrantID, q.GrantID = "", ""
		if !reflect.DeepEqual(p, q) {
			return invalid("github request scope mutation")
		}
	}
	return nil
}
