package store

import (
	"fmt"
	"reflect"

	"github.com/ufaruq/toolbox/internal/domain"
)

func invalid(kind string) error { return fmt.Errorf("%w: %s", ErrInvariant, kind) }

// validate is shared by both adapters. SQL constraints are a second boundary;
// application policy must still authorize every mutation before this layer.
func validate(old, s *domain.State) error {
	if s.CallerProfiles == nil || s.OwnerLogins == nil || s.Users == nil || s.Agents == nil || s.Credentials == nil || s.Sessions == nil || s.Connections == nil || s.Resources == nil || s.Requests == nil || s.Grants == nil || s.OAuth == nil || s.Cleanup == nil {
		return invalid("nil collection")
	}
	identities := map[string]bool{}
	for k, v := range s.Users {
		if k == "" || k != v.ID || v.Issuer == "" || v.Subject == "" || v.Status == "" {
			return invalid("user")
		}
		key := v.Issuer + "\x00" + v.Subject
		if identities[key] {
			return invalid("duplicate user identity")
		}
		identities[key] = true
	}
	for k, v := range s.Agents {
		if k == "" || k != v.ID || v.Status == "" {
			return invalid("agent")
		}
		if _, ok := s.Users[v.OwnerID]; !ok {
			return invalid("agent owner")
		}
		if prev, ok := old.Agents[k]; ok && prev.OwnerID != v.OwnerID {
			return invalid("agent owner changed")
		}
	}
	profileIdentities := map[[3]string]bool{}
	profileAgents := map[string]bool{}
	for k, v := range s.CallerProfiles {
		if k == "" || k != v.ID || v.Issuer == "" || v.UserID == "" || v.ClientID == "" || (v.Status != "active" && v.Status != "disabled") || v.ApprovedAt.IsZero() || v.ExpiresAt.IsZero() || !v.ExpiresAt.After(v.ApprovedAt) {
			return invalid("caller profile")
		}
		owner, ok := s.Users[v.OwnerID]
		agent, aok := s.Agents[v.AgentID]
		if !ok || !aok || agent.OwnerID != v.OwnerID || owner.Issuer != v.Issuer || owner.Subject != v.UserID {
			return invalid("caller profile owner identity")
		}
		identity := [3]string{v.Issuer, v.UserID, v.ClientID}
		if profileIdentities[identity] || profileAgents[v.AgentID] {
			return invalid("duplicate caller profile binding")
		}
		profileIdentities[identity], profileAgents[v.AgentID] = true, true
		if prev, ok := old.CallerProfiles[k]; ok && (prev.OwnerID != v.OwnerID || prev.AgentID != v.AgentID || prev.Issuer != v.Issuer || prev.UserID != v.UserID || prev.ClientID != v.ClientID) {
			return invalid("caller profile binding changed")
		}
	}
	for k, v := range s.OwnerLogins {
		if k == "" || k != v.ID || v.StateHash == "" || v.NonceHash == "" || v.BrowserHash == "" || v.SecretRef == "" || v.ExpiresAt.IsZero() {
			return invalid("owner login")
		}
		if prev, ok := old.OwnerLogins[k]; ok {
			if (prev.Consumed && !v.Consumed) || prev.StateHash != v.StateHash || prev.NonceHash != v.NonceHash || prev.BrowserHash != v.BrowserHash || prev.SecretRef != v.SecretRef || !prev.ExpiresAt.Equal(v.ExpiresAt) {
				return invalid("owner login binding or consumption changed")
			}
		}
	}
	for k, v := range s.Credentials {
		if k == "" || k != v.ID || v.Hash == "" || v.Status == "" || v.ExpiresAt.IsZero() {
			return invalid("credential")
		}
		if _, ok := s.Agents[v.AgentID]; !ok {
			return invalid("credential agent")
		}
	}
	for k, v := range s.Sessions {
		if k == "" || k != v.ID || v.CSRFHash == "" || v.ExpiresAt.IsZero() {
			return invalid("session")
		}
		if _, ok := s.Users[v.UserID]; !ok {
			return invalid("session owner")
		}
	}
	for k, v := range s.Connections {
		if k == "" || k != v.ID || v.Provider == "" || v.Status == "" || v.Epoch < 1 || v.SecretVersion < 0 {
			return invalid("connection")
		}
		if _, ok := s.Users[v.OwnerID]; !ok {
			return invalid("connection owner")
		}
		if prev, ok := old.Connections[k]; ok && (prev.OwnerID != v.OwnerID || v.Epoch < prev.Epoch) {
			return invalid("connection ownership or epoch changed")
		}
	}
	for k, v := range s.Resources {
		if v.ConnectionID == "" || v.FileID == "" || k != domain.ResourceKey(v.ConnectionID, v.FileID) {
			return invalid("resource")
		}
		if _, ok := s.Connections[v.ConnectionID]; !ok {
			return invalid("resource connection")
		}
	}
	for k, v := range s.Grants {
		if k == "" || k != v.ID || v.Tool == "" || v.Action == "" || v.FileID == "" || v.Version < 1 || v.Epoch < 1 || v.NotBefore.IsZero() || !v.ExpiresAt.After(v.NotBefore) {
			return invalid("grant")
		}
		a, aok := s.Agents[v.AgentID]
		c, cok := s.Connections[v.ConnectionID]
		if !aok || !cok || a.OwnerID != v.OwnerID || c.OwnerID != v.OwnerID {
			return invalid("grant ownership")
		}
		if _, ok := s.Resources[domain.ResourceKey(v.ConnectionID, v.FileID)]; !ok {
			return invalid("grant resource")
		}
	}
	for k, prev := range old.Grants {
		v, ok := s.Grants[k]
		if !ok {
			return invalid("grant deletion")
		}
		p, g := prev, v
		p.RevokedAt = nil
		g.RevokedAt = nil
		if !reflect.DeepEqual(p, g) {
			return invalid("grant mutation")
		}
		if prev.RevokedAt != nil && (v.RevokedAt == nil || !prev.RevokedAt.Equal(*v.RevokedAt)) {
			return invalid("grant revocation mutation")
		}
	}
	approvals := map[string]bool{}
	for k, v := range s.Requests {
		if k == "" || k != v.ID || v.FileID == "" || v.Tool == "" || v.Digest == "" || v.Status == "" || v.Version < 1 || v.DurationSeconds < 1 || v.ExpiresAt.IsZero() {
			return invalid("request")
		}
		if _, ok := s.Agents[v.AgentID]; !ok {
			return invalid("request agent")
		}
		if (v.Status == "approved") != (v.GrantID != "") {
			return invalid("request approval state")
		}
		if v.GrantID != "" {
			g, ok := s.Grants[v.GrantID]
			if !ok || g.AgentID != v.AgentID || g.Tool != v.Tool || g.FileID != v.FileID || approvals[v.GrantID] {
				return invalid("request grant binding")
			}
			approvals[v.GrantID] = true
		}
		if prev, ok := old.Requests[k]; ok && prev.GrantID != "" && !reflect.DeepEqual(prev, v) {
			return invalid("approved request mutation")
		}
	}
	for k, prev := range old.Requests {
		if prev.GrantID != "" {
			if _, ok := s.Requests[k]; !ok {
				return invalid("approved request deletion")
			}
		}
	}
	for k, v := range s.OAuth {
		if k == "" || k != v.ID || v.StateHash == "" || v.NonceHash == "" || v.SecretRef == "" || v.ExpiresAt.IsZero() {
			return invalid("oauth transaction")
		}
		session, ok := s.Sessions[v.SessionID]
		if !ok || session.UserID != v.OwnerID {
			return invalid("oauth session owner")
		}
		if v.ConnectionID != "" {
			c, ok := s.Connections[v.ConnectionID]
			if !ok || c.OwnerID != v.OwnerID {
				return invalid("oauth connection owner")
			}
		}
	}
	for k, v := range s.Cleanup {
		if k == "" || k != v.ID || v.Status == "" || v.Epoch < 1 {
			return invalid("cleanup")
		}
		c, ok := s.Connections[v.ConnectionID]
		if !ok || c.OwnerID != v.OwnerID {
			return invalid("cleanup owner")
		}
	}
	if len(s.Audits) < len(old.Audits) {
		return invalid("audit deletion")
	}
	ids := map[string]bool{}
	for i, a := range s.Audits {
		if a.ID == "" || a.At.IsZero() || a.Bytes < 0 || ids[a.ID] {
			return invalid("audit event")
		}
		ids[a.ID] = true
		if i < len(old.Audits) && !reflect.DeepEqual(a, old.Audits[i]) {
			return invalid("audit mutation")
		}
	}
	return nil
}
