package server

import (
	"context"
	"fmt"
	"net/http"
	"regexp"

	"github.com/ufaruq/toolbox/internal/domain"
	"github.com/ufaruq/toolbox/internal/security"
)

var fileIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,256}$`)

func digest(q domain.Request) string {
	return security.Hash(fmt.Sprintf("%s\n%s\n%s\n%d\n%d\n%d", q.AgentID, q.Tool, q.FileID, q.Version, q.DurationSeconds, q.RequestedExpiry.Unix()))
}
func approvalDigest(q domain.Request, c domain.Connection) string {
	return security.Hash(q.Digest + "\n" + c.ID + "\n" + c.Subject + fmt.Sprintf("\n%d", c.Epoch))
}
func (s *Server) createRequest(w http.ResponseWriter, r *http.Request) {
	a, credential, ok := s.requireAgent(w, r)
	if !ok {
		return
	}
	var in struct {
		Tool            string `json:"tool"`
		FileID          string `json:"file_id"`
		DurationSeconds int64  `json:"duration_seconds"`
	}
	if !body(w, r, &in) {
		return
	}
	if in.Tool != domain.Tool || !fileIDPattern.MatchString(in.FileID) || in.DurationSeconds < 1 || in.DurationSeconds > 7*24*3600 {
		fail(w, 400, "INVALID_SCHEMA")
		return
	}
	result, e := s.createDelegation(r.Context(), agentAccess{AgentID: a.ID, CredentialID: credential}, in.Tool, in.FileID, in.DurationSeconds)
	if e != nil {
		operationFailure(w, e)
		return
	}
	jsonOut(w, 201, result)
}
func (s *Server) pollRequest(w http.ResponseWriter, r *http.Request) {
	a, cred, ok := s.requireAgent(w, r)
	if !ok {
		return
	}
	result, e := s.pollDelegation(r.Context(), agentAccess{AgentID: a.ID, CredentialID: cred}, r.PathValue("id"))
	if e != nil {
		operationFailure(w, e)
		return
	}
	jsonOut(w, 200, result)
}

type reviewInput struct {
	ConnectionID string `json:"connection_id"`
}
type approvalInput struct {
	ConnectionID string `json:"connection_id"`
	Version      int    `json:"version"`
	Digest       string `json:"digest"`
}

func (s *Server) ownerConnectionCheck(ctx context.Context, ownerID, sessionID, connID string) error {
	return s.Repository.Transact(ctx, func(st *domain.State) error {
		u := st.Users[ownerID]
		session := st.Sessions[sessionID]
		c, ok := st.Connections[connID]
		if !ok || u.Status != "active" || session.UserID != ownerID || !st.Now.Before(session.ExpiresAt) || c.OwnerID != ownerID || c.Status != "active" || !domain.HasScope(c.Scopes, domain.DriveScope) {
			return domain.ErrDenied
		}
		if s.OwnerLogin != nil && !s.OwnerLogin.SessionBound(st, sessionID) {
			return domain.ErrDenied
		}
		return nil
	})
}
func (s *Server) pendingConnectionCheck(ctx context.Context, ownerID, sessionID, connID, requestID string) error {
	return s.Repository.Transact(ctx, func(st *domain.State) error {
		u := st.Users[ownerID]
		session := st.Sessions[sessionID]
		c, ok := st.Connections[connID]
		if !ok || u.Status != "active" || session.UserID != ownerID || !st.Now.Before(session.ExpiresAt) || c.OwnerID != ownerID || c.Status != "active" || !domain.HasScope(c.Scopes, domain.DriveScope) {
			return domain.ErrDenied
		}
		if s.OwnerLogin != nil && !s.OwnerLogin.SessionBound(st, sessionID) {
			return domain.ErrDenied
		}
		_, _, e := pending(st, requestID, ownerID, connID)
		return e
	})
}
func pending(st *domain.State, id, ownerID, connID string) (domain.Request, domain.Connection, error) {
	q, ok := st.Requests[id]
	a := st.Agents[q.AgentID]
	c, exists := st.Connections[connID]
	if !ok || !exists || a.OwnerID != ownerID || a.Status != "active" || c.OwnerID != ownerID || c.Status != "active" || q.Status != "pending" || !st.Now.Before(q.ExpiresAt) || !st.Now.Before(q.RequestedExpiry) || q.Digest != digest(q) || q.Tool != domain.Tool || !pendingProfileAllowed(st, q) || !domain.HasScope(c.Scopes, domain.DriveScope) {
		return q, c, domain.ErrDenied
	}
	return q, c, nil
}
func (s *Server) reviewRequest(w http.ResponseWriter, r *http.Request) {
	owner, ok := s.requireOwner(w, r, true)
	if !ok {
		return
	}
	var in reviewInput
	if !body(w, r, &in) {
		return
	}
	var q domain.Request
	var c domain.Connection
	var a domain.Agent
	var clientID string
	e := s.Repository.Transact(r.Context(), func(st *domain.State) error {
		var e error
		q, c, e = pending(st, r.PathValue("id"), owner.UserID, in.ConnectionID)
		a = st.Agents[q.AgentID]
		if p, ok := profileForAgent(st, a.ID); ok {
			clientID = p.ClientID
		}
		return e
	})
	if e != nil {
		fail(w, 403, "NOT_AUTHORIZED")
		return
	}
	check := func(ctx context.Context) error {
		return s.pendingConnectionCheck(ctx, owner.UserID, owner.ID, c.ID, q.ID)
	}
	doc, e := s.integration.Inspect(r.Context(), c.ID, q.FileID, check)
	if e == nil {
		e = check(r.Context())
	}
	if e != nil {
		fail(w, 403, "RESOURCE_UNAVAILABLE")
		return
	}
	jsonOut(w, 200, map[string]any{"request_id": q.ID, "agent_id": a.ID, "agent_name": a.Name, "verified_client": clientID, "account_subject": c.Subject, "connection_id": c.ID, "tool": q.Tool, "description": "Read only the plain-text export of this Google document.", "file_id": q.FileID, "document_name": doc.Name, "expires_at": q.RequestedExpiry, "version": q.Version, "digest": approvalDigest(q, c), "provider_scope_notice": "Google drive.file includes broader app file authority. This grant permits only this exact document read."})
}
func (s *Server) approveRequest(w http.ResponseWriter, r *http.Request) {
	owner, ok := s.requireOwner(w, r, true)
	if !ok {
		return
	}
	var in approvalInput
	if !body(w, r, &in) {
		return
	}
	var q domain.Request
	var c domain.Connection
	e := s.Repository.Transact(r.Context(), func(st *domain.State) error {
		var e error
		q, c, e = pending(st, r.PathValue("id"), owner.UserID, in.ConnectionID)
		if e != nil || q.Version != in.Version || !security.Equal(approvalDigest(q, c), in.Digest) {
			return domain.ErrDenied
		}
		return nil
	})
	if e != nil {
		fail(w, 403, "APPROVAL_CHANGED_OR_EXPIRED")
		return
	}
	check := func(ctx context.Context) error {
		return s.pendingConnectionCheck(ctx, owner.UserID, owner.ID, c.ID, q.ID)
	}
	doc, e := s.integration.Inspect(r.Context(), c.ID, q.FileID, check)
	if e != nil {
		fail(w, 403, "RESOURCE_UNAVAILABLE")
		return
	}
	var grant domain.Grant
	e = s.Repository.Transact(r.Context(), func(st *domain.State) error {
		current, conn, e := pending(st, q.ID, owner.UserID, c.ID)
		session := st.Sessions[owner.ID]
		if e != nil || session.UserID != owner.UserID || !st.Now.Before(session.ExpiresAt) || current.Version != in.Version || !security.Equal(approvalDigest(current, conn), in.Digest) {
			return domain.ErrDenied
		}
		st.Resources[domain.ResourceKey(c.ID, q.FileID)] = domain.Resource{ConnectionID: c.ID, FileID: q.FileID, MIME: doc.MIME, Name: doc.Name, VerifiedAt: st.Now}
		grant = domain.Grant{ID: security.ID(), OwnerID: owner.UserID, AgentID: q.AgentID, ConnectionID: c.ID, Epoch: conn.Epoch, Version: 1, Tool: q.Tool, Action: domain.Action, FileID: q.FileID, NotBefore: st.Now, ExpiresAt: q.RequestedExpiry}
		st.Grants[grant.ID] = grant
		current.Status = "approved"
		current.GrantID = grant.ID
		st.Requests[current.ID] = current
		addAudit(st, "user", owner.UserID, owner.UserID, "delegation.approved", grant.ID, c.ID, q.FileID, "allowed", "", 0)
		return nil
	})
	if e != nil {
		fail(w, 403, "APPROVAL_CHANGED_OR_EXPIRED")
		return
	}
	jsonOut(w, 201, map[string]string{"grant_id": grant.ID, "status": "approved"})
}
func (s *Server) denyRequest(w http.ResponseWriter, r *http.Request) {
	owner, ok := s.requireOwner(w, r, true)
	if !ok {
		return
	}
	var in struct{}
	if !body(w, r, &in) {
		return
	}
	e := s.Repository.Transact(r.Context(), func(st *domain.State) error {
		q, ok := st.Requests[r.PathValue("id")]
		if !ok || st.Agents[q.AgentID].OwnerID != owner.UserID || q.Status != "pending" {
			return domain.ErrDenied
		}
		q.Status = "denied"
		st.Requests[q.ID] = q
		addAudit(st, "user", owner.UserID, owner.UserID, "delegation.denied", "", "", q.FileID, "denied", "", 0)
		return nil
	})
	if e != nil {
		fail(w, 403, "NOT_AUTHORIZED")
		return
	}
	jsonOut(w, 200, map[string]string{"status": "denied"})
}
func (s *Server) mintToken(w http.ResponseWriter, r *http.Request) {
	a, cred, ok := s.requireAgent(w, r)
	if !ok {
		return
	}
	var in struct {
		GrantID string `json:"grant_id"`
	}
	if !body(w, r, &in) {
		return
	}
	result, e := s.mintDelegation(r.Context(), agentAccess{AgentID: a.ID, CredentialID: cred}, in.GrantID)
	if e != nil {
		operationFailure(w, e)
		return
	}
	jsonOut(w, 200, result)
}
