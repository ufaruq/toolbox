package server

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/ufaruq/toolbox/internal/connectors"
	"github.com/ufaruq/toolbox/internal/domain"
	"github.com/ufaruq/toolbox/internal/security"
)

type operationError struct {
	Status int
	Code   string
}

func (e *operationError) Error() string     { return e.Code }
func opError(status int, code string) error { return &operationError{Status: status, Code: code} }
func operationFailure(w http.ResponseWriter, e error) {
	var oe *operationError
	if errors.As(e, &oe) {
		fail(w, oe.Status, oe.Code)
		return
	}
	fail(w, 503, "DEPENDENCY_UNAVAILABLE")
}
func (s *Server) createDelegation(ctx context.Context, access agentAccess, tool, fileID string, durationSeconds int64) (map[string]any, error) {
	if tool != domain.Tool || !fileIDPattern.MatchString(fileID) || durationSeconds < 1 || durationSeconds > 604800 {
		return nil, opError(400, "INVALID_SCHEMA")
	}
	if !s.allowed("request:"+access.AgentID, 10) {
		return nil, opError(429, "RATE_LIMITED")
	}
	var q domain.Request
	e := s.Repository.Transact(ctx, func(st *domain.State) error {
		if e := authorizeAgent(st, access, tool); e != nil {
			return e
		}
		q = domain.Request{ID: security.ID(), AgentID: access.AgentID, FileID: fileID, Tool: tool, Status: "pending", Version: 1, DurationSeconds: durationSeconds, RequestedExpiry: st.Now.Add(time.Duration(durationSeconds) * time.Second), ExpiresAt: st.Now.Add(10 * time.Minute)}
		if p, ok := profileForAgent(st, access.AgentID); ok && q.RequestedExpiry.After(p.ExpiresAt) {
			q.RequestedExpiry = p.ExpiresAt
		}
		q.Digest = digest(q)
		st.Requests[q.ID] = q
		addAudit(st, "agent", access.AgentID, st.Agents[access.AgentID].OwnerID, "delegation.requested", "", "", q.FileID, "pending", "", 0)
		return nil
	})
	if e != nil {
		if errors.Is(e, domain.ErrDenied) {
			return nil, opError(403, "NOT_AUTHORIZED")
		}
		return nil, opError(503, "DEPENDENCY_UNAVAILABLE")
	}
	return map[string]any{"request_id": q.ID, "status": q.Status, "approval_url": s.Origin + "/approve/" + q.ID, "expires_at": q.ExpiresAt}, nil
}
func (s *Server) pollDelegation(ctx context.Context, access agentAccess, id string) (map[string]string, error) {
	var q domain.Request
	e := s.Repository.Transact(ctx, func(st *domain.State) error {
		v, ok := st.Requests[id]
		if !ok || v.AgentID != access.AgentID || authorizeAgent(st, access, "") != nil {
			return domain.ErrDenied
		}
		q = v
		if q.Status == "pending" && !st.Now.Before(q.ExpiresAt) {
			q.Status = "expired"
		}
		return nil
	})
	if e != nil {
		return nil, opError(403, "NOT_AUTHORIZED")
	}
	return map[string]string{"request_id": q.ID, "status": q.Status, "grant_id": q.GrantID}, nil
}
func (s *Server) mintDelegation(ctx context.Context, access agentAccess, grantID string) (map[string]string, error) {
	if !s.allowed("mint:"+access.AgentID, 30) {
		return nil, opError(429, "RATE_LIMITED")
	}
	var raw string
	e := s.Repository.Transact(ctx, func(st *domain.State) error {
		g := st.Grants[grantID]
		g, e := grantAccessCheck(st, access, grantID, g.FileID, nil)
		if e != nil {
			return e
		}
		raw, e = s.Signer.Mint(g, st.Now)
		if e != nil {
			return e
		}
		addAudit(st, "agent", access.AgentID, g.OwnerID, "delegation.token_issued", g.ID, g.ConnectionID, g.FileID, "allowed", "", 0)
		return nil
	})
	if e != nil {
		return nil, opError(403, "NOT_AUTHORIZED")
	}
	return map[string]string{"delegation_token": raw, "token_type": "Toolbox-Delegation"}, nil
}
func (s *Server) invokeOperation(ctx context.Context, access agentAccess, tool, grantID, fileID, delegationToken string) (map[string]any, error) {
	if tool != domain.Tool || !fileIDPattern.MatchString(fileID) {
		return nil, opError(400, "INVALID_TOOL_OR_RESOURCE")
	}
	ownerID := ""
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	var claims security.Claims
	var grant domain.Grant
	var authorizationErr error
	invocationID := security.ID()
	e := s.Repository.Transact(ctx, func(st *domain.State) error {
		ownerID = st.Agents[access.AgentID].OwnerID
		var verifyErr error
		claims, verifyErr = s.Signer.Verify(delegationToken, st.Now)
		if verifyErr != nil {
			authorizationErr = domain.ErrDenied
		} else {
			grant, authorizationErr = grantAccessCheck(st, access, grantID, fileID, &claims)
		}
		if authorizationErr != nil {
			// Request and token identifiers are untrusted until the entire grant
			// check succeeds. Attribute the denial only to the authenticated owner.
			addAudit(st, "agent", access.AgentID, ownerID, "tool.invocation", "", "", "", "denied", invocationID, 0)
			return nil
		}
		addAudit(st, "agent", access.AgentID, grant.OwnerID, "tool.invocation", grant.ID, grant.ConnectionID, grant.FileID, "started", invocationID, 0)
		return nil
	})
	if e != nil {
		return nil, opError(503, "DEPENDENCY_UNAVAILABLE")
	}
	if authorizationErr != nil {
		return nil, opError(403, safeCode(authorizationErr))
	}
	// Once started is committed every failure path attempts a terminal event.
	// Audit persistence has its own short budget because the provider/caller
	// context may already be cancelled. It never permits content release.
	failInvocation := func(status int, code string) error {
		auditCtx, auditCancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer auditCancel()
		if err := s.Repository.Transact(auditCtx, func(st *domain.State) error {
			addAudit(st, "agent", access.AgentID, ownerID, "tool.invocation", grant.ID, grant.ConnectionID, grant.FileID, "failed", invocationID, 0)
			return nil
		}); err != nil {
			return opError(503, "DEPENDENCY_UNAVAILABLE")
		}
		return opError(status, code)
	}
	authorize := func(ctx context.Context) error {
		return s.Repository.Transact(ctx, func(st *domain.State) error {
			_, e := grantAccessCheck(st, access, grant.ID, fileID, &claims)
			return e
		})
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	case <-ctx.Done():
		return nil, failInvocation(503, "INVOCATION_TIMEOUT")
	}
	result, e := s.integration.Read(ctx, grant.ConnectionID, fileID, authorize)
	if e != nil {
		status := 503
		code := safeCode(e)
		if code != "DEPENDENCY_UNAVAILABLE" {
			status = 403
		}
		if errors.Is(e, connectors.ErrTooLarge) {
			status = 413
			code = "CONTENT_TOO_LARGE"
		}
		return nil, failInvocation(status, code)
	}
	e = s.Repository.Transact(ctx, func(st *domain.State) error {
		_, e := grantAccessCheck(st, access, grant.ID, fileID, &claims)
		if e != nil {
			return e
		}
		addAudit(st, "agent", access.AgentID, grant.OwnerID, "tool.invocation", grant.ID, grant.ConnectionID, grant.FileID, "succeeded", invocationID, len(result.Content))
		return nil
	})
	if e != nil {
		code := safeCode(e)
		status := 403
		if code == "DEPENDENCY_UNAVAILABLE" {
			status = 503
		}
		return nil, failInvocation(status, code)
	}
	return map[string]any{"invocation_id": invocationID, "tool": domain.Tool, "resource": map[string]string{"file_id": result.FileID, "mime_type": "text/plain"}, "content": result.Content, "bytes": len(result.Content), "retrieved_at": result.RetrievedAt, "observed_modified_time": result.ModifiedTime, "untrusted_content": true}, nil
}
