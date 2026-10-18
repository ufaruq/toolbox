package server

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/ufaruq/toolbox/internal/connectors"
	"github.com/ufaruq/toolbox/internal/domain"
	"github.com/ufaruq/toolbox/internal/security"
	"github.com/ufaruq/toolbox/internal/tokens"
)

func (s *Server) invoke(w http.ResponseWriter, r *http.Request) {
	a, credential, ok := s.requireAgent(w, r)
	if !ok {
		return
	}
	var in struct {
		Tool      string `json:"tool"`
		GrantID   string `json:"grant_id"`
		Arguments struct {
			FileID string `json:"file_id"`
		} `json:"arguments"`
	}
	if !body(w, r, &in) {
		return
	}
	if in.Tool != domain.Tool || !fileIDPattern.MatchString(in.Arguments.FileID) {
		fail(w, 400, "INVALID_TOOL_OR_RESOURCE")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	var claims security.Claims
	var grant domain.Grant
	invocationID := security.ID()
	e := s.Repository.Transact(ctx, func(st *domain.State) error {
		var e error
		claims, e = s.Signer.Verify(r.Header.Get("Toolbox-Delegation"), st.Now)
		if e != nil {
			return domain.ErrDenied
		}
		grant, e = grantCheck(st, a.ID, credential, in.GrantID, in.Arguments.FileID, &claims)
		if e != nil {
			return e
		}
		addAudit(st, "agent", a.ID, grant.OwnerID, "tool.invocation", grant.ID, grant.ConnectionID, grant.FileID, "started", invocationID, 0)
		return nil
	})
	if e != nil {
		fail(w, 403, safeCode(e))
		return
	}
	authorize := func(ctx context.Context) error {
		return s.Repository.Transact(ctx, func(st *domain.State) error {
			_, e := grantCheck(st, a.ID, credential, grant.ID, in.Arguments.FileID, &claims)
			return e
		})
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	case <-ctx.Done():
		fail(w, 503, "INVOCATION_TIMEOUT")
		return
	}
	result, e := s.integration.Read(ctx, grant.ConnectionID, in.Arguments.FileID, authorize)
	if e != nil {
		_ = s.Repository.Transact(ctx, func(st *domain.State) error {
			addAudit(st, "agent", a.ID, grant.OwnerID, "tool.invocation", grant.ID, grant.ConnectionID, grant.FileID, "failed", invocationID, 0)
			return nil
		})
		status := 503
		code := safeCode(e)
		if code != "DEPENDENCY_UNAVAILABLE" {
			status = 403
		}
		if errors.Is(e, connectors.ErrTooLarge) {
			status = 413
			code = "CONTENT_TOO_LARGE"
		}
		fail(w, status, code)
		return
	}
	e = s.Repository.Transact(ctx, func(st *domain.State) error {
		_, e := grantCheck(st, a.ID, credential, grant.ID, in.Arguments.FileID, &claims)
		if e != nil {
			return e
		}
		addAudit(st, "agent", a.ID, grant.OwnerID, "tool.invocation", grant.ID, grant.ConnectionID, grant.FileID, "succeeded", invocationID, len(result.Content))
		return nil
	})
	if e != nil {
		fail(w, 403, safeCode(e))
		return
	}
	jsonOut(w, 200, map[string]any{"invocation_id": invocationID, "tool": domain.Tool, "resource": map[string]string{"file_id": result.FileID, "mime_type": "text/plain"}, "content": result.Content, "bytes": len(result.Content), "retrieved_at": result.RetrievedAt, "observed_modified_time": result.ModifiedTime, "untrusted_content": true})
}
func safeCode(e error) string {
	if errors.Is(e, connectors.ErrTooLarge) {
		return "CONTENT_TOO_LARGE"
	}
	if errors.Is(e, connectors.ErrRestricted) {
		return "PROVIDER_EXPORT_BLOCKED"
	}
	if errors.Is(e, connectors.ErrUnsupported) {
		return "UNSUPPORTED_RESOURCE"
	}
	if errors.Is(e, connectors.ErrReauth) || errors.Is(e, tokens.ErrReauth) {
		return "CONNECTION_REAUTH_REQUIRED"
	}
	if errors.Is(e, domain.ErrDenied) {
		return "NOT_AUTHORIZED"
	}
	switch e.Error() {
	case "GRANT_REVOKED", "GRANT_EXPIRED", "RESOURCE_NOT_ALLOWED", "CONNECTION_UNAVAILABLE", "CONNECTION_REAUTH_REQUIRED", "PROVIDER_EXPORT_BLOCKED":
		return e.Error()
	}
	return "DEPENDENCY_UNAVAILABLE"
}
