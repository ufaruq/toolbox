package server

import (
	"errors"
	"net/http"

	"github.com/ufaruq/toolbox/internal/connectors"
	"github.com/ufaruq/toolbox/internal/domain"
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
	result, e := s.invokeOperation(r.Context(), agentAccess{AgentID: a.ID, CredentialID: credential}, in.Tool, in.GrantID, in.Arguments.FileID, r.Header.Get("Toolbox-Delegation"))
	if e != nil {
		operationFailure(w, e)
		return
	}
	jsonOut(w, 200, result)
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
