package server

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ufaruq/toolbox/internal/tokens"
)

type PickerConfig struct{ APIKey, ProjectNumber string }

func (s *Server) workspaceConfig(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireOwner(w, r, false); !ok {
		return
	}
	jsonOut(w, 200, map[string]string{"picker_api_key": s.Picker.APIKey, "project_number": s.Picker.ProjectNumber, "policy": "approve_exact_document_read"})
}

// Picker is the sole browser credential boundary. It is owner-only and carries
// the existing account's short-lived token, never its offline refresh token.
func (s *Server) pickerToken(w http.ResponseWriter, r *http.Request) {
	owner, ok := s.requireOwner(w, r, true)
	if !ok {
		return
	}
	var in struct{}
	if !body(w, r, &in) {
		return
	}
	id := r.PathValue("id")
	auth := func(ctx context.Context) error { return s.ownerConnectionCheck(ctx, owner.UserID, owner.ID, id) }
	if err := auth(r.Context()); err != nil {
		fail(w, 403, "NOT_AUTHORIZED")
		return
	}
	if !s.allowed("picker:"+owner.UserID, 30) {
		fail(w, 429, "RATE_LIMITED")
		return
	}
	provider, ok := s.integration.(interface {
		PickerToken(context.Context, string, func(context.Context) error) (tokens.Lease, error)
	})
	if !ok || s.Picker.APIKey == "" || s.Picker.ProjectNumber == "" {
		fail(w, 503, "PICKER_UNAVAILABLE")
		return
	}
	lease, err := provider.PickerToken(r.Context(), id, auth)
	if err != nil || lease.Token == "" || !lease.Expiry.After(time.Now().Add(time.Minute)) {
		fail(w, 503, "CONNECTION_REAUTH_REQUIRED")
		return
	}
	if err := auth(r.Context()); err != nil {
		fail(w, 403, "NOT_AUTHORIZED")
		return
	}
	jsonOut(w, 200, map[string]any{"access_token": lease.Token, "expires_at": lease.Expiry})
}

// Google adds hints to its authorization response. Bound and discard them;
// identity and authority come exclusively from the verified token exchange.
func googleCallbackFields(raw string) (url.Values, bool) {
	if len(raw) > 12288 {
		return nil, false
	}
	values, err := url.ParseQuery(raw)
	if err != nil || len(values) > 20 {
		return nil, false
	}
	for k, vs := range values {
		max := 2048
		if k == "state" {
			max = 256
		}
		if k == "code" {
			max = 4096
		}
		if len(k) == 0 || len(k) > 128 || strings.ContainsAny(k, "\x00\r\n") || len(vs) != 1 || len(vs[0]) > max || strings.ContainsAny(vs[0], "\x00\r\n") {
			return nil, false
		}
	}
	if values.Get("state") == "" || (values.Get("code") == "") == (values.Get("error") == "") {
		return nil, false
	}
	if values.Get("error") == "" && (values.Has("error_description") || values.Has("error_uri")) {
		return nil, false
	}
	if issuer := values.Get("iss"); issuer != "" && issuer != "https://accounts.google.com" {
		return nil, false
	}
	return values, true
}

func (s *Server) workspaceCallback(w http.ResponseWriter, r *http.Request) {
	owner, ok := s.requireOwner(w, r, false)
	if !ok {
		return
	}
	q, ok := googleCallbackFields(r.URL.RawQuery)
	if !ok {
		fail(w, 400, "INVALID_CALLBACK")
		return
	}
	if q.Get("error") != "" {
		provider, ok := s.integration.(interface {
			Reject(context.Context, string, string, string) error
		})
		if !ok || provider.Reject(r.Context(), owner.UserID, owner.ID, q.Get("state")) != nil {
			fail(w, 403, "OAUTH_CALLBACK_REJECTED")
			return
		}
		http.Redirect(w, r, "/#connection=cancelled", http.StatusSeeOther)
		return
	}
	connection, err := s.integration.Complete(r.Context(), owner.UserID, owner.ID, q.Get("state"), q.Get("code"))
	if err != nil {
		http.Redirect(w, r, "/#connection=failed", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/#connection=connected&connection_id="+url.QueryEscape(connection.ID), http.StatusSeeOther)
}
