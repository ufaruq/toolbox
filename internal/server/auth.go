package server

import (
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ufaruq/toolbox/internal/domain"
	"github.com/ufaruq/toolbox/internal/ownerlogin"
	"github.com/ufaruq/toolbox/internal/security"
)

func validOwnerOrigin(value string) bool {
	u, err := url.Parse(value)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return false
	}
	ip := net.ParseIP(u.Hostname())
	return u.Port() != "" && (u.Hostname() == "localhost" || ip != nil && ip.IsLoopback())
}

func (s *Server) authConfig(w http.ResponseWriter, _ *http.Request) {
	loginURL := "/fixture/login"
	if s.OwnerOnly {
		loginURL = "/auth/oidc/start"
	}
	jsonOut(w, 200, map[string]any{"fixture": s.Fixture, "owner_only": s.OwnerOnly, "login_url": loginURL})
}

func (s *Server) ownerOrigin(r *http.Request) bool {
	return r.Header.Get("Origin") == s.Origin && r.Header.Get("Sec-Fetch-Site") != "cross-site"
}

func (s *Server) startOwnerLogin(w http.ResponseWriter, r *http.Request) {
	if !s.ownerOrigin(r) {
		fail(w, 403, "NOT_AUTHORIZED")
		return
	}
	var in struct{}
	if !body(w, r, &in) {
		return
	}
	if !s.allowed("owner-login-start", 30) {
		fail(w, 429, "RATE_LIMITED")
		return
	}
	previous := ""
	if _, err := s.owner(r, false); err == nil {
		cookie, _ := r.Cookie("toolbox_session")
		previous = security.Hash(cookie.Value)
	}
	binding := ""
	if cookie, err := r.Cookie("toolbox_login"); err == nil && len(cookie.Value) == 43 {
		binding = cookie.Value
	}
	result, err := s.OwnerLogin.Start(r.Context(), previous, binding)
	if err != nil {
		ownerAuthError(w, err)
		return
	}
	s.authCookie(w, "toolbox_login", result.BrowserToken, 600)
	jsonOut(w, 200, map[string]string{"authorization_url": result.AuthorizationURL})
}

func callbackFields(raw string) (url.Values, bool) {
	if len(raw) > 12288 {
		return nil, false
	}
	values, err := url.ParseQuery(raw)
	if err != nil {
		return nil, false
	}
	for k, vs := range values {
		max := 2048
		switch k {
		case "state":
			max = 256
		case "code":
			max = 4096
		case "error", "error_description", "error_uri", "iss":
		default:
			return nil, false
		}
		if len(vs) != 1 || len(vs[0]) == 0 || len(vs[0]) > max || strings.ContainsAny(vs[0], "\x00\r\n") {
			return nil, false
		}
	}
	if values.Get("state") == "" || (values.Get("code") == "") == (values.Get("error") == "") {
		return nil, false
	}
	if values.Get("error") == "" && (values.Has("error_description") || values.Has("error_uri")) {
		return nil, false
	}
	return values, true
}

func (s *Server) ownerCallback(w http.ResponseWriter, r *http.Request) {
	values, ok := callbackFields(r.URL.RawQuery)
	if !ok {
		fail(w, 400, "INVALID_AUTH_CALLBACK")
		return
	}
	browser, err := r.Cookie("toolbox_login")
	if err != nil || len(browser.Value) != 43 {
		fail(w, 403, "INVALID_AUTH_CALLBACK")
		return
	}
	if issuer := values.Get("iss"); issuer != "" && issuer != s.OwnerLogin.Issuer() {
		fail(w, 403, "INVALID_AUTH_CALLBACK")
		return
	}
	if values.Get("error") != "" {
		err = s.OwnerLogin.Reject(r.Context(), values.Get("state"), browser.Value)
		if err != nil {
			ownerAuthError(w, err)
			return
		}
		s.authCookie(w, "toolbox_login", "", -1)
		fail(w, 403, "SIGN_IN_CANCELLED")
		return
	}
	result, err := s.OwnerLogin.Complete(r.Context(), values.Get("state"), values.Get("code"), browser.Value)
	if err != nil {
		ownerAuthError(w, err)
		return
	}
	s.authCookie(w, "toolbox_session", result.SessionToken, 8*3600)
	s.authCookie(w, "toolbox_login", "", -1)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) logoutOwner(w http.ResponseWriter, r *http.Request) {
	if !s.ownerOrigin(r) {
		fail(w, 403, "NOT_AUTHORIZED")
		return
	}
	var in struct{}
	if !body(w, r, &in) {
		return
	}
	sessionID := ""
	if _, err := s.owner(r, false); err == nil {
		if _, err = s.owner(r, true); err != nil {
			fail(w, 403, "NOT_AUTHORIZED")
			return
		}
		cookie, _ := r.Cookie("toolbox_session")
		sessionID = security.Hash(cookie.Value)
	}
	binding := ""
	if cookie, err := r.Cookie("toolbox_login"); err == nil && len(cookie.Value) == 43 {
		binding = cookie.Value
	}
	if sessionID == "" && binding == "" {
		fail(w, 403, "NOT_AUTHORIZED")
		return
	}
	if err := s.OwnerLogin.Logout(r.Context(), sessionID, binding); err != nil {
		ownerAuthError(w, err)
		return
	}
	s.authCookie(w, "toolbox_session", "", -1)
	s.authCookie(w, "toolbox_login", "", -1)
	status := "signed_out"
	if sessionID == "" {
		status = "login_cancelled"
	}
	jsonOut(w, 200, map[string]string{"status": status})
}

func (s *Server) authCookie(w http.ResponseWriter, name, value string, maxAge int) {
	cookie := &http.Cookie{Name: name, Value: value, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: maxAge}
	// Owner-only HTTP is accepted solely on loopback by New and the executable.
	cookie.Secure = strings.HasPrefix(s.Origin, "https://")
	if maxAge < 0 {
		cookie.Expires = time.Unix(1, 0)
	}
	http.SetCookie(w, cookie)
}

func ownerAuthError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ownerlogin.ErrCapacity):
		fail(w, 429, "RATE_LIMITED")
	case errors.Is(err, domain.ErrDenied), errors.Is(err, ownerlogin.ErrCallback):
		fail(w, 403, "INVALID_AUTH_CALLBACK")
	case errors.Is(err, ownerlogin.ErrProvider):
		fail(w, 502, "IDENTITY_PROVIDER_UNAVAILABLE")
	default:
		fail(w, 503, "AUTH_UNAVAILABLE")
	}
}
