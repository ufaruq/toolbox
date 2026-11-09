package oidcidp

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestAuthorizeRejectsUnregisteredRedirect(t *testing.T) {
	s := New(t)
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		t.Run(method, func(t *testing.T) {
			q := authorizationForm(s, "https://attacker.example/callback")
			response := authorizeRequest(s, method, q)
			if response.Code != http.StatusBadRequest || response.Header().Get("Location") != "" {
				t.Fatalf("unregistered callback: status=%d location=%q", response.Code, response.Header().Get("Location"))
			}
			if len(s.codes) != 0 {
				t.Fatal("rejected request issued an authorization code")
			}
		})
	}
}

func authorizationForm(s *Server, callback string) url.Values {
	return url.Values{"client_id": {s.ClientID}, "response_type": {"code"}, "redirect_uri": {callback}, "scope": {"openid"}, "state": {"synthetic-state"}, "nonce": {"synthetic-nonce"}, "code_challenge_method": {"S256"}, "code_challenge": {"synthetic-challenge"}, "subject": {"synthetic-owner"}}
}

func authorizeRequest(s *Server, method string, q url.Values) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, "/authorize?"+q.Encode(), nil)
	if method == http.MethodPost {
		request = httptest.NewRequest(method, "/authorize", strings.NewReader(q.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	response := httptest.NewRecorder()
	s.serveHTTP(response, request)
	return response
}

func TestAuthorizeExactRegisteredCallback(t *testing.T) {
	s := New(t)
	const callback = "http://127.0.0.1:18090/auth/oidc/callback?fixture=1"
	s.RegisterCallback(t, callback)
	for _, target := range []string{
		"https://attacker.example/callback",
		"http://127.0.0.1:18091/auth/oidc/callback?fixture=1",
		"http://127.0.0.1:18090/other?fixture=1",
		callback + "&next=https://attacker.example",
		callback + "#fragment",
		"http://127.0.0.1:18090@attacker.example/auth/oidc/callback?fixture=1",
		"http://127.0.0.1:18090\\@attacker.example/auth/oidc/callback?fixture=1",
		"//attacker.example/callback", "", "/auth/oidc/callback",
	} {
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			response := authorizeRequest(s, method, authorizationForm(s, target))
			if response.Code != http.StatusBadRequest || response.Header().Get("Location") != "" {
				t.Fatalf("accepted %s callback %q: %d", method, target, response.Code)
			}
		}
	}
	if len(s.codes) != 0 {
		t.Fatal("rejected request issued a code")
	}
	if got := authorizeRequest(s, http.MethodGet, authorizationForm(s, callback)); got.Code != http.StatusOK {
		t.Fatalf("registered GET status=%d", got.Code)
	}
	// Repeated use must not retain the prior code/state in the configured URL.
	for _, state := range []string{"first-state", "second-state", "https://attacker.example/", "//attacker.example/", "&redirect_uri=https://attacker.example/#fragment", "\r\nLocation: https://attacker.example/", `\\attacker.example\callback`} {
		q := authorizationForm(s, callback)
		q.Set("state", state)
		response := authorizeRequest(s, http.MethodPost, q)
		location, err := url.Parse(response.Header().Get("Location"))
		if err != nil || response.Code != http.StatusFound {
			t.Fatalf("registered POST status=%d, err=%v", response.Code, err)
		}
		if location.Scheme != "http" || location.Host != "127.0.0.1:18090" || location.Path != "/auth/oidc/callback" || location.Query().Get("fixture") != "1" || location.Query().Get("state") != state || location.Query().Get("code") == "" {
			t.Fatalf("incorrect callback: %s", location)
		}
		if auth, ok := s.codes[location.Query().Get("code")]; !ok || auth.redirectURI != callback {
			t.Fatal("authorization code is not bound to registered callback")
		}
	}
}
