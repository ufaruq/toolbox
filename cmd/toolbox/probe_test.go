package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ufaruq/toolbox/internal/oauth"
)

type syntheticProbe struct{ started, completed int }

func (p *syntheticProbe) Begin() (string, error) {
	p.started++
	return "https://accounts.google.com/o/oauth2/v2/auth?state=one-use", nil
}
func (p *syntheticProbe) Complete(context.Context, string, string) (oauth.ProbeStatus, error) {
	p.completed++
	return oauth.ProbeStatus{Completed: 1}, nil
}
func (p *syntheticProbe) Status() oauth.ProbeStatus { return oauth.ProbeStatus{} }

func TestProbeHTTPBindsBrowserAndOriginAndCleansCallbackURL(t *testing.T) {
	p := &syntheticProbe{}
	h := newProbeHandler("http://127.0.0.1:8080", p)
	call := func(method, path, origin string, cookie *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "http://127.0.0.1:8080"+path, strings.NewReader(""))
		r.Header.Set("Origin", origin)
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	page := call("GET", "/", "", nil)
	if page.Code != 200 || len(page.Result().Cookies()) != 1 {
		t.Fatal("probe did not establish private browser binding")
	}
	cookie := page.Result().Cookies()[0]
	for _, origin := range []string{"", "https://evil.test"} {
		if w := call("POST", "/probe/start", origin, cookie); w.Code != 403 || p.started != 0 {
			t.Fatal("cross-origin probe started")
		}
	}
	if w := call("POST", "/probe/start", "http://127.0.0.1:8080", cookie); w.Code != 200 || p.started != 1 {
		t.Fatal("probe did not start")
	}
	if w := call("GET", "/oauth/callback?state=one-use&code=secret-code", "", nil); w.Code != 403 || p.completed != 0 {
		t.Fatal("unbound probe callback accepted")
	}
	w := call("GET", "/oauth/callback?state=one-use&code=secret-code&authuser=0", "", cookie)
	if w.Code != 303 || w.Header().Get("Location") != "/" || p.completed != 1 || strings.Contains(w.Body.String(), "secret-code") {
		t.Fatal("probe callback leaked code or failed")
	}
}
