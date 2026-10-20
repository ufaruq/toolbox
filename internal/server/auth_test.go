package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ufaruq/toolbox/internal/domain"
	"github.com/ufaruq/toolbox/internal/ownerlogin"
	"github.com/ufaruq/toolbox/internal/security"
	"github.com/ufaruq/toolbox/internal/store"
	"github.com/ufaruq/toolbox/internal/tokens"
)

const ownerTestOrigin = "http://127.0.0.1:18090"

type httpOwnerProvider struct{}

func (httpOwnerProvider) AuthorizationURL(state, nonce, challenge string) (string, error) {
	u := url.URL{Scheme: "https", Host: "idp.example.test", Path: "/authorize"}
	q := url.Values{"state": {state}, "nonce": {nonce}, "code_challenge": {challenge}}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

type ownerLookupFailure struct {
	domain.Repository
	failAt int
}

func (r *ownerLookupFailure) Transact(ctx context.Context, fn func(*domain.State) error) error {
	r.failAt--
	if r.failAt == 0 {
		return errors.New("temporary repository failure")
	}
	return r.Repository.Transact(ctx, fn)
}

func TestOwnerAuthLookupFailureDoesNotPublishSuccess(t *testing.T) {
	for _, test := range []struct {
		path   string
		failAt int
	}{
		{"/auth/oidc/start", 1}, {"/v1/session/logout", 1}, {"/v1/session/logout", 2},
	} {
		t.Run(fmt.Sprintf("%s/lookup=%d", test.path, test.failAt), func(t *testing.T) {
			api, repo := newOwnerHTTP(t)
			state, binding := beginOwnerHTTP(t, api)
			callback := ownerRequest(api, "GET", "/auth/oidc/callback?state="+url.QueryEscape(state)+"&code=c", "", "", "", binding)
			if callback.Code != 303 {
				t.Fatalf("login failed: %d", callback.Code)
			}
			var session *http.Cookie
			for _, cookie := range callback.Result().Cookies() {
				if cookie.Name == "toolbox_session" {
					session = cookie
				}
			}
			if session == nil {
				t.Fatal("missing session")
			}
			current := ownerRequest(api, "GET", "/v1/session", "", "", "", session)
			var body struct {
				CSRF string `json:"csrf_token"`
			}
			if err := json.Unmarshal(current.Body.Bytes(), &body); err != nil || body.CSRF == "" {
				t.Fatal("missing CSRF")
			}
			pending := ownerRequest(api, "POST", "/auth/oidc/start", "{}", ownerTestOrigin, "", session)
			if pending.Code != 200 {
				t.Fatal("pending login failed")
			}
			binding = pending.Result().Cookies()[0]
			var before int
			if err := repo.Transact(context.Background(), func(st *domain.State) error { before = len(st.OwnerLogins); return nil }); err != nil {
				t.Fatal(err)
			}
			api.Repository = &ownerLookupFailure{Repository: repo, failAt: test.failAt}
			failed := ownerRequest(api, "POST", test.path, "{}", ownerTestOrigin, body.CSRF, session, binding)
			if failed.Code != 503 || len(failed.Result().Cookies()) != 0 {
				t.Fatalf("dependency failure must return 503 without replacing or clearing cookies; got %d", failed.Code)
			}
			if err := repo.Transact(context.Background(), func(st *domain.State) error {
				if len(st.OwnerLogins) != before || !st.Now.Before(st.Sessions[security.Hash(session.Value)].ExpiresAt) {
					t.Fatal("failed request mutated login/session")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if recovered := ownerRequest(api, "POST", "/v1/session/logout", "{}", ownerTestOrigin, body.CSRF, session, binding); recovered.Code != 200 {
				t.Fatalf("logout after recovery: %d", recovered.Code)
			}
			if stale := ownerRequest(api, "GET", "/v1/session", "", "", "", session); stale.Code != 403 {
				t.Fatal("recovered logout left old session live")
			}
		})
	}
}
func (httpOwnerProvider) Exchange(context.Context, string, string, string) (ownerlogin.Identity, error) {
	return ownerlogin.Identity{Issuer: "https://idp.example.test", Subject: "owner-alice"}, nil
}

func newOwnerHTTP(t *testing.T) (*Server, *store.Memory) {
	t.Helper()
	repo := store.NewMemory()
	pepper := bytes.Repeat([]byte("p"), 32)
	login, err := ownerlogin.NewService(repo, tokens.NewMemorySecretStore(), httpOwnerProvider{}, ownerlogin.ServiceConfig{
		Issuer: "https://idp.example.test", ClientID: "owner-client", RedirectURI: ownerTestOrigin + "/auth/oidc/callback", Pepper: pepper,
	})
	if err != nil {
		t.Fatal(err)
	}
	api, err := New(Config{Repository: repo, Origin: ownerTestOrigin, Pepper: pepper, OwnerOnly: true, OwnerLogin: login}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return api, repo
}

func ownerRequest(api *Server, method, path, body, origin, csrf string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, ownerTestOrigin+path, strings.NewReader(body))
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	if csrf != "" {
		r.Header.Set("X-CSRF-Token", csrf)
	}
	for _, c := range cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	api.ServeHTTP(w, r)
	return w
}

func beginOwnerHTTP(t *testing.T, api *Server) (string, *http.Cookie) {
	t.Helper()
	w := ownerRequest(api, "POST", "/auth/oidc/start", "{}", ownerTestOrigin, "")
	if w.Code != 200 {
		t.Fatalf("start status %d: %s", w.Code, w.Body.String())
	}
	var result map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(result["authorization_url"])
	if err != nil {
		t.Fatal(err)
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != "toolbox_login" || !cookies[0].HttpOnly || cookies[0].Secure || cookies[0].SameSite != http.SameSiteLaxMode || cookies[0].Path != "/" || cookies[0].MaxAge != 600 {
		t.Fatal("invalid local binding cookie")
	}
	return u.Query().Get("state"), cookies[0]
}

func TestOwnerAuthHTTP(t *testing.T) {
	api, _ := newOwnerHTTP(t)
	for _, origin := range []string{"", "https://attacker.example"} {
		if w := ownerRequest(api, "POST", "/auth/oidc/start", "{}", origin, ""); w.Code != 403 {
			t.Fatal("cross-origin start accepted")
		}
	}
	if w := ownerRequest(api, "POST", "/auth/oidc/start", `{"user_id":"forged"}`, ownerTestOrigin, ""); w.Code != 400 {
		t.Fatal("caller identity accepted")
	}
	state, binding := beginOwnerHTTP(t, api)
	path := "/auth/oidc/callback?state=" + url.QueryEscape(state) + "&code=test-code"
	if w := ownerRequest(api, "GET", path, "", "", ""); w.Code != 403 {
		t.Fatal("callback without binding accepted")
	}
	wrong := *binding
	wrong.Value = security.Random()
	if w := ownerRequest(api, "GET", path, "", "", "", &wrong); w.Code != 403 {
		t.Fatal("wrong browser accepted")
	}
	if w := ownerRequest(api, "GET", path+"&iss=https%3A%2F%2Fevil.example", "", "", "", binding); w.Code != 403 {
		t.Fatal("wrong response issuer accepted")
	}
	w := ownerRequest(api, "GET", path+"&iss=https%3A%2F%2Fidp.example.test", "", "", "", binding)
	if w.Code != 303 || w.Header().Get("Location") != "/" {
		t.Fatalf("callback failed %d: %s", w.Code, w.Body.String())
	}
	var session *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == "toolbox_session" {
			session = c
		}
	}
	if session == nil || !session.HttpOnly || session.Secure || session.MaxAge != 8*3600 {
		t.Fatal("invalid local session cookie")
	}
	if w := ownerRequest(api, "GET", path, "", "", "", binding); w.Code != 403 {
		t.Fatal("callback replay accepted")
	}
	w = ownerRequest(api, "GET", "/v1/session", "", "", "", session)
	var current struct {
		UserID    string `json:"user_id"`
		CSRF      string `json:"csrf_token"`
		OwnerOnly bool   `json:"owner_only"`
		Fixture   bool   `json:"fixture"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &current) != nil || current.UserID == "" || current.CSRF == "" || !current.OwnerOnly || current.Fixture {
		t.Fatal("verified session unavailable")
	}
	pending := ownerRequest(api, "POST", "/auth/oidc/start", "{}", ownerTestOrigin, "", session)
	if pending.Code != 200 {
		t.Fatal("authenticated login start failed")
	}
	var pendingBinding *http.Cookie
	for _, c := range pending.Result().Cookies() {
		if c.Name == "toolbox_login" {
			pendingBinding = c
		}
	}
	if pendingBinding == nil {
		t.Fatal("missing pending binding")
	}
	if w := ownerRequest(api, "POST", "/v1/session/logout", "{}", ownerTestOrigin, "wrong", session, pendingBinding); w.Code != 403 {
		t.Fatal("pending login bypassed active session CSRF")
	}
	if w := ownerRequest(api, "POST", "/v1/session/logout", "{}", ownerTestOrigin, "wrong", session); w.Code != 403 {
		t.Fatal("logout CSRF accepted")
	}
	if w := ownerRequest(api, "POST", "/v1/session/logout", "{}", "https://evil.example", current.CSRF, session); w.Code != 403 {
		t.Fatal("cross-origin logout accepted")
	}
	if w := ownerRequest(api, "POST", "/v1/session/logout", "{}", ownerTestOrigin, current.CSRF, session); w.Code != 200 {
		t.Fatalf("logout failed %d", w.Code)
	}
	if w := ownerRequest(api, "GET", "/v1/session", "", "", "", session); w.Code != 403 {
		t.Fatal("logged-out cookie still works")
	}
}

func TestOwnerCallbackFields(t *testing.T) {
	for _, raw := range []string{"", "state=s", "state=s&code=c&code=d", "state=s&code=c&error=e", "state=s&code=c&user_id=x", "state=s&code=c&error_description=e", "state=s&code=%0A", "state=s&error=", "state=s&code=c&iss=x&iss=x", "state=s&code=" + strings.Repeat("x", 4097), "state=%zz&code=x"} {
		if _, ok := callbackFields(raw); ok {
			t.Fatalf("accepted malformed callback %q", raw[:min(len(raw), 100)])
		}
	}
	for _, raw := range []string{"state=s&code=c", "state=s&error=access_denied", "state=s&error=access_denied&error_description=Denied&error_uri=https%3A%2F%2Fexample.test"} {
		if _, ok := callbackFields(raw); !ok {
			t.Fatal("valid callback shape rejected")
		}
	}
}

func TestOwnerOnlyRejectsFixtureAndToolAPIs(t *testing.T) {
	api, repo := newOwnerHTTP(t)
	fixtureToken := security.Random()
	if err := repo.Transact(context.Background(), func(st *domain.State) error {
		st.Users["old"] = domain.User{ID: "old", Issuer: "fixture://local", Subject: "old", Status: "active"}
		st.Sessions[security.Hash(fixtureToken)] = domain.Session{ID: security.Hash(fixtureToken), UserID: "old", CSRFHash: "old", ExpiresAt: st.Now.Add(time.Hour)}
		st.Agents["a"] = domain.Agent{ID: "a", OwnerID: "old", Name: "old agent", Status: "active"}
		st.Credentials["c"] = domain.Credential{ID: "c", AgentID: "a", Hash: "hash", Status: "active", ExpiresAt: st.Now.Add(time.Hour)}
		st.Connections["c"] = domain.Connection{ID: "c", OwnerID: "old", Provider: "google_drive", Subject: "old", ClientID: "fixture", Status: "active", Epoch: 1}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if w := ownerRequest(api, "GET", "/v1/session", "", "", "", &http.Cookie{Name: "toolbox_session", Value: fixtureToken}); w.Code != 403 {
		t.Fatal("fixture session accepted as verified OIDC identity")
	}
	for _, path := range []string{"/v1/agents", "/v1/agents/a/credentials", "/v1/credentials/c/revoke", "/v1/connections", "/v1/connections/google/start", "/v1/connections/c/disconnect", "/v1/delegation-requests", "/v1/delegation-requests/a/review", "/v1/delegation-tokens", "/v1/grants/g/revoke", "/v1/tool-invocations", "/v1/audit", "/oauth/callback"} {
		for _, method := range []string{"GET", "POST"} {
			if w := ownerRequest(api, method, path, "{}", ownerTestOrigin, ""); w.Code != 503 || !strings.Contains(w.Body.String(), "FEATURE_DISABLED") {
				t.Fatalf("enabled operation %s %s: %d", method, path, w.Code)
			}
		}
	}
	for _, path := range []string{"/fixture/login", "/fixture/authorize"} {
		if w := ownerRequest(api, "POST", path, "{}", ownerTestOrigin, ""); w.Code != 404 && w.Code != 405 {
			t.Fatal("fixture route exposed")
		}
	}
	if w := ownerRequest(api, "GET", "/v1/auth/config?extra=x", "", "", ""); w.Code != 400 {
		t.Fatal("unexpected query accepted")
	}
	if w := ownerRequest(api, "GET", "/v1/auth/config", "", "", ""); w.Code != 200 || strings.Contains(w.Body.String(), "secret") {
		t.Fatal("invalid public config")
	}
	if err := repo.Transact(context.Background(), func(st *domain.State) error {
		if len(st.Agents) != 1 || len(st.Credentials) != 1 || len(st.Connections) != 1 || len(st.OwnerLogins) != 0 {
			t.Fatal("disabled API mutated state")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestOwnerLoginCancellationAndRateLimit(t *testing.T) {
	api, _ := newOwnerHTTP(t)
	state, binding := beginOwnerHTTP(t, api)
	if w := ownerRequest(api, "POST", "/v1/session/logout", "{}", ownerTestOrigin, "", binding); w.Code != 200 {
		t.Fatal("bound cancellation failed")
	}
	if w := ownerRequest(api, "GET", "/auth/oidc/callback?state="+url.QueryEscape(state)+"&code=c", "", "", "", binding); w.Code != 403 {
		t.Fatal("cancelled callback accepted")
	}
	for i := 1; i < 30; i++ {
		beginOwnerHTTP(t, api)
	}
	if w := ownerRequest(api, "POST", "/auth/oidc/start", "{}", ownerTestOrigin, ""); w.Code != 429 {
		t.Fatal("login flood accepted")
	}
}
