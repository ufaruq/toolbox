package server

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ufaruq/toolbox/internal/domain"
	"github.com/ufaruq/toolbox/internal/security"
	"github.com/ufaruq/toolbox/internal/tokens"
)

type workspaceBoundary struct {
	Integration
	completed, rejected, leased int
	afterLease                  func()
}

func (b *workspaceBoundary) Complete(context.Context, string, string, string, string) (domain.Connection, error) {
	b.completed++
	return domain.Connection{ID: "connected-id"}, nil
}
func (b *workspaceBoundary) Reject(context.Context, string, string, string) error {
	b.rejected++
	return nil
}
func (b *workspaceBoundary) PickerToken(ctx context.Context, id string, auth func(context.Context) error) (tokens.Lease, error) {
	if err := auth(ctx); err != nil {
		return tokens.Lease{}, err
	}
	b.leased++
	if b.afterLease != nil {
		b.afterLease()
	}
	return tokens.Lease{Token: "owner-picker-access", Expiry: time.Now().Add(time.Hour)}, nil
}

func newWorkspaceHTTP(t *testing.T) (*Server, *workspaceBoundary, *http.Cookie, string) {
	t.Helper()
	owner, repo := newOwnerHTTP(t)
	b := &workspaceBoundary{}
	signer, err := security.NewSigner(ownerTestOrigin, "workspace", ed25519.NewKeyFromSeed(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	api, err := New(Config{Repository: repo, Origin: ownerTestOrigin, Pepper: []byte(strings.Repeat("c", 32)), SessionPepper: owner.Pepper, Signer: signer, WorkspaceLocal: true, OwnerLogin: owner.OwnerLogin, Picker: PickerConfig{APIKey: "picker-key", ProjectNumber: "123456"}}, b)
	if err != nil {
		t.Fatal(err)
	}
	state, binding := beginOwnerHTTP(t, api)
	callback := ownerRequest(api, "GET", "/auth/oidc/callback?state="+state+"&code=test", "", "", "", binding)
	if callback.Code != 303 {
		t.Fatal("owner login failed", callback.Code)
	}
	var cookie *http.Cookie
	for _, c := range callback.Result().Cookies() {
		if c.Name == "toolbox_session" {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("missing owner cookie")
	}
	session := ownerRequest(api, "GET", "/v1/session", "", "", "", cookie)
	var current struct {
		CSRF  string `json:"csrf_token"`
		Owner string `json:"user_id"`
	}
	if err := json.Unmarshal(session.Body.Bytes(), &current); err != nil {
		t.Fatal(err)
	}
	if err := repo.Transact(context.Background(), func(st *domain.State) error {
		st.Users["other-owner"] = domain.User{ID: "other-owner", Issuer: "https://idp.example.test", Subject: "other", Status: "active"}
		for _, c := range []domain.Connection{
			{ID: "own", OwnerID: current.Owner, Provider: "google_drive", Subject: "google-sub", ClientID: "client", Status: "active", Epoch: 1, Scopes: []string{"openid", "email", domain.DriveScope}},
			{ID: "other", OwnerID: "other-owner", Provider: "google_drive", Subject: "other-google", ClientID: "client", Epoch: 1, Status: "active", Scopes: []string{domain.DriveScope}},
		} {
			st.Connections[c.ID] = c
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return api, b, cookie, current.CSRF
}

func TestWorkspaceGoogleCallbackAcceptsHintsWithoutTrustingThem(t *testing.T) {
	api, b, cookie, _ := newWorkspaceHTTP(t)
	w := ownerRequest(api, "GET", "/oauth/callback?state=bound&code=one-use&scope=openid+email&authuser=0&hd=example.test&prompt=consent&future_hint=ignored", "", "", "", cookie)
	if w.Code != 303 || !strings.HasPrefix(w.Header().Get("Location"), "/#connection=connected") || b.completed != 1 {
		t.Fatal("real Google response rejected", w.Code)
	}
	for _, query := range []string{"state=x&state=y&code=c", "state=x&code=c&error=access_denied", "state=x&code=c&iss=https://evil.test", "state=x&code=c&code=d", "state=x&code=c&broken=%GG"} {
		w = ownerRequest(api, "GET", "/oauth/callback?"+query, "", "", "", cookie)
		if w.Code < 400 || b.completed != 1 {
			t.Fatal("ambiguous callback accepted", query)
		}
	}
	w = ownerRequest(api, "GET", "/oauth/callback?state=bound&error=access_denied&error_description=untrusted", "", "", "", cookie)
	if w.Code != 303 || w.Header().Get("Location") != "/#connection=cancelled" || b.rejected != 1 || b.completed != 1 {
		t.Fatal("cancellation not consumed safely")
	}
}

func TestPickerTokenRequiresOwnerCSRFAndLiveConnection(t *testing.T) {
	api, b, cookie, csrf := newWorkspaceHTTP(t)
	for _, tc := range []struct {
		path, origin, csrf string
		cookie             *http.Cookie
	}{
		{"own", ownerTestOrigin, csrf, nil}, {"own", ownerTestOrigin, "wrong", cookie}, {"own", "https://evil.test", csrf, cookie}, {"other", ownerTestOrigin, csrf, cookie},
	} {
		var cookies []*http.Cookie
		if tc.cookie != nil {
			cookies = append(cookies, tc.cookie)
		}
		w := ownerRequest(api, "POST", "/v1/connections/"+tc.path+"/picker-token", "{}", tc.origin, tc.csrf, cookies...)
		if w.Code != 403 || strings.Contains(w.Body.String(), "owner-picker-access") || b.leased != 0 {
			t.Fatal("picker credential escaped authorization", w.Code)
		}
	}
	w := ownerRequest(api, "POST", "/v1/connections/own/picker-token", "{}", ownerTestOrigin, csrf, cookie)
	var result struct {
		Access string    `json:"access_token"`
		Expiry time.Time `json:"expires_at"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil || result.Access != "owner-picker-access" || !result.Expiry.After(time.Now()) || strings.Contains(w.Body.String(), "refresh") || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("invalid Picker credential response", w.Code)
	}
	b.afterLease = func() {
		_ = api.Repository.Transact(context.Background(), func(st *domain.State) error {
			c := st.Connections["own"]
			c.Status = "disconnecting"
			st.Connections[c.ID] = c
			return nil
		})
	}
	w = ownerRequest(api, "POST", "/v1/connections/own/picker-token", "{}", ownerTestOrigin, csrf, cookie)
	if w.Code != 403 || strings.Contains(w.Body.String(), "owner-picker-access") {
		t.Fatal("disconnect during lease released a token")
	}
}

func TestWorkspaceServesConnectorUIInsteadOfFixture(t *testing.T) {
	api, _, _, _ := newWorkspaceHTTP(t)
	w := ownerRequest(api, "GET", "/", "", "", " ")
	if w.Code != 200 || strings.Contains(w.Body.String(), "fixture owner") || !strings.Contains(w.Body.String(), "Choose a connector") {
		t.Fatal("live runtime serves fixture UI")
	}
}
