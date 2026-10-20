package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ufaruq/toolbox/internal/domain"
	"github.com/ufaruq/toolbox/internal/identity"
	"github.com/ufaruq/toolbox/internal/security"
)

type testIdentity struct {
	state, nonce, verifier string
	exchanges              int
	reject                 bool
}

func (i *testIdentity) VerifyAccess(context.Context, string) (identity.Claims, error) {
	return identity.Claims{}, errors.New("unused")
}
func (i *testIdentity) Clients() map[string]string {
	return map[string]string{"web": "ChatGPT Web", "code": "Codex"}
}
func (i *testIdentity) Issuer() string { return "https://okta.test/oauth2/default" }
func (i *testIdentity) AuthorizationURL(state, nonce, verifier string) (string, error) {
	i.state = state
	i.nonce = nonce
	i.verifier = verifier
	return "https://okta.test/authorize?state=" + url.QueryEscape(state), nil
}
func (i *testIdentity) Complete(_ context.Context, code, verifier, nonceHash string) (identity.Owner, error) {
	i.exchanges++
	if i.reject || code != "code" || verifier != i.verifier || nonceHash != security.Hash(i.nonce) {
		return identity.Owner{}, errors.New("rejected")
	}
	return identity.Owner{Issuer: i.Issuer(), UserID: "uid-owner"}, nil
}
func callerFixture(t *testing.T) (*Server, *invocationAuditRepository, *http.Request, *testIdentity) {
	t.Helper()
	idp := &testIdentity{}
	s, repo, r := invocationFixture(t, domain.User{ID: "owner", Issuer: idp.Issuer(), Subject: "uid-owner", Status: "active"})
	s.Identity = idp
	e := repo.Transact(context.Background(), func(st *domain.State) error {
		u := st.Users["owner"]
		u.Issuer = idp.Issuer()
		u.Subject = "uid-owner"
		st.Users[u.ID] = u
		st.CallerProfiles["web-profile"] = domain.CallerProfile{ID: "web-profile", OwnerID: "owner", AgentID: "agent", Issuer: u.Issuer, UserID: u.Subject, ClientID: "web", Label: "Web", Status: "active", Tools: []string{domain.Tool}, ApprovedAt: st.Now.Add(-time.Hour), ExpiresAt: st.Now.Add(time.Hour)}
		st.Agents["code-agent"] = domain.Agent{ID: "code-agent", OwnerID: u.ID, Name: "Code", Status: "active"}
		st.CallerProfiles["code-profile"] = domain.CallerProfile{ID: "code-profile", OwnerID: u.ID, AgentID: "code-agent", Issuer: u.Issuer, UserID: u.Subject, ClientID: "code", Label: "Code", Status: "active", Tools: []string{domain.Tool}, ApprovedAt: st.Now.Add(-time.Hour), ExpiresAt: st.Now.Add(time.Hour)}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	return s, repo, r, idp
}
func ownerCookie(t *testing.T, s *Server, ownerID string) (*http.Cookie, string) {
	t.Helper()
	raw := security.Random()
	csrf := security.KeyedHash(s.Pepper, raw)
	e := s.Repository.Transact(context.Background(), func(st *domain.State) error {
		st.Sessions[security.Hash(raw)] = domain.Session{ID: security.Hash(raw), UserID: ownerID, CSRFHash: security.Hash(csrf), ExpiresAt: st.Now.Add(time.Hour)}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	return &http.Cookie{Name: "toolbox_session", Value: raw}, csrf
}
func ownerPost(s *Server, path, body string, cookie *http.Cookie, csrf string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", path, strings.NewReader(body))
	r.AddCookie(cookie)
	r.Header.Set("Origin", s.Origin)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", csrf)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}
func TestCallerSeparatesClientsAndRejectsCrossOwner(t *testing.T) {
	s, repo, _, idp := callerFixture(t)
	ctx := context.Background()
	web, e := s.resolveCaller(ctx, identity.Claims{Issuer: idp.Issuer(), UserID: "uid-owner", ClientID: "web", ExpiresAt: time.Now().Add(time.Hour)})
	if e != nil {
		t.Fatal(e)
	}
	code, e := s.resolveCaller(ctx, identity.Claims{Issuer: idp.Issuer(), UserID: "uid-owner", ClientID: "code", ExpiresAt: time.Now().Add(time.Hour)})
	if e != nil {
		t.Fatal(e)
	}
	if web.AgentID == code.AgentID {
		t.Fatal("web and Code share an agent")
	}
	if _, e = s.mintDelegation(ctx, code, "grant"); e == nil {
		t.Fatal("Code minted Web grant")
	}
	if _, e = s.resolveCaller(ctx, identity.Claims{Issuer: idp.Issuer(), UserID: "other-owner", ClientID: "web", ExpiresAt: time.Now().Add(time.Hour)}); e == nil {
		t.Fatal("cross owner caller authenticated")
	}
	e = repo.Transact(ctx, func(st *domain.State) error {
		if authorizeAgent(st, agentAccess{AgentID: "agent"}, domain.Tool) == nil {
			t.Fatal("empty credential bypass")
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
}
func TestCallerFinalReleaseChecksLiveTokenAndProfile(t *testing.T) {
	for _, mutation := range []string{"disable", "token-expiry", "profile-expiry", "tool-removal"} {
		t.Run(mutation, func(t *testing.T) {
			s, repo, r, idp := callerFixture(t)
			access, e := s.resolveCaller(context.Background(), identity.Claims{Issuer: idp.Issuer(), UserID: "uid-owner", ClientID: "web", ExpiresAt: time.Now().Add(time.Hour)})
			if e != nil {
				t.Fatal(e)
			}
			if mutation == "token-expiry" {
				access.TokenExpiresAt = time.Now().Add(time.Minute)
			}
			s.integration = invocationIntegration{read: func(ctx context.Context, auth func(context.Context) error) (Document, error) {
				if e := auth(ctx); e != nil {
					return Document{}, e
				}
				if mutation == "token-expiry" {
					s.Repository = &loginClockRepository{Repository: repo, now: access.TokenExpiresAt.Add(time.Second)}
				} else {
					if e := repo.Transact(ctx, func(st *domain.State) error {
						p := st.CallerProfiles["web-profile"]
						switch mutation {
						case "disable":
							p.Status = "disabled"
						case "profile-expiry":
							p.ExpiresAt = st.Now.Add(-time.Millisecond)
						case "tool-removal":
							p.Tools = nil
						}
						st.CallerProfiles[p.ID] = p
						return nil
					}); e != nil {
						t.Fatal(e)
					}
				}
				return Document{Content: "private document"}, nil
			}}
			result, e := s.invokeOperation(context.Background(), access, domain.Tool, "grant", "doc-A", r.Header.Get("Toolbox-Delegation"))
			if e == nil || result != nil {
				t.Fatalf("released content after %s: %+v %v", mutation, result, e)
			}
			requireFailedInvocation(t, repo)
		})
	}
}
func TestOpaqueCredentialUsesLinkedProfileCeiling(t *testing.T) {
	s, repo, r, _ := callerFixture(t)
	if e := repo.Transact(context.Background(), func(st *domain.State) error {
		p := st.CallerProfiles["web-profile"]
		p.Tools = nil
		st.CallerProfiles[p.ID] = p
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	s.integration = invocationIntegration{read: func(context.Context, func(context.Context) error) (Document, error) {
		t.Fatal("provider called beyond ceiling")
		return Document{}, nil
	}}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("opaque linked tool removal = %d %s", w.Code, w.Body)
	}
}
func TestCallerMutationCSRFAndOwnerIsolationAndEnable(t *testing.T) {
	s, repo, _, _ := callerFixture(t)
	cookie, csrf := ownerCookie(t, s, "owner")
	if w := ownerPost(s, "/v1/callers/web-profile/disable", "{}", cookie, ""); w.Code != 403 {
		t.Fatalf("missing CSRF: %d", w.Code)
	}
	if e := repo.Transact(context.Background(), func(st *domain.State) error {
		st.Users["other"] = domain.User{ID: "other", Issuer: "other", Subject: "other", Status: "active"}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	other, otherCSRF := ownerCookie(t, s, "other")
	if w := ownerPost(s, "/v1/callers/web-profile/disable", "{}", other, otherCSRF); w.Code != 403 {
		t.Fatalf("cross-owner disable: %d", w.Code)
	}
	// Enable must revoke/cancel even if the profile was still active.
	q, e := s.createDelegation(context.Background(), agentAccess{AgentID: "agent", CallerProfileID: "web-profile", TokenExpiresAt: time.Now().Add(time.Hour)}, domain.Tool, "doc-A", 300)
	if e != nil {
		t.Fatal(e)
	}
	if w := ownerPost(s, "/v1/callers/web-profile/disable", "{}", cookie, csrf); w.Code != 200 {
		t.Fatalf("disable: %d %s", w.Code, w.Body)
	}
	if w := ownerPost(s, "/v1/callers/web-profile/enable", `{"tools":["`+domain.Tool+`"],"duration_seconds":3600}`, cookie, csrf); w.Code != 200 {
		t.Fatalf("enable: %d %s", w.Code, w.Body)
	}
	if e := repo.Transact(context.Background(), func(st *domain.State) error {
		p := st.CallerProfiles["web-profile"]
		if p.Status != "active" || st.Agents[p.AgentID].Status != "active" {
			t.Fatal("enable did not restore identity")
		}
		if st.Grants["grant"].RevokedAt == nil || st.Requests[q["request_id"].(string)].Status != "cancelled" {
			t.Fatal("old rights resurrected")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
}

func TestCallerRenameUpdatesReviewWithoutChangingAccess(t *testing.T) {
	s, repo, _, idp := callerFixture(t)
	cookie, csrf := ownerCookie(t, s, "owner")
	access, err := s.resolveCaller(context.Background(), identity.Claims{Issuer: idp.Issuer(), UserID: "uid-owner", ClientID: "web", ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	request, err := s.createDelegation(context.Background(), access, domain.Tool, "doc-A", 300)
	if err != nil {
		t.Fatal(err)
	}
	var expiry time.Time
	if err := repo.Transact(context.Background(), func(st *domain.State) error {
		expiry = st.CallerProfiles["web-profile"].ExpiresAt
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if w := ownerPost(s, "/v1/callers/web-profile/name", `{"label":"Codex local"}`, cookie, csrf); w.Code != 200 {
		t.Fatalf("rename: %d %s", w.Code, w.Body)
	}
	if err := repo.Transact(context.Background(), func(st *domain.State) error {
		p := st.CallerProfiles["web-profile"]
		if p.Label != "Codex local" || st.Agents[p.AgentID].Name != "Codex local" || p.AgentID != "agent" || p.ClientID != "web" || !p.ExpiresAt.Equal(expiry) || p.Status != "active" || len(p.Tools) != 1 || p.Tools[0] != domain.Tool {
			t.Fatal("rename lost the saved name or changed caller permissions")
		}
		if st.Grants["grant"].RevokedAt != nil || st.Requests[request["request_id"].(string)].Status != "pending" {
			t.Fatal("renaming invalidated document access")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.mintDelegation(context.Background(), access, "grant"); err != nil {
		t.Fatalf("existing access failed after rename: %v", err)
	}
	s.integration = approvalIntegration{inspect: func(ctx context.Context, authorize func(context.Context) error) (Document, error) {
		return Document{Name: "Test document"}, authorize(ctx)
	}}
	w := ownerPost(s, "/v1/delegation-requests/"+request["request_id"].(string)+"/review", `{"connection_id":"connection"}`, cookie, csrf)
	var review struct {
		AgentName string `json:"agent_name"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &review) != nil || review.AgentName != "Codex local" {
		t.Fatalf("review lost the saved name: %d %s", w.Code, w.Body)
	}
}

func TestCallerRenameRequiresOwnerAndValidLabel(t *testing.T) {
	for _, tc := range []struct {
		name, body, owner string
		csrf              bool
		status            int
	}{
		{"missing csrf", `{"label":"New name"}`, "owner", false, 403},
		{"different owner", `{"label":"New name"}`, "other", true, 403},
		{"empty", `{"label":""}`, "owner", true, 400},
		{"blank", `{"label":"   "}`, "owner", true, 400},
		{"oversized", `{"label":"` + strings.Repeat("x", 81) + `"}`, "owner", true, 400},
		{"control character", `{"label":"Bad\nname"}`, "owner", true, 400},
		{"identity override", `{"label":"New name","client_id":"code"}`, "owner", true, 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, repo, _, _ := callerFixture(t)
			if err := repo.Transact(context.Background(), func(st *domain.State) error {
				st.Users["other"] = domain.User{ID: "other", Issuer: "other", Subject: "other", Status: "active"}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			cookie, csrf := ownerCookie(t, s, tc.owner)
			if !tc.csrf {
				csrf = ""
			}
			w := ownerPost(s, "/v1/callers/web-profile/name", tc.body, cookie, csrf)
			if w.Code != tc.status {
				t.Fatalf("rename rejection: %d %s", w.Code, w.Body)
			}
			if err := repo.Transact(context.Background(), func(st *domain.State) error {
				if st.CallerProfiles["web-profile"].Label != "Web" {
					t.Fatal("rejected rename changed the caller")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestCallerCreateAcceptsOnlyConfiguredClientAndIgnoresOwnerInputs(t *testing.T) {
	s, _, _, _ := callerFixture(t)
	cookie, csrf := ownerCookie(t, s, "owner")
	for _, data := range []string{`{"client_id":"unknown","label":"X","tools":["` + domain.Tool + `"],"duration_seconds":3600}`, `{"client_id":"web","label":"X","owner_id":"other","tools":["` + domain.Tool + `"],"duration_seconds":3600}`} {
		w := ownerPost(s, "/v1/callers", data, cookie, csrf)
		if w.Code != 400 {
			t.Fatalf("invalid client/owner input: %d %s", w.Code, w.Body)
		}
	}
}

func TestCallerAcceptsExplicitEmptyCeilingAndThirtyDayExpiry(t *testing.T) {
	s, repo, _ := invocationFixture(t, domain.User{ID: "owner", Issuer: (&testIdentity{}).Issuer(), Subject: "uid-owner", Status: "active"})
	idp := &testIdentity{}
	s.Identity = idp
	if e := repo.Transact(context.Background(), func(st *domain.State) error {
		u := st.Users["owner"]
		u.Issuer = idp.Issuer()
		u.Subject = "uid-owner"
		st.Users[u.ID] = u
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	cookie, csrf := ownerCookie(t, s, "owner")
	w := ownerPost(s, "/v1/callers", `{"client_id":"web","label":"Web","tools":[],"duration_seconds":2592000}`, cookie, csrf)
	if w.Code != 201 {
		t.Fatalf("explicit empty ceiling/30-day profile = %d %s", w.Code, w.Body)
	}
}
func TestSharedOperationRequestRateLimit(t *testing.T) {
	s, _, r, _ := callerFixture(t)
	a, cred, e := s.agent(r)
	if e != nil {
		t.Fatal(e)
	}
	for n := 0; n < 11; n++ {
		_, e := s.createDelegation(context.Background(), agentAccess{AgentID: a.ID, CredentialID: cred}, domain.Tool, "doc-A", 30)
		if n == 10 {
			var oe *operationError
			if !errors.As(e, &oe) || oe.Status != 429 {
				t.Fatalf("request %d not rate limited: %v", n, e)
			}
		} else if e != nil {
			t.Fatal(e)
		}
	}
}

type unavailableUIIntegration struct{ Integration }

func (unavailableUIIntegration) Available() bool { return false }
func TestBootstrapReportsUnavailableGoogle(t *testing.T) {
	s, _, _ := invocationFixture(t)
	s.integration = unavailableUIIntegration{}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest("GET", "/v1/config", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"google_available":false`) {
		t.Fatalf("unavailable integration metadata: %d %s", w.Code, w.Body)
	}
}

func TestCallerAuditRecordsVerifiedClientAndAgentWithoutSecrets(t *testing.T) {
	s, repo, _, idp := callerFixture(t)
	access, e := s.resolveCaller(context.Background(), identity.Claims{Issuer: idp.Issuer(), UserID: "uid-owner", ClientID: "web", ExpiresAt: time.Now().Add(time.Hour)})
	if e != nil {
		t.Fatal(e)
	}
	if _, e := s.createDelegation(context.Background(), access, domain.Tool, "doc-A", 300); e != nil {
		t.Fatal(e)
	}
	events := invocationEvents(t, repo)
	encoded, e := json.Marshal(events)
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(string(encoded), `"AgentID":"agent"`) || !strings.Contains(string(encoded), `"CallerProfileID":"web-profile"`) || !strings.Contains(string(encoded), `"ClientID":"web"`) {
		t.Fatalf("missing verified caller attribution: %s", encoded)
	}
	for _, secret := range []string{"access_token", "refresh_token", "delegation_token", "private document"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("secret in audit: %s", secret)
		}
	}
}

type approvalIntegration struct {
	Integration
	inspect func(context.Context, func(context.Context) error) (Document, error)
}

func (i approvalIntegration) Inspect(ctx context.Context, _, _ string, auth func(context.Context) error) (Document, error) {
	return i.inspect(ctx, auth)
}
func TestPendingApprovalRechecksProfileAfterProviderWork(t *testing.T) {
	s, repo, _, idp := callerFixture(t)
	cookie, csrf := ownerCookie(t, s, "owner")
	access, e := s.resolveCaller(context.Background(), identity.Claims{Issuer: idp.Issuer(), UserID: "uid-owner", ClientID: "web", ExpiresAt: time.Now().Add(time.Hour)})
	if e != nil {
		t.Fatal(e)
	}
	result, e := s.createDelegation(context.Background(), access, domain.Tool, "doc-A", 300)
	if e != nil {
		t.Fatal(e)
	}
	var approval string
	if e := repo.Transact(context.Background(), func(st *domain.State) error {
		q := st.Requests[result["request_id"].(string)]
		approval = approvalDigest(q, st.Connections["connection"])
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	s.integration = approvalIntegration{inspect: func(ctx context.Context, _ func(context.Context) error) (Document, error) {
		e := repo.Transact(ctx, func(st *domain.State) error {
			p := st.CallerProfiles["web-profile"]
			p.Tools = nil
			st.CallerProfiles[p.ID] = p
			return nil
		})
		return Document{Name: "A", MIME: "application/vnd.google-apps.document"}, e
	}}
	w := ownerPost(s, "/v1/delegation-requests/"+result["request_id"].(string)+"/approve", `{"connection_id":"connection","version":1,"digest":"`+approval+`"}`, cookie, csrf)
	if w.Code != 403 {
		t.Fatalf("approved after ceiling removed: %d %s", w.Code, w.Body)
	}
	if e := repo.Transact(context.Background(), func(st *domain.State) error {
		if st.Requests[result["request_id"].(string)].Status != "pending" {
			t.Fatal("stale request approved")
		}
		if len(st.Grants) != 1 {
			t.Fatal("stale request created grant")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
}

func TestEnableRestoresAllValidMatchingTokensWithoutRights(t *testing.T) {
	s, _, _, idp := callerFixture(t)
	cookie, csrf := ownerCookie(t, s, "owner")
	claims := []identity.Claims{{Issuer: idp.Issuer(), UserID: "uid-owner", ClientID: "web", ExpiresAt: time.Now().Add(time.Hour)}, {Issuer: idp.Issuer(), UserID: "uid-owner", ClientID: "web", ExpiresAt: time.Now().Add(30 * time.Minute)}}
	for _, c := range claims {
		if _, e := s.resolveCaller(context.Background(), c); e != nil {
			t.Fatal(e)
		}
	}
	if w := ownerPost(s, "/v1/callers/web-profile/disable", "{}", cookie, csrf); w.Code != 200 {
		t.Fatal(w.Body)
	}
	for _, c := range claims {
		if _, e := s.resolveCaller(context.Background(), c); e == nil {
			t.Fatal("disabled profile authenticated")
		}
	}
	if w := ownerPost(s, "/v1/callers/web-profile/enable", `{"tools":["`+domain.Tool+`"],"duration_seconds":3600}`, cookie, csrf); w.Code != 200 {
		t.Fatal(w.Body)
	}
	for _, c := range claims {
		a, e := s.resolveCaller(context.Background(), c)
		if e != nil {
			t.Fatal("valid same-profile token not restored", e)
		}
		if _, e = s.mintDelegation(context.Background(), a, "grant"); e == nil {
			t.Fatal("old grant restored")
		}
	}
}
func TestCallerMutationsRejectCrossSiteOrigin(t *testing.T) {
	s, _, _, _ := callerFixture(t)
	cookie, csrf := ownerCookie(t, s, "owner")
	for _, path := range []string{"/v1/callers", "/v1/callers/web-profile/disable", "/v1/callers/web-profile/enable", "/v1/callers/web-profile/name"} {
		r := httptest.NewRequest("POST", path, strings.NewReader("{}"))
		r.AddCookie(cookie)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", "https://evil.test")
		r.Header.Set("X-CSRF-Token", csrf)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatalf("cross-site mutation %s: %d", path, w.Code)
		}
	}
}

func TestApprovalProviderAuthorizationRechecksProfile(t *testing.T) {
	s, repo, _, idp := callerFixture(t)
	cookie, csrf := ownerCookie(t, s, "owner")
	access, e := s.resolveCaller(context.Background(), identity.Claims{Issuer: idp.Issuer(), UserID: "uid-owner", ClientID: "web", ExpiresAt: time.Now().Add(time.Hour)})
	if e != nil {
		t.Fatal(e)
	}
	result, e := s.createDelegation(context.Background(), access, domain.Tool, "doc-A", 300)
	if e != nil {
		t.Fatal(e)
	}
	s.integration = approvalIntegration{inspect: func(ctx context.Context, auth func(context.Context) error) (Document, error) {
		if e := repo.Transact(ctx, func(st *domain.State) error {
			p := st.CallerProfiles["web-profile"]
			p.Tools = nil
			st.CallerProfiles[p.ID] = p
			return nil
		}); e != nil {
			t.Fatal(e)
		}
		e := auth(ctx)
		if e == nil {
			t.Error("metadata credential/dispatch authorization ignored removed profile tool")
		}
		return Document{}, e
	}}
	w := ownerPost(s, "/v1/delegation-requests/"+result["request_id"].(string)+"/review", `{"connection_id":"connection"}`, cookie, csrf)
	if w.Code != 403 {
		t.Fatalf("review released metadata beyond profile: %d %s", w.Code, w.Body)
	}
}

func TestReviewFinalReleaseRechecksProfile(t *testing.T) {
	s, repo, _, idp := callerFixture(t)
	cookie, csrf := ownerCookie(t, s, "owner")
	access, e := s.resolveCaller(context.Background(), identity.Claims{Issuer: idp.Issuer(), UserID: "uid-owner", ClientID: "web", ExpiresAt: time.Now().Add(time.Hour)})
	if e != nil {
		t.Fatal(e)
	}
	result, e := s.createDelegation(context.Background(), access, domain.Tool, "doc-A", 300)
	if e != nil {
		t.Fatal(e)
	}
	s.integration = approvalIntegration{inspect: func(ctx context.Context, auth func(context.Context) error) (Document, error) {
		if e := auth(ctx); e != nil {
			return Document{}, e
		}
		e := repo.Transact(ctx, func(st *domain.State) error {
			p := st.CallerProfiles["web-profile"]
			p.Tools = nil
			st.CallerProfiles[p.ID] = p
			return nil
		})
		return Document{Name: "private-metadata"}, e
	}}
	w := ownerPost(s, "/v1/delegation-requests/"+result["request_id"].(string)+"/review", `{"connection_id":"connection"}`, cookie, csrf)
	if w.Code != 403 || strings.Contains(w.Body.String(), "private-metadata") {
		t.Fatalf("released stale profile metadata: %d %s", w.Code, w.Body)
	}
}

type loginClockRepository struct {
	domain.Repository
	now time.Time
}

func (r *loginClockRepository) Transact(ctx context.Context, fn func(*domain.State) error) error {
	return r.Repository.Transact(ctx, func(st *domain.State) error { st.Now = r.now; return fn(st) })
}
