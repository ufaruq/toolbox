package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ufaruq/toolbox/internal/domain"
	"github.com/ufaruq/toolbox/internal/identity"
)

type onboardingIdentity struct {
	mcpIdentity
	enabled bool
	user    string
}

func (i onboardingIdentity) DynamicClientOnboarding() bool { return i.enabled }
func (i onboardingIdentity) VerifyOnboardingAccess(ctx context.Context, raw string) (identity.Claims, error) {
	if raw == "invalid" {
		return identity.Claims{}, domain.ErrDenied
	}
	user := i.user
	if user == "" {
		user = "owner"
	}
	return identity.Claims{Issuer: i.Issuer(), UserID: user, ClientID: raw, ExpiresAt: time.Now().Add(time.Hour)}, nil
}
func pendingMCP(s *Server, token string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/mcp", strings.NewReader(`{}`))
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}
func candidateID(t *testing.T, s *Server) string {
	t.Helper()
	var id string
	if err := s.Repository.Transact(context.Background(), func(st *domain.State) error {
		for k := range st.CallerCandidates {
			id = k
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if id == "" {
		t.Fatal("missing candidate")
	}
	return id
}
func TestDynamicCallerPendingApprovalLifecycle(t *testing.T) {
	s, repo, ts := mcpFixture(t)
	s.Identity = onboardingIdentity{enabled: true}
	for n := 0; n < 20; n++ {
		w := pendingMCP(s, "new-client")
		if w.Code != 403 || !strings.Contains(w.Body.String(), "CALLER_PENDING_APPROVAL") {
			t.Fatalf("pending: %d %s", w.Code, w.Body)
		}
	}
	id := candidateID(t, s)
	if err := repo.Transact(context.Background(), func(st *domain.State) error {
		if len(st.CallerCandidates) != 1 || len(st.CallerProfiles) != 2 || len(st.Agents) != 2 || len(st.Grants) != 1 {
			t.Fatal("pending mutated privileges")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	cookie, csrf := ownerCookie(t, s, "owner")
	path := "/v1/callers/pending/" + id
	for _, op := range []string{"reject", "reopen"} {
		if w := ownerPost(s, path+"/"+op, `{}`, cookie, csrf); w.Code != 200 {
			t.Fatalf("%s: %d %s", op, w.Code, w.Body)
		}
		if op == "reject" {
			w := pendingMCP(s, "new-client")
			if w.Code != 403 || strings.Contains(w.Body.String(), "PENDING") {
				t.Fatalf("rejection reset: %s", w.Body)
			}
		}
	}
	approval := `{"label":"Local assistant","tools":["` + domain.Tool + `"],"duration_seconds":3600}`
	w := ownerPost(s, path+"/approve", approval, cookie, csrf)
	if w.Code != 201 {
		t.Fatalf("approve: %d %s", w.Code, w.Body)
	}
	var profile map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &profile); err != nil {
		t.Fatal(err)
	}
	for _, op := range []string{"approve", "reject", "reopen"} {
		body := `{}`
		if op == "approve" {
			body = approval
		}
		if w := ownerPost(s, path+"/"+op, body, cookie, csrf); w.Code != 409 {
			t.Fatalf("stale %s: %d", op, w.Code)
		}
	}
	client := connectMCP(t, ts, "new-client", "")
	catalog, err := client.ListTools(context.Background(), nil)
	if err != nil || len(catalog.Tools) != 3 {
		t.Fatalf("approved tools: %v %v", catalog, err)
	}
	access, err := s.resolveCaller(context.Background(), identity.Claims{Issuer: s.Identity.Issuer(), UserID: "owner", ClientID: "new-client", ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.mintDelegation(context.Background(), access, "grant"); err == nil {
		t.Fatal("client gained another agent's document grant")
	}
	s.Identity = onboardingIdentity{enabled: false}
	if w := pendingMCP(s, "new-client"); w.Code != 401 {
		t.Fatalf("off mode: %d", w.Code)
	}
	s.Identity = onboardingIdentity{enabled: true}
	if w := ownerPost(s, "/v1/callers/"+profile["id"].(string)+"/disable", `{}`, cookie, csrf); w.Code != 200 {
		t.Fatal(w.Body)
	}
	if w := pendingMCP(s, "new-client"); w.Code != 403 || strings.Contains(w.Body.String(), "PENDING") {
		t.Fatalf("disabled reset: %d %s", w.Code, w.Body)
	}
	if w := ownerPost(s, "/v1/callers/"+profile["id"].(string)+"/enable", `{"tools":[],"duration_seconds":3600}`, cookie, csrf); w.Code != 200 {
		t.Fatalf("enable: %d %s", w.Code, w.Body)
	}
}
func TestDynamicCallerOwnerBoundaryAndInput(t *testing.T) {
	s, repo, _ := mcpFixture(t)
	s.Identity = onboardingIdentity{enabled: true}
	for _, user := range []string{"unlinked", "disabled"} {
		if user == "disabled" {
			_ = repo.Transact(context.Background(), func(st *domain.State) error {
				st.Users["disabled"] = domain.User{ID: "disabled", Issuer: s.Identity.Issuer(), Subject: "disabled", Status: "disabled"}
				return nil
			})
		}
		s.Identity = onboardingIdentity{enabled: true, user: user}
		if w := pendingMCP(s, "new-client"); w.Code != 403 {
			t.Fatalf("unknown owner %d", w.Code)
		}
	}
	s.Identity = onboardingIdentity{enabled: true}
	if w := pendingMCP(s, "invalid"); w.Code != 401 {
		t.Fatal(w.Code)
	}
	_ = repo.Transact(context.Background(), func(st *domain.State) error {
		if len(st.CallerCandidates) != 0 {
			t.Fatal("unverified or inactive identity enqueued")
		}
		st.Users["other"] = domain.User{ID: "other", Issuer: "other", Subject: "other", Status: "active"}
		return nil
	})
	pendingMCP(s, "new-client")
	id := candidateID(t, s)
	path := "/v1/callers/pending/" + id + "/approve"
	payload := `{"label":"Chosen name","tools":[],"duration_seconds":3600}`
	owner, csrf := ownerCookie(t, s, "owner")
	other, otherCSRF := ownerCookie(t, s, "other")
	if w := ownerPost(s, path, payload, other, otherCSRF); w.Code != 403 {
		t.Fatal("foreign owner approved", w.Code)
	}
	if w := ownerPost(s, path, payload, owner, ""); w.Code != 403 {
		t.Fatal("missing csrf", w.Code)
	}
	r := httptest.NewRequest("POST", path, strings.NewReader(payload))
	r.Header.Set("Authorization", "Bearer new-client")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("bearer management", w.Code)
	}
	r = httptest.NewRequest("POST", path, strings.NewReader(payload))
	r.AddCookie(owner)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", csrf)
	r.Header.Set("Origin", "https://evil.example")
	w = httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("origin", w.Code)
	}
	if w := ownerPost(s, path, strings.TrimSuffix(payload, "}")+`,"client_id":"web"}`, owner, csrf); w.Code != 400 {
		t.Fatal("injected identity", w.Code)
	}
	r = httptest.NewRequest("GET", "/v1/callers", nil)
	r.AddCookie(other)
	w = httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if strings.Contains(w.Body.String(), "new-client") {
		t.Fatal("foreign candidate disclosed")
	}
}
func TestDynamicCallerRateLimit(t *testing.T) {
	s, _, _ := mcpFixture(t)
	s.Identity = onboardingIdentity{enabled: true}
	for n := 0; n < 11; n++ {
		w := pendingMCP(s, fmt.Sprintf("client-%d", n))
		want := 403
		if n == 10 {
			want = 429
		}
		if w.Code != want {
			t.Fatalf("candidate %d: %d %s", n, w.Code, w.Body)
		}
	}
	if w := pendingMCP(s, "client-0"); w.Code != 403 {
		t.Fatal("idempotent retry rate limited")
	}
}

type unavailableCandidateRepository struct{ domain.Repository }

func (unavailableCandidateRepository) Transact(context.Context, func(*domain.State) error) error {
	return fmt.Errorf("unavailable")
}
func TestDynamicCallerCapacityAndDependency(t *testing.T) {
	for _, global := range []bool{false, true} {
		t.Run(fmt.Sprint(global), func(t *testing.T) {
			s, repo, _ := mcpFixture(t)
			s.Identity = onboardingIdentity{enabled: true}
			if err := repo.Transact(context.Background(), func(st *domain.State) error {
				count := 64
				if global {
					count = 4096
					st.Users["other"] = domain.User{ID: "other", Issuer: s.Identity.Issuer(), Subject: "other", Status: "active"}
				}
				for n := 0; n < count; n++ {
					owner := "owner"
					if global {
						owner = "other"
					}
					id := fmt.Sprint(n)
					st.CallerCandidates[id] = domain.CallerCandidate{ID: id, OwnerID: owner, Issuer: s.Identity.Issuer(), UserID: owner, ClientID: "seed-" + id, Status: "rejected", FirstSeenAt: st.Now, DecidedAt: st.Now}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if w := pendingMCP(s, "new-client"); w.Code != 429 || !strings.Contains(w.Body.String(), "CAPACITY") {
				t.Fatalf("capacity: %d %s", w.Code, w.Body)
			}
		})
	}
	s, _, _ := mcpFixture(t)
	s.Identity = onboardingIdentity{enabled: true}
	s.Repository = unavailableCandidateRepository{s.Repository}
	if w := pendingMCP(s, "new-client"); w.Code != 503 {
		t.Fatalf("repository failure: %d", w.Code)
	}
}
func TestDynamicCallerConcurrentDecisionsAndExpiry(t *testing.T) {
	s, repo, _ := mcpFixture(t)
	s.Identity = onboardingIdentity{enabled: true}
	outcomes := make(chan int, 20)
	for n := 0; n < 20; n++ {
		go func() { outcomes <- pendingMCP(s, "race-client").Code }()
	}
	for n := 0; n < 20; n++ {
		if code := <-outcomes; code != 403 {
			t.Fatal(code)
		}
	}
	id := candidateID(t, s)
	cookie, csrf := ownerCookie(t, s, "owner")
	for _, op := range []string{"approve", "reject"} {
		go func(op string) {
			payload := `{}`
			if op == "approve" {
				payload = `{"label":"Race client","tools":[],"duration_seconds":1}`
			}
			outcomes <- ownerPost(s, "/v1/callers/pending/"+id+"/"+op, payload, cookie, csrf).Code
		}(op)
	}
	a, b := <-outcomes, <-outcomes
	if !(a == 409 && (b == 200 || b == 201) || b == 409 && (a == 200 || a == 201)) {
		t.Fatalf("concurrent decisions: %d %d", a, b)
	}
	if err := repo.Transact(context.Background(), func(st *domain.State) error {
		if len(st.CallerCandidates) != 1 {
			t.Fatal("duplicate candidates")
		}
		for _, p := range st.CallerProfiles {
			if p.ClientID == "race-client" {
				st.Now = p.ExpiresAt.Add(time.Second)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// Use repository clock wrapper so expiration is observed on every request.
	s.Repository = &loginClockRepository{Repository: repo, now: time.Now().Add(2 * time.Hour)}
	if w := pendingMCP(s, "race-client"); w.Code != 403 || strings.Contains(w.Body.String(), "PENDING") {
		t.Fatalf("expired/rejected client reset: %d %s", w.Code, w.Body)
	}
}

// The first body read happens after requireOwner authenticated the cookie.
type candidateDecisionBody struct {
	beforeRead func()
	body       *strings.Reader
}

func (r *candidateDecisionBody) Read(p []byte) (int, error) {
	if r.beforeRead != nil {
		fn := r.beforeRead
		r.beforeRead = nil
		fn()
	}
	return r.body.Read(p)
}
func (r *candidateDecisionBody) Close() error { return nil }
func TestCandidateDecisionRechecksSessionAtCommit(t *testing.T) {
	for _, op := range []string{"approve", "reject", "reopen"} {
		for _, revoke := range []string{"logout", "expiry"} {
			t.Run(op+"/"+revoke, func(t *testing.T) {
				s, repo, _ := mcpFixture(t)
				s.Identity = onboardingIdentity{enabled: true}
				pendingMCP(s, "new-client")
				id := candidateID(t, s)
				cookie, csrf := ownerCookie(t, s, "owner")
				if op == "reopen" {
					if w := ownerPost(s, "/v1/callers/pending/"+id+"/reject", `{}`, cookie, csrf); w.Code != 200 {
						t.Fatal(w.Code)
					}
				}
				payload := `{}`
				if op == "approve" {
					payload = `{"label":"Delayed approval","tools":[],"duration_seconds":3600}`
				}
				r := httptest.NewRequest("POST", "/v1/callers/pending/"+id+"/"+op, nil)
				r.AddCookie(cookie)
				r.Header.Set("Origin", s.Origin)
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("X-CSRF-Token", csrf)
				r.Body = &candidateDecisionBody{body: strings.NewReader(payload), beforeRead: func() {
					if err := repo.Transact(context.Background(), func(st *domain.State) error {
						for key, session := range st.Sessions {
							if revoke == "logout" {
								delete(st.Sessions, key)
							} else {
								session.ExpiresAt = st.Now
								st.Sessions[key] = session
							}
						}
						return nil
					}); err != nil {
						t.Fatal(err)
					}
				}}
				w := httptest.NewRecorder()
				s.ServeHTTP(w, r)
				if w.Code != 403 {
					t.Fatalf("decision survived %s: %d %s", revoke, w.Code, w.Body)
				}
				if err := repo.Transact(context.Background(), func(st *domain.State) error {
					want := "pending"
					if op == "reopen" {
						want = "rejected"
					}
					if st.CallerCandidates[id].Status != want || len(st.Agents) != 2 || len(st.CallerProfiles) != 2 {
						t.Fatal("revoked session changed candidate privileges")
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

type staticOnboardingIdentity struct{ onboardingIdentity }

func (staticOnboardingIdentity) Clients() map[string]string {
	return map[string]string{"new-client": "Explicit static admission"}
}
func TestDynamicCredentialRespectsAdmissionRollback(t *testing.T) {
	s, repo, _ := mcpFixture(t)
	s.Identity = onboardingIdentity{enabled: true}
	pendingMCP(s, "new-client")
	id := candidateID(t, s)
	cookie, csrf := ownerCookie(t, s, "owner")
	w := ownerPost(s, "/v1/callers/pending/"+id+"/approve", `{"label":"Local client","tools":["`+domain.Tool+`"],"duration_seconds":3600}`, cookie, csrf)
	if w.Code != 201 {
		t.Fatal(w.Body)
	}
	var profile map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &profile)
	w = ownerPost(s, "/v1/agents/"+profile["agent_id"].(string)+"/credentials", `{}`, cookie, csrf)
	if w.Code != 201 {
		t.Fatal(w.Body)
	}
	var credential map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &credential)
	if err := repo.Transact(context.Background(), func(st *domain.State) error {
		g := st.Grants["grant"]
		g.ID = "dynamic-grant"
		g.AgentID = profile["agent_id"].(string)
		st.Grants[g.ID] = g
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	mint := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/v1/delegation-tokens", strings.NewReader(`{"grant_id":"dynamic-grant"}`))
		r.Header.Set("Authorization", "Bearer "+credential["credential"])
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w
	}
	if w := mint(); w.Code != 200 {
		t.Fatalf("enabled credential: %d", w.Code)
	}
	s.Identity = onboardingIdentity{enabled: false}
	if w := mint(); w.Code != 401 {
		t.Fatalf("dynamic credential survived rollback: %d", w.Code)
	}
	s.Identity = staticOnboardingIdentity{onboardingIdentity{enabled: false}}
	if w := mint(); w.Code != 200 {
		t.Fatalf("explicit static admission denied: %d", w.Code)
	}
	s.Identity = onboardingIdentity{enabled: true}
	w = mint()
	var minted map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &minted)
	s.integration = invocationIntegration{read: func(ctx context.Context, authorize func(context.Context) error) (Document, error) {
		if err := authorize(ctx); err != nil {
			return Document{}, err
		}
		s.Identity = onboardingIdentity{enabled: false}
		return Document{Content: "must not be released"}, nil
	}}
	result, err := s.invokeOperation(context.Background(), agentAccess{AgentID: profile["agent_id"].(string), CredentialID: credential["credential_id"]}, domain.Tool, "dynamic-grant", "doc-A", minted["delegation_token"])
	if err == nil || result != nil {
		t.Fatal("dynamic credential released data after admission rollback")
	}
}
