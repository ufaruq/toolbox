package identitylink

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ufaruq/toolbox/internal/domain"
	"github.com/ufaruq/toolbox/internal/store"
)

type fixture struct {
	server       *httptest.Server
	provider     map[string]any
	mappers      []map[string]any
	users        []map[string]any
	federated    map[string][]map[string]any
	tokenStatus  int
	tokenBody    string
	onProof      func()
	actualUserID string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{
		provider: map[string]any{"alias": "okta", "providerId": "oidc", "enabled": true, "config": map[string]string{"issuer": "https://old.example/", "validateSignature": "true", "userIDClaim": "sub"}},
		mappers:  []map[string]any{}, users: []map[string]any{{"id": "kc-owner", "enabled": true, "email": "same@example.test"}},
		federated:   map[string][]map[string]any{"kc-owner": {{"identityProvider": "okta", "userId": "old-sub", "userName": "mutable@example.test"}}},
		tokenStatus: 200, tokenBody: `{"access_token":"admin-private-token","token_type":"Bearer","expires_in":300}`,
	}
	f.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/realms/toolbox/protocol/openid-connect/token" {
			if r.Method != "POST" {
				t.Errorf("token method %s", r.Method)
			}
			if err := r.ParseForm(); err != nil {
				t.Error(err)
			}
			if r.Form.Get("grant_type") != "client_credentials" || r.Form.Get("client_id") != "readonly" || r.Form.Get("client_secret") != "client-private-secret" {
				t.Error("wrong token grant")
			}
			w.WriteHeader(f.tokenStatus)
			_, _ = w.Write([]byte(f.tokenBody))
			return
		}
		if r.Header.Get("Authorization") != "Bearer admin-private-token" {
			t.Errorf("missing admin authorization for %s", r.URL.Path)
		}
		if r.Method != "GET" {
			t.Errorf("Admin API writes forbidden: %s", r.Method)
			w.WriteHeader(405)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/admin/realms/toolbox/identity-provider/instances/okta":
			_ = json.NewEncoder(w).Encode(f.provider)
		case "/admin/realms/toolbox/identity-provider/instances/okta/mappers":
			_ = json.NewEncoder(w).Encode(f.mappers)
		case "/admin/realms/toolbox/users":
			if r.URL.Query().Get("first") == "0" {
				_ = json.NewEncoder(w).Encode(f.users)
			} else {
				_ = json.NewEncoder(w).Encode([]any{})
			}
		default:
			id := strings.TrimPrefix(r.URL.Path, "/admin/realms/toolbox/users/")
			if strings.HasSuffix(id, "/federated-identity") {
				if f.onProof != nil {
					f.onProof()
				}
				_ = json.NewEncoder(w).Encode(f.federated[strings.TrimSuffix(id, "/federated-identity")])
				return
			}
			for _, u := range f.users {
				if u["id"] == id {
					if f.actualUserID != "" {
						_ = json.NewEncoder(w).Encode(map[string]any{"id": f.actualUserID, "enabled": true})
						return
					}
					_ = json.NewEncoder(w).Encode(u)
					return
				}
			}
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(f.server.Close)
	return f
}
func (f *fixture) config() Config {
	return Config{RealmIssuer: f.server.URL + "/realms/toolbox", SourceIssuer: "https://old.example/", SourceProviderAlias: "okta", ClientID: "readonly", ClientSecret: "client-private-secret", HTTPClient: f.server.Client()}
}
func legacyRepo(t *testing.T) *store.Memory {
	t.Helper()
	r := store.NewMemory()
	if err := r.Transact(context.Background(), func(st *domain.State) error {
		st.Users["owner"] = domain.User{ID: "owner", Issuer: "https://old.example/", Subject: "old-sub", Status: "active"}
		st.Users["google-owner"] = domain.User{ID: "google-owner", Issuer: "https://google.example/", Subject: "old-sub", Status: "active"}
		st.Agents["agent"] = domain.Agent{ID: "agent", OwnerID: "owner", Status: "active"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return r
}
func TestVerifiedLinkDryRunApplyAndRepeat(t *testing.T) {
	f := newFixture(t)
	r := legacyRepo(t)
	l, err := New(context.Background(), f.config())
	if err != nil {
		t.Fatal(err)
	}
	report, err := l.Link(context.Background(), r, false)
	if err != nil {
		t.Fatal(err)
	}
	if report.Scanned != 1 || report.Linked != 1 || report.AlreadyLinked != 0 {
		t.Fatalf("dry run report %+v", report)
	}
	_ = r.Transact(context.Background(), func(st *domain.State) error {
		if len(st.IdentityAliases) != 0 || len(st.Audits) != 0 {
			t.Fatal("dry run mutated state")
		}
		return nil
	})
	report, err = l.Link(context.Background(), r, true)
	if err != nil {
		t.Fatal(err)
	}
	if report.Linked != 1 {
		t.Fatalf("apply %+v", report)
	}
	if err = r.Transact(context.Background(), func(st *domain.State) error {
		got, ok := domain.ResolveIdentity(st, f.config().RealmIssuer, "kc-owner")
		if !ok || got.ID != "owner" {
			t.Fatalf("legacy identity not preserved: %+v %v", got, ok)
		}
		if st.Users["owner"].Subject != "old-sub" || st.Agents["agent"].OwnerID != "owner" {
			t.Fatal("ownership mutated")
		}
		if len(st.Audits) != 1 || st.Audits[0].Action != "owner.identity.linked" {
			t.Fatalf("audits %+v", st.Audits)
		}
		if _, ok = domain.ResolveIdentity(st, f.config().RealmIssuer, "google-owner"); ok {
			t.Fatal("Google identity linked by email")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	report, err = l.Link(context.Background(), r, true)
	if err != nil {
		t.Fatal(err)
	}
	if report.Linked != 0 || report.AlreadyLinked != 1 {
		t.Fatalf("repeat %+v", report)
	}
	_ = r.Transact(context.Background(), func(st *domain.State) error {
		if len(st.Audits) != 1 {
			t.Fatal("duplicate audit")
		}
		return nil
	})
}
func TestRejectsUnverifiedProvider(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*fixture)
	}{
		{"foreign issuer", func(f *fixture) { f.provider["config"].(map[string]string)["issuer"] = "https://foreign.example/" }},
		{"email identity claim", func(f *fixture) { f.provider["config"].(map[string]string)["userIDClaim"] = "email" }},
		{"signature disabled", func(f *fixture) { f.provider["config"].(map[string]string)["validateSignature"] = "false" }},
		{"foreign alias", func(f *fixture) { f.provider["alias"] = "google" }},
		{"wrong protocol", func(f *fixture) { f.provider["providerId"] = "saml" }},
		{"custom mapper", func(f *fixture) {
			f.mappers = []map[string]any{{"identityProviderAlias": "okta", "identityProviderMapper": "custom-substitution"}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			tc.change(f)
			if _, err := New(context.Background(), f.config()); err == nil {
				t.Fatal("accepted unverified provider")
			}
		})
	}
}
func TestRejectsMissingDuplicateAndForeignProofAtomically(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*fixture)
	}{
		{"missing old subject", func(f *fixture) { f.federated["kc-owner"][0]["userId"] = "same@example.test" }},
		{"wrong upstream", func(f *fixture) { f.federated["kc-owner"][0]["identityProvider"] = "google" }},
		{"duplicate upstream binding", func(f *fixture) {
			f.users = append(f.users, map[string]any{"id": "kc-other", "enabled": true})
			f.federated["kc-other"] = f.federated["kc-owner"]
		}},
		{"duplicate listed user", func(f *fixture) { f.users = append(f.users, f.users[0]) }},
		{"duplicate provider record", func(f *fixture) {
			f.federated["kc-owner"] = append(f.federated["kc-owner"], f.federated["kc-owner"][0])
		}},
		{"service account", func(f *fixture) { f.users[0]["serviceAccountClientId"] = "admin" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			tc.change(f)
			r := legacyRepo(t)
			l, err := New(context.Background(), f.config())
			if err != nil {
				t.Fatal(err)
			}
			if _, err = l.Link(context.Background(), r, true); err == nil {
				t.Fatal("accepted missing or ambiguous proof")
			}
			_ = r.Transact(context.Background(), func(st *domain.State) error {
				if len(st.IdentityAliases) != 0 || len(st.Audits) != 0 {
					t.Fatal("partial migration")
				}
				return nil
			})
		})
	}
}
func TestRejectsIdentityCollision(t *testing.T) {
	f := newFixture(t)
	r := legacyRepo(t)
	if err := r.Transact(context.Background(), func(st *domain.State) error {
		st.Users["impostor"] = domain.User{ID: "impostor", Issuer: f.config().RealmIssuer, Subject: "kc-owner", Status: "active"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	l, err := New(context.Background(), f.config())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = l.Link(context.Background(), r, true); err == nil {
		t.Fatal("identity reassigned")
	}
}
func TestNewRejectsHTTPAndDoesNotExposeAdminErrorBodies(t *testing.T) {
	if _, err := New(context.Background(), Config{RealmIssuer: "http://example.test/realms/x", ClientID: "id", ClientSecret: "secret", SourceIssuer: "https://old.example/", SourceProviderAlias: "okta"}); err == nil {
		t.Fatal("accepted HTTP")
	}
	f := newFixture(t)
	f.tokenStatus = 401
	f.tokenBody = "client-private-secret admin-private-token"
	_, err := New(context.Background(), f.config())
	if err == nil {
		t.Fatal("accepted failed auth")
	}
	if strings.Contains(err.Error(), "private") {
		t.Fatal("secret exposed")
	}
}

func TestRejectsProviderChangesAfterConstruction(t *testing.T) {
	f := newFixture(t)
	l, err := New(context.Background(), f.config())
	if err != nil {
		t.Fatal(err)
	}
	f.provider["config"].(map[string]string)["userIDClaim"] = "email"
	if _, err = l.Link(context.Background(), legacyRepo(t), true); err == nil {
		t.Fatal("accepted changed provider proof")
	}
}

func TestRejectsMapperThatRewritesBrokerID(t *testing.T) {
	f := newFixture(t)
	f.mappers = []map[string]any{{"identityProviderAlias": "okta", "identityProviderMapper": "oidc-username-idp-mapper", "config": map[string]string{"target": "BROKER_ID", "template": "${CLAIM.email}"}}}
	if _, err := New(context.Background(), f.config()); err == nil {
		t.Fatal("accepted mutable broker subject mapper")
	}
}

func TestAllowsLocalProviderPrefixedUsername(t *testing.T) {
	f := newFixture(t)
	f.mappers = []map[string]any{{"identityProviderAlias": "okta", "identityProviderMapper": "oidc-username-idp-mapper", "config": map[string]string{"target": "LOCAL", "template": "${ALIAS}.${CLAIM.sub}"}}}
	l, err := New(context.Background(), f.config())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = l.Link(context.Background(), legacyRepo(t), true); err != nil {
		t.Fatal(err)
	}
}

func TestRejectsPremergedProviderIdentities(t *testing.T) {
	f := newFixture(t)
	f.federated["kc-owner"] = append(f.federated["kc-owner"], map[string]any{"identityProvider": "google", "userId": "google-sub"})
	l, err := New(context.Background(), f.config())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = l.Link(context.Background(), legacyRepo(t), true); err == nil {
		t.Fatal("migrated premerged provider identities")
	}
}

type staleRepo struct {
	domain.Repository
	calls int
}

func (r *staleRepo) Transact(ctx context.Context, fn func(*domain.State) error) error {
	r.calls++
	if r.calls == 2 {
		if err := r.Repository.Transact(ctx, func(st *domain.State) error {
			u := st.Users["owner"]
			u.Status = "disabled"
			st.Users[u.ID] = u
			return nil
		}); err != nil {
			return err
		}
	}
	return r.Repository.Transact(ctx, fn)
}
func TestApplyRechecksOwnerState(t *testing.T) {
	f := newFixture(t)
	base := legacyRepo(t)
	r := &staleRepo{Repository: base}
	l, err := New(context.Background(), f.config())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = l.Link(context.Background(), r, true); err == nil {
		t.Fatal("accepted stale owner snapshot")
	}
	_ = base.Transact(context.Background(), func(st *domain.State) error {
		if len(st.IdentityAliases) != 0 || len(st.Audits) != 0 {
			t.Fatal("partial stale migration")
		}
		return nil
	})
}

func TestDryRunRejectsIncompleteCutover(t *testing.T) {
	f := newFixture(t)
	f.federated["kc-owner"] = []map[string]any{}
	l, err := New(context.Background(), f.config())
	if err != nil {
		t.Fatal(err)
	}
	report, err := l.Link(context.Background(), legacyRepo(t), false)
	if err == nil || report.Unmatched != 1 {
		t.Fatalf("incomplete dry run: %+v %v", report, err)
	}
}

func TestRejectsMalformedBoundedAndRedirectingAdminResponses(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{"malformed", 200, `{"alias":`},
		{"oversized", 200, strings.Repeat(" ", 2<<20) + `{}`},
		{"redirect", 302, `do not follow`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reached := false
			foreign := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				reached = true
				t.Error("followed redirected admin request")
			}))
			defer foreign.Close()
			var server *httptest.Server
			server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/token") {
					_, _ = w.Write([]byte(`{"access_token":"admin-private-token","token_type":"Bearer","expires_in":300}`))
					return
				}
				if tc.status == 302 {
					w.Header().Set("Location", foreign.URL)
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			cfg := Config{RealmIssuer: server.URL + "/realms/toolbox", SourceIssuer: "https://old.example/", SourceProviderAlias: "okta", ClientID: "readonly", ClientSecret: "client-private-secret", HTTPClient: server.Client()}
			if _, err := New(context.Background(), cfg); err == nil {
				t.Fatal("accepted invalid admin response")
			}
			if reached {
				t.Fatal("foreign endpoint reached")
			}
		})
	}
}

func TestRejectsDuplicateJSONProofMembers(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/token") {
			_, _ = w.Write([]byte(`{"access_token":"admin-private-token","token_type":"Bearer","expires_in":300}`))
			return
		}
		if strings.HasSuffix(r.URL.Path, "/mappers") {
			_, _ = w.Write([]byte(`[]`))
			return
		}
		_, _ = w.Write([]byte(`{"alias":"google","alias":"okta","providerId":"oidc","enabled":true,"config":{"issuer":"https://old.example/","validateSignature":"true"}}`))
	}))
	defer server.Close()
	cfg := Config{RealmIssuer: server.URL + "/realms/toolbox", SourceIssuer: "https://old.example/", SourceProviderAlias: "okta", ClientID: "readonly", ClientSecret: "client-private-secret", HTTPClient: server.Client()}
	if _, err := New(context.Background(), cfg); err == nil {
		t.Fatal("accepted ambiguous duplicate JSON proof")
	}
}

func TestRejectsProviderChangedWhileScanning(t *testing.T) {
	f := newFixture(t)
	l, err := New(context.Background(), f.config())
	if err != nil {
		t.Fatal(err)
	}
	f.onProof = func() { f.provider["config"].(map[string]string)["userIDClaim"] = "email" }
	if _, err = l.Link(context.Background(), legacyRepo(t), true); err == nil {
		t.Fatal("accepted proof after provider changed during scan")
	}
}

func TestRejectsExistingDifferentAliasForOwner(t *testing.T) {
	f := newFixture(t)
	r := legacyRepo(t)
	if err := r.Transact(context.Background(), func(st *domain.State) error {
		a := domain.IdentityAlias{Issuer: f.config().RealmIssuer, Subject: "other-kc-sub", OwnerID: "owner"}
		st.IdentityAliases[domain.IdentityKey(a.Issuer, a.Subject)] = a
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	l, err := New(context.Background(), f.config())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = l.Link(context.Background(), r, true); err == nil {
		t.Fatal("accepted different existing realm alias for owner")
	}
}

func TestRejectsForeignUserRepresentation(t *testing.T) {
	f := newFixture(t)
	f.actualUserID = "foreign-user"
	l, err := New(context.Background(), f.config())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = l.Link(context.Background(), legacyRepo(t), true); err == nil {
		t.Fatal("accepted foreign user representation")
	}
}

func TestRejectsDisabledIdentityProof(t *testing.T) {
	f := newFixture(t)
	f.users[0]["enabled"] = false
	l, err := New(context.Background(), f.config())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = l.Link(context.Background(), legacyRepo(t), true); err == nil {
		t.Fatal("accepted disabled identity proof")
	}
}

func TestRejectsExpiredAdminToken(t *testing.T) {
	f := newFixture(t)
	l, err := New(context.Background(), f.config())
	if err != nil {
		t.Fatal(err)
	}
	l.expires = time.Now().Add(-time.Second)
	if _, err = l.Link(context.Background(), legacyRepo(t), true); err == nil {
		t.Fatal("accepted expired admin token")
	}
}

func TestRejectsNonCanonicalSourceURLAndInvalidUTF8Config(t *testing.T) {
	for _, change := range []func(*Config){
		func(c *Config) { c.SourceIssuer += "?" },
		func(c *Config) { c.SourceIssuer += "/" + string([]byte{0xff}) },
		func(c *Config) { c.ClientID = string([]byte{0xff}) },
	} {
		f := newFixture(t)
		cfg := f.config()
		change(&cfg)
		_, err := New(context.Background(), cfg)
		if err != errConfig {
			t.Fatalf("expected invalid configuration before network I/O, got %v", err)
		}
	}
}

func TestSameEmailAtDifferentUpstreamRemainsSeparate(t *testing.T) {
	f := newFixture(t)
	f.users = append(f.users, map[string]any{"id": "kc-google", "enabled": true, "email": "same@example.test"})
	f.federated["kc-google"] = []map[string]any{{"identityProvider": "google", "userId": "old-sub"}}
	r := legacyRepo(t)
	l, err := New(context.Background(), f.config())
	if err != nil {
		t.Fatal(err)
	}
	report, err := l.Link(context.Background(), r, true)
	if err != nil {
		t.Fatal(err)
	}
	if report.Linked != 1 {
		t.Fatalf("migration %+v", report)
	}
	_ = r.Transact(context.Background(), func(st *domain.State) error {
		if len(st.IdentityAliases) != 1 {
			t.Fatal("unexpected alias")
		}
		if _, ok := domain.ResolveIdentity(st, f.config().RealmIssuer, "kc-google"); ok {
			t.Fatal("linked same-email Google identity")
		}
		return nil
	})
}

func TestRejectsLookalikeSubjectClaimOption(t *testing.T) {
	f := newFixture(t)
	f.provider["config"].(map[string]string)["userIdClaim"] = "sub"
	if _, err := New(context.Background(), f.config()); err == nil {
		t.Fatal("accepted unrecognized lookalike subject claim option")
	}
}

func TestRejectsCaseVariantJSONProofMembers(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/token") {
			_, _ = w.Write([]byte(`{"access_token":"admin-private-token","token_type":"Bearer","expires_in":300}`))
			return
		}
		if strings.HasSuffix(r.URL.Path, "/mappers") {
			_, _ = w.Write([]byte(`[]`))
			return
		}
		_, _ = w.Write([]byte(`{"alias":"google","Alias":"okta","providerId":"oidc","enabled":true,"config":{"issuer":"https://old.example/","validateSignature":"true"}}`))
	}))
	defer server.Close()
	cfg := Config{RealmIssuer: server.URL + "/realms/toolbox", SourceIssuer: "https://old.example/", SourceProviderAlias: "okta", ClientID: "readonly", ClientSecret: "client-private-secret", HTTPClient: server.Client()}
	if _, err := New(context.Background(), cfg); err == nil {
		t.Fatal("accepted case-variant ambiguous JSON proof")
	}
}
