package oauth

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/ufaruq/toolbox/internal/domain"
	"github.com/ufaruq/toolbox/internal/tokens"
)

type ownerResolverFunc func(context.Context, string) (CorporateIdentity, error)

func (f ownerResolverFunc) ResolveCorporateIdentity(ctx context.Context, id string) (CorporateIdentity, error) {
	return f(ctx, id)
}

func trustedCorporateOwner(_ context.Context, id string) (CorporateIdentity, error) {
	if id != "owner" {
		return CorporateIdentity{}, errors.New("not permitted")
	}
	return CorporateIdentity{Email: "ufaruq@company.com", HostedDomain: "company.com"}, nil
}

func newCorporateHarness(t *testing.T, resolver TrustedOwnerIdentityResolver) (*harness, *GoogleProvider) {
	t.Helper()
	h := newHarness(t)
	p := corporateGoogle(t)
	var err error
	h.service, err = NewCorporateService(h.repo, h.secrets, p, resolver)
	if err != nil {
		t.Fatal(err)
	}
	return h, p
}

func beginCorporate(t *testing.T, h *harness, p *GoogleProvider, edit func(map[string]any), afterToken func()) (StartResult, string, *int) {
	t.Helper()
	start, err := h.service.Start(context.Background(), "owner", "session")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(start.AuthorizationURL)
	claims := testClaims(p, u.Query().Get("nonce"))
	claims["email"], claims["email_verified"], claims["hd"] = "ufaruq@company.com", true, "company.com"
	if edit != nil {
		edit(claims)
	}
	signed := signTestToken(t, map[string]any{"alg": "RS256", "kid": "test-key"}, claims)
	calls := new(int)
	p.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() == googleJWKSEndpoint {
			return jsonHTTP(200, testJWKS(t)), nil
		}
		if r.URL.String() != googleTokenEndpoint {
			t.Fatal("unexpected provider endpoint")
		}
		*calls++
		if afterToken != nil {
			afterToken()
		}
		return jsonHTTP(200, map[string]any{"access_token": "known-access", "refresh_token": "known-refresh", "token_type": "Bearer", "expires_in": 3600, "scope": "openid email " + domain.DriveScope, "id_token": signed}), nil
	})
	return start, u.Query().Get("state"), calls
}

func TestCorporateConstructorRequiresResolverAndExplicitIdentityMode(t *testing.T) {
	h := newHarness(t)
	if _, err := NewCorporateService(h.repo, h.secrets, h.provider, ownerResolverFunc(trustedCorporateOwner)); !errors.Is(err, ErrConfiguration) {
		t.Fatal("minimal provider accepted for corporate policy", err)
	}
	if _, err := NewCorporateService(h.repo, h.secrets, corporateGoogle(t), nil); !errors.Is(err, ErrConfiguration) {
		t.Fatal("missing trusted resolver accepted", err)
	}
	if _, err := NewService(h.repo, h.secrets, corporateGoogle(t)); !errors.Is(err, ErrConfiguration) {
		t.Fatal("identity mode silently omitted corporate enforcement", err)
	}
}

func TestIndependentGoogleIdentityServiceIsExplicit(t *testing.T) {
	h := newHarness(t)
	p := corporateGoogle(t)
	service, err := NewIndependentGoogleService(h.repo, h.secrets, p)
	if err != nil {
		t.Fatal(err)
	}
	h.service = service
	// This mode explicitly keeps the connected Google identity independent from
	// the owner. Only the corporate constructor may enforce a trusted mapping.
	_, state, _ := beginCorporate(t, h, p, func(c map[string]any) { c["email"] = "another@company.com" }, nil)
	if connection, err := service.Complete(context.Background(), "owner", "session", state, "code"); err != nil || connection.Status != "active" {
		t.Fatalf("explicit independent identity linking failed: %v", err)
	}
	if _, err := NewIndependentGoogleService(h.repo, h.secrets, h.provider); !errors.Is(err, ErrConfiguration) {
		t.Fatal("independent email identity mode accepted the minimal fixture contract")
	}
}

func TestCorporateCompleteAllowsOnlyExactVerifiedWorkspaceIdentity(t *testing.T) {
	cases := []struct {
		name    string
		edit    func(map[string]any)
		allowed bool
	}{
		{"permitted owner", nil, true},
		{"colleague same domain", func(c map[string]any) { c["email"] = "colleague@company.com" }, false},
		{"personal account", func(c map[string]any) { c["email"] = "ufaruq@gmail.com"; delete(c, "hd") }, false},
		{"different corporate domain", func(c map[string]any) { c["email"] = "ufaruq@other.com"; c["hd"] = "other.com" }, false},
		{"matching email wrong hosted domain", func(c map[string]any) { c["hd"] = "other.com" }, false},
		{"missing email", func(c map[string]any) { delete(c, "email") }, false},
		{"missing verification", func(c map[string]any) { delete(c, "email_verified") }, false},
		{"unverified email", func(c map[string]any) { c["email_verified"] = false }, false},
		{"missing hosted domain", func(c map[string]any) { delete(c, "hd") }, false},
		{"invalid email syntax", func(c map[string]any) { c["email"] = "ufaruq@company.com\n" }, false},
		{"mailbox plus alias", func(c map[string]any) { c["email"] = "ufaruq+other@company.com" }, false},
		{"mailbox case change", func(c map[string]any) { c["email"] = "UFARUQ@company.com" }, false},
		{"domain suffix", func(c map[string]any) {
			c["email"] = "ufaruq@company.com.evil.example"
			c["hd"] = "company.com.evil.example"
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resolverCalls := 0
			h, p := newCorporateHarness(t, ownerResolverFunc(func(ctx context.Context, id string) (CorporateIdentity, error) {
				resolverCalls++
				return trustedCorporateOwner(ctx, id)
			}))
			start, state, tokenCalls := beginCorporate(t, h, p, tc.edit, nil)
			got, err := h.service.Complete(context.Background(), "owner", "session", state, "code")
			if tc.allowed {
				if err != nil || got.Status != "active" || got.Subject != "google-subject" || got.Subject == "ufaruq@company.com" || !sameScopes(got.Scopes, p.ExpectedScopes()) {
					t.Fatalf("exact permitted account rejected or email used as account key: %+v %v", got, err)
				}
			} else {
				if !errors.Is(err, ErrAccountLinking) || h.connection(t, start.ConnectionID).Status != "pending" || got.ID != "" {
					t.Fatal("unpermitted identity linked", err)
				}
				assertCorporateCleanup(t, h, start.ConnectionID)
				if _, err := h.service.Complete(context.Background(), "owner", "session", state, "code"); !errors.Is(err, ErrCallback) {
					t.Fatal("denial reopened transaction", err)
				}
			}
			if resolverCalls != 1 || *tokenCalls != 1 {
				t.Fatalf("wrong resolver/exchange calls: %d/%d", resolverCalls, *tokenCalls)
			}
		})
	}
}

func assertCorporateCleanup(t *testing.T, h *harness, id string) {
	t.Helper()
	bundle, _, err := h.secrets.Get(context.Background(), tokens.Path(id))
	if err != nil || bundle.State != tokens.StateCleanup || bundle.RefreshToken != "known-refresh" || bundle.AccessToken != "" || !bundle.Expiry.IsZero() {
		t.Fatal("rejected credential missing or usable", err)
	}
	manager := &tokens.Manager{Repository: h.repo, Secrets: h.secrets}
	if token, err := manager.Access(context.Background(), id, func(context.Context) error { return nil }); err == nil || token != "" {
		t.Fatal("rejected identity dispatched credential", err)
	}
}

func TestCorporateResolverFailureAndInvalidTrustedConfigurationFailClosed(t *testing.T) {
	for _, tc := range []struct {
		name     string
		identity CorporateIdentity
		err      error
	}{
		{name: "unmapped owner", err: errors.New("CANARY resolver failure")},
		{name: "missing expected identity"},
		{name: "missing trusted domain", identity: CorporateIdentity{Email: "ufaruq@company.com"}},
		{name: "malformed expected identity", identity: CorporateIdentity{Email: "ufaruq@company.com\n", HostedDomain: "company.com"}},
		{name: "personal trusted mailbox", identity: CorporateIdentity{Email: "ufaruq@gmail.com", HostedDomain: "company.com"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, p := newCorporateHarness(t, ownerResolverFunc(func(context.Context, string) (CorporateIdentity, error) { return tc.identity, tc.err }))
			start, state, _ := beginCorporate(t, h, p, nil, nil)
			_, err := h.service.Complete(context.Background(), "owner", "session", state, "code")
			if !errors.Is(err, ErrAccountLinking) || strings.Contains(err.Error(), "CANARY") {
				t.Fatal("resolver failure accepted or leaked", err)
			}
			assertCorporateCleanup(t, h, start.ConnectionID)
		})
	}
}

func TestCorporatePolicyPreservesTransactionOwnerSessionAndExpiryBindings(t *testing.T) {
	for _, tc := range []struct {
		name, owner, session string
		expire               bool
	}{
		{name: "wrong owner", owner: "other", session: "other-session"},
		{name: "wrong session", owner: "owner", session: "session-2"},
		{name: "expired transaction", owner: "owner", session: "session", expire: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolverCalls := 0
			h, p := newCorporateHarness(t, ownerResolverFunc(func(ctx context.Context, id string) (CorporateIdentity, error) {
				resolverCalls++
				return trustedCorporateOwner(ctx, id)
			}))
			_, state, calls := beginCorporate(t, h, p, nil, nil)
			if tc.expire {
				h.now = h.now.Add(TransactionLifetime)
			}
			if _, err := h.service.Complete(context.Background(), tc.owner, tc.session, state, "code"); !errors.Is(err, ErrCallback) {
				t.Fatal("unbound callback accepted", err)
			}
			if *calls != 0 || resolverCalls != 0 {
				t.Fatal("untrusted owner reached provider or resolver")
			}
		})
	}
}

func TestCorporatePolicyRechecksOwnerSessionAfterProviderExchange(t *testing.T) {
	for _, lost := range []string{"session", "owner"} {
		t.Run(lost, func(t *testing.T) {
			h, p := newCorporateHarness(t, ownerResolverFunc(trustedCorporateOwner))
			start, state, _ := beginCorporate(t, h, p, nil, func() {
				if err := h.repo.Transact(context.Background(), func(st *domain.State) error {
					if lost == "session" {
						session := st.Sessions["session"]
						session.ExpiresAt = st.Now
						st.Sessions["session"] = session
					} else {
						u := st.Users["owner"]
						u.Status = "disabled"
						st.Users["owner"] = u
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			})
			if _, err := h.service.Complete(context.Background(), "owner", "session", state, "code"); !errors.Is(err, domain.ErrDenied) {
				t.Fatal("stale owner session linked account", err)
			}
			assertCorporateCleanup(t, h, start.ConnectionID)
		})
	}
}

func TestCorporatePolicyIgnoresForgedAuthorizationHints(t *testing.T) {
	h, p := newCorporateHarness(t, ownerResolverFunc(trustedCorporateOwner))
	start, state, _ := beginCorporate(t, h, p, func(c map[string]any) { c["email"] = "colleague@company.com" }, nil)
	u, _ := url.Parse(start.AuthorizationURL)
	q := u.Query()
	q.Set("login_hint", "ufaruq@company.com")
	q.Set("email", "ufaruq@company.com")
	q.Set("hd", "company.com")
	u.RawQuery = q.Encode()
	// These browser-controlled values are consent hints; completion accepts no
	// mailbox or domain input and must use only the signed token and resolver.
	if u.Query().Get("login_hint") != "ufaruq@company.com" {
		t.Fatal("test hint missing")
	}
	if _, err := h.service.Complete(context.Background(), "owner", "session", state, "code"); !errors.Is(err, ErrAccountLinking) {
		t.Fatal("forged account hints overrode signed identity", err)
	}
	assertCorporateCleanup(t, h, start.ConnectionID)
}

func TestCorporatePolicyDeniedCredentialCanBeRevokedByExistingCleanup(t *testing.T) {
	h, p := newCorporateHarness(t, ownerResolverFunc(trustedCorporateOwner))
	start, state, _ := beginCorporate(t, h, p, func(c map[string]any) { c["email"] = "colleague@company.com" }, nil)
	if _, err := h.service.Complete(context.Background(), "owner", "session", state, "code"); !errors.Is(err, ErrAccountLinking) {
		t.Fatal(err)
	}
	disconnectPending(t, h, start.ConnectionID)
	revokes := 0
	p.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		revokes++
		if r.URL.String() != googleRevocationEndpoint || r.ParseForm() != nil || r.PostForm.Get("token") != "known-refresh" {
			t.Fatal("wrong cleanup credential")
		}
		return jsonHTTP(200, map[string]any{}), nil
	})
	manager := &tokens.Manager{Repository: h.repo, Secrets: h.secrets, Provider: p}
	if err := manager.Tombstone(context.Background(), start.ConnectionID, 2); err != nil {
		t.Fatal(err)
	}
	bundle, _, err := h.secrets.Get(context.Background(), tokens.Path(start.ConnectionID))
	if err != nil || revokes != 1 || bundle.RefreshToken != "" || bundle.AccessToken != "" || bundle.State != tokens.StateTombstoned {
		t.Fatal("rejected account cleanup failed", err)
	}
}

func TestCorporateResolverFailureAfterCancellationStillPersistsCleanup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h, p := newCorporateHarness(t, ownerResolverFunc(func(ctx context.Context, id string) (CorporateIdentity, error) {
		cancel()
		return CorporateIdentity{}, ctx.Err()
	}))
	start, state, _ := beginCorporate(t, h, p, nil, nil)
	if _, err := h.service.Complete(ctx, "owner", "session", state, "code"); !errors.Is(err, ErrAccountLinking) {
		t.Fatal("cancelled resolver did not deny link", err)
	}
	assertCorporateCleanup(t, h, start.ConnectionID)
}

func TestCorporateResolverTimeoutRetainsIssuedCredentials(t *testing.T) {
	h, p := newCorporateHarness(t, ownerResolverFunc(func(ctx context.Context, id string) (CorporateIdentity, error) {
		<-ctx.Done()
		return CorporateIdentity{}, ctx.Err()
	}))
	start, state, _ := beginCorporate(t, h, p, nil, nil)
	if _, err := h.service.Complete(context.Background(), "owner", "session", state, "code"); !errors.Is(err, ErrAccountLinking) {
		t.Fatal("timed-out policy lost its cleanup write budget", err)
	}
	assertCorporateCleanup(t, h, start.ConnectionID)
}
