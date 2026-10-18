package oauth

import (
	"context"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/ufaruq/toolbox/internal/domain"
	"github.com/ufaruq/toolbox/internal/security"
	"github.com/ufaruq/toolbox/internal/store"
	"github.com/ufaruq/toolbox/internal/tokens"
)

// Exercise the real Google response parser through the manager: a known token
// rotation must remain available for cleanup even when the response is rejected.
func TestGoogleRejectedRefreshRetainsCleanupThroughManager(t *testing.T) {
	for _, mode := range []string{"scope-loss", "empty-scope", "broader-scope", "zero-expiry", "malformed-expiry", "missing-access", "malformed-access", "wrong-token-type", "malformed-scope", "malformed-refresh", "rejected-access-only", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			p, manager, secrets := googleRefreshHarness(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			refreshCalls, revokeCalls := 0, 0
			cleanupToken := "rotated-refresh"
			if mode == "malformed-refresh" || mode == "rejected-access-only" {
				cleanupToken = "new-access"
			}
			p.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
				switch r.URL.String() {
				case googleTokenEndpoint:
					refreshCalls++
					response := map[string]any{"access_token": "new-access", "refresh_token": "rotated-refresh", "expires_in": 3600, "token_type": "Bearer", "scope": "openid " + domain.DriveScope}
					switch mode {
					case "scope-loss", "cancelled":
						response["scope"] = "openid"
					case "broader-scope":
						response["scope"] = "openid " + domain.DriveScope + " https://www.googleapis.com/auth/drive"
					case "empty-scope":
						response["scope"] = ""
					case "zero-expiry":
						response["expires_in"] = 0
					case "malformed-expiry":
						response["expires_in"] = "invalid"
					case "missing-access":
						delete(response, "access_token")
					case "malformed-access":
						response["access_token"] = []string{"invalid"}
					case "wrong-token-type":
						response["token_type"] = "MAC"
					case "malformed-scope":
						response["scope"] = []string{"invalid"}
					case "malformed-refresh":
						response["refresh_token"] = []string{"invalid"}
					case "rejected-access-only":
						delete(response, "refresh_token")
						response["scope"] = "openid"
					}
					result := jsonHTTP(http.StatusOK, response)
					if mode == "cancelled" {
						result.Body = &cancelAfterRead{ReadCloser: result.Body, cancel: cancel}
					}
					return result, nil
				case googleRevocationEndpoint:
					revokeCalls++
					if err := r.ParseForm(); err != nil || r.PostForm.Get("token") != cleanupToken {
						t.Fatal("cleanup did not revoke the known rotated credential")
					}
					if revokeCalls == 1 {
						return jsonHTTP(http.StatusServiceUnavailable, map[string]any{}), nil
					}
					return jsonHTTP(http.StatusOK, map[string]any{}), nil
				default:
					t.Fatal("unexpected provider endpoint")
					return nil, ErrProvider
				}
			})
			allow := func(c context.Context) error { return c.Err() }
			if token, err := manager.Access(ctx, "c", allow); err == nil || token != "" {
				t.Fatal("invalid response released an access token")
			}
			b, _, err := secrets.Get(context.Background(), tokens.Path("c"))
			if err != nil || b.State != tokens.StateCleanup || b.Generation != 2 || b.Epoch != 1 || !b.Expiry.IsZero() {
				t.Fatal("rejected known rotation was not durably retained for cleanup", err)
			}
			if cleanupToken == "new-access" {
				if b.AccessToken != "new-access" || b.RefreshToken != "" {
					t.Fatal("known access credential lost behind an old refresh credential")
				}
			} else if b.RefreshToken != "rotated-refresh" || b.AccessToken != "" || !b.Expiry.IsZero() {
				t.Fatal("known refresh credential lost")
			}
			if err := manager.Tombstone(context.Background(), "c", 1); !errors.Is(err, tokens.ErrUnavailable) {
				t.Fatal("failed revocation did not remain pending", err)
			}
			b, _, err = secrets.Get(context.Background(), tokens.Path("c"))
			if err != nil || b.State != tokens.StateTombstoned || b.RefreshToken == "" && b.AccessToken == "" {
				t.Fatal("retry credential lost after revocation failure", err)
			}
			if err := manager.Tombstone(context.Background(), "c", 1); err != nil {
				t.Fatal(err)
			}
			b, _, err = secrets.Get(context.Background(), tokens.Path("c"))
			if err != nil || b.RefreshToken != "" || b.AccessToken != "" {
				t.Fatal("revoked credentials retained in current secret", err)
			}
			if token, err := manager.Access(context.Background(), "c", allow); err == nil || token != "" || refreshCalls != 1 || revokeCalls != 2 {
				t.Fatal("cleanup replayed a refresh or reactivated the connection")
			}
		})
	}
}

func googleRefreshHarness(t *testing.T) (*GoogleProvider, *tokens.Manager, *tokens.MemorySecretStore) {
	t.Helper()
	p := testProvider(t)
	repo := store.NewMemoryWithClock(p.now)
	secrets := tokens.NewMemorySecretStore()
	scopes := []string{"openid", domain.DriveScope}
	if err := repo.Transact(context.Background(), func(s *domain.State) error {
		s.Users["owner"] = domain.User{ID: "owner", Issuer: "fixture", Subject: "owner", Status: "active"}
		s.Connections["c"] = domain.Connection{ID: "c", OwnerID: "owner", Provider: "google_drive", Subject: "subject", ClientID: p.clientID, Status: "active", Epoch: 1, Scopes: scopes}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := secrets.Put(context.Background(), tokens.Path("c"), tokens.Bundle{ConnectionID: "c", Subject: "subject", ClientID: p.clientID, Epoch: 1, Generation: 1, OperationID: "initial", AccessToken: "old-access", RefreshToken: "old-refresh", Expiry: p.now().Add(-time.Minute), Scopes: scopes, State: tokens.StateActive}, 0); err != nil {
		t.Fatal(err)
	}
	return p, &tokens.Manager{Repository: repo, Secrets: secrets, Provider: p, Now: p.now}, secrets
}

func TestGoogleRefreshOmittedScopeInheritsStoredGrant(t *testing.T) {
	p, manager, secrets := googleRefreshHarness(t)
	calls := 0
	p.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return jsonHTTP(http.StatusOK, map[string]any{"access_token": "new-access", "expires_in": 3600, "token_type": "Bearer"}), nil
	})
	for range 2 {
		if token, err := manager.Access(context.Background(), "c", func(context.Context) error { return nil }); err != nil || token != "new-access" {
			t.Fatal("omitted scope rejected the existing grant", err)
		}
	}
	b, _, err := secrets.Get(context.Background(), tokens.Path("c"))
	if err != nil || b.State != tokens.StateActive || b.RefreshToken != "old-refresh" || b.Generation != 2 || !exactScopes(b.Scopes) || calls != 1 {
		t.Fatal("omitted refresh fields changed the stored grant", err)
	}
}

type cancelAfterRead struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (r *cancelAfterRead) Read(p []byte) (int, error) {
	n, err := r.ReadCloser.Read(p)
	if err == io.EOF {
		r.cancel()
	}
	return n, err
}

func TestGoogleExchangeRejectedResponseRetainsKnownCredentials(t *testing.T) {
	for _, mode := range []string{"bad-expiry", "bad-identity", "scope-loss"} {
		t.Run(mode, func(t *testing.T) {
			p := testProvider(t)
			nonce, verifier := security.Random(), security.Random()
			idToken := "invalid"
			if mode == "scope-loss" {
				idToken = signTestToken(t, map[string]any{"alg": "RS256", "kid": "test-key"}, testClaims(p, nonce))
				p.keys["test-key"] = &signingTestKey(t).PublicKey
				p.keysExpire = p.now().Add(time.Hour)
			}
			p.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
				response := map[string]any{"access_token": "known-access", "refresh_token": "known-refresh", "token_type": "Bearer", "expires_in": 3600, "scope": "openid " + domain.DriveScope, "id_token": idToken}
				if mode == "bad-expiry" {
					response["expires_in"] = 0
				} else if mode == "scope-loss" {
					response["scope"] = "openid"
				}
				return jsonHTTP(http.StatusOK, response), nil
			})
			result, err := p.Exchange(context.Background(), "code", verifier, security.Hash(nonce))
			if err == nil || result.AccessToken != "known-access" || result.RefreshToken != "known-refresh" {
				t.Fatal("exchange rejected a known response without cleanup credentials")
			}
			if mode == "scope-loss" {
				if !errors.Is(err, ErrScope) || result.Subject != "google-subject" {
					t.Fatal("scope rejection did not preserve the verified identity for cleanup", err)
				}
			} else if result.Subject != "" {
				t.Fatal("rejected identity was treated as verified")
			}
		})
	}
}
