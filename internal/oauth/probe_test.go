package oauth

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/ufaruq/toolbox/internal/domain"
)

func TestPKCEProbeUsesFourFreshCodesAndRequiresBothNegativeRejections(t *testing.T) {
	for _, missingAccepted := range []bool{false, true} {
		t.Run(map[bool]string{false: "enforced", true: "not-enforced"}[missingAccepted], func(t *testing.T) {
			probe, err := NewPKCEProbe(GoogleConfig{ClientID: "test-client", ClientSecret: "synthetic-secret", CallbackURL: "http://127.0.0.1:8080/oauth/callback", AllowLoopbackHTTP: true})
			if err != nil {
				t.Fatal(err)
			}
			probe.provider.now = testProvider(t).now
			codes := map[string]url.Values{}
			calls, revoke := 0, 0
			probe.provider.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.URL.String() == googleJWKSEndpoint {
					return jsonHTTP(200, testJWKS(t)), nil
				}
				if r.URL.String() == googleRevocationEndpoint {
					revoke++
					return jsonHTTP(200, map[string]any{}), nil
				}
				if r.URL.String() != googleTokenEndpoint {
					t.Fatal("unexpected probe endpoint")
				}
				data, _ := io.ReadAll(r.Body)
				form, _ := url.ParseQuery(string(data))
				auth, exists := codes[form.Get("code")]
				if !exists {
					t.Fatal("code reuse or unknown code")
				}
				delete(codes, form.Get("code"))
				calls++
				if calls == 2 && !missingAccepted {
					if form.Has("code_verifier") {
						t.Fatal("missing-verifier probe sent a verifier")
					}
					return jsonHTTP(400, map[string]any{"error": "invalid_request", "error_description": "Missing code_verifier."}), nil
				}
				if calls == 3 {
					if challengeFor(form.Get("code_verifier")) == auth.Get("code_challenge") {
						t.Fatal("wrong-verifier probe used correct verifier")
					}
					return jsonHTTP(400, map[string]any{"error": "invalid_grant"}), nil
				}
				claims := testClaims(probe.provider, auth.Get("nonce"))
				claims["email"], claims["email_verified"] = "owner@example.test", true
				return jsonHTTP(200, map[string]any{"access_token": "probe-access", "refresh_token": "probe-refresh", "token_type": "Bearer", "expires_in": 3600, "scope": "openid email " + domain.DriveScope, "id_token": signTestToken(t, map[string]any{"alg": "RS256", "kid": "test-key"}, claims)}), nil
			})
			for step := 0; step < 4; step++ {
				authorization, err := probe.Begin()
				if err != nil {
					t.Fatal(err)
				}
				u, _ := url.Parse(authorization)
				state := u.Query().Get("state")
				code := string(rune('a' + step))
				codes[code] = u.Query()
				if _, err := probe.Complete(context.Background(), state+"wrong", code); err == nil {
					t.Fatal("wrong state accepted")
				}
				if step > 0 {
					before := calls
					if _, err := probe.Complete(context.Background(), state, "a"); err == nil || calls != before {
						t.Fatal("reused positive code counted as a PKCE test")
					}
				}
				result, err := probe.Complete(context.Background(), state, code)
				if missingAccepted && step == 1 {
					if err == nil {
						t.Fatal("provider without PKCE enforcement passed")
					}
					break
				}
				if err != nil || result.Done != (step == 3) {
					t.Fatal("probe outcome incorrect", step, err)
				}
				if _, err := probe.Complete(context.Background(), state, code); err == nil {
					t.Fatal("probe replay accepted")
				}
			}
			if !missingAccepted && (calls != 4 || revoke == 0) {
				t.Fatal("probe did not verify fresh final positive and clean up")
			}
			if missingAccepted && (calls != 2 || revoke == 0) {
				t.Fatal("failed probe continued or discarded known credentials")
			}
			encoded, _ := json.Marshal(probe.Status())
			if strings.Contains(string(encoded), "probe-refresh") {
				t.Fatal("probe status exposed credentials")
			}
		})
	}
}
