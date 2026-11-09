package githubapp

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestIssueScopesAndSigns(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	now := time.Now().UTC().Truncate(time.Second)
	called := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		if r.Method != "POST" || r.URL.Path != "/app/installations/42/access_tokens" {
			t.Error("wrong endpoint")
		}
		parts := strings.Split(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), ".")
		if len(parts) != 3 {
			t.Error("missing JWT")
			w.WriteHeader(401)
			return
		}
		sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
		sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
		if rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, sum[:], sig) != nil {
			t.Error("invalid signature")
		}
		raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
		var claims map[string]any
		json.Unmarshal(raw, &claims)
		if claims["iss"] != "123" || claims["exp"].(float64)-claims["iat"].(float64) > 600 {
			t.Error("invalid claims")
		}
		var in struct {
			RepositoryIDs []int64           `json:"repository_ids"`
			Permissions   map[string]string `json:"permissions"`
		}
		json.NewDecoder(r.Body).Decode(&in)
		if len(in.RepositoryIDs) != 1 || in.RepositoryIDs[0] != 99 || len(in.Permissions) != 2 || in.Permissions["contents"] != "read" || in.Permissions["metadata"] != "read" {
			t.Error("scope not explicit")
		}
		w.WriteHeader(201)
		fmt.Fprintf(w, `{"token":"secret-installation-token","expires_at":%q,"permissions":{"contents":"read","metadata":"read"},"repository_selection":"selected","repositories":[{"id":99,"full_name":"owner/repo"}]}`, now.Add(time.Hour).Format(time.RFC3339))
	}))
	defer srv.Close()
	issuer := &Issuer{appID: "123", key: key, baseURL: srv.URL, http: srv.Client(), now: func() time.Time { return now }}
	credential, err := issuer.Issue(context.Background(), 42, 99, map[string]string{"contents": "read"})
	if err != nil || credential.Token != "secret-installation-token" || called != 1 {
		t.Fatalf("issuance failed: %v", err)
	}
}

func TestIssueRejectsUntrustedScope(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	now := time.Now().UTC().Truncate(time.Second)
	cases := map[string]string{
		"other repository":     `"permissions":{"contents":"read","metadata":"read"},"repository_selection":"selected","repositories":[{"id":100}]`,
		"all repositories":     `"permissions":{"contents":"read","metadata":"read"},"repository_selection":"all","repositories":[{"id":99}]`,
		"extra permission":     `"permissions":{"contents":"write","metadata":"read"},"repository_selection":"selected","repositories":[{"id":99}]`,
		"duplicate":            `"permissions":{"contents":"read","contents":"write","metadata":"read"},"repository_selection":"selected","repositories":[{"id":99}]`,
		"missing repositories": `"permissions":{"contents":"read","metadata":"read"},"repository_selection":"selected"`,
	}
	for name, fields := range cases {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(201)
				fmt.Fprintf(w, `{"token":"secret-installation-token","expires_at":%q,%s}`, now.Add(time.Hour).Format(time.RFC3339), fields)
			}))
			defer srv.Close()
			issuer := &Issuer{appID: "123", key: key, baseURL: srv.URL, http: srv.Client(), now: func() time.Time { return now }}
			c, err := issuer.Issue(context.Background(), 42, 99, map[string]string{"contents": "read"})
			if err == nil || c.Token != "" || strings.Contains(err.Error(), "secret-installation-token") {
				t.Fatal("invalid response was not safely rejected")
			}
		})
	}
}

func TestIssueRejectsBroadRequestsBeforeNetwork(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	issuer := &Issuer{appID: "123", key: key, baseURL: "https://invalid.example", http: &http.Client{}, now: time.Now}
	for _, p := range []map[string]string{nil, {}, {"administration": "write"}, {"contents": "admin"}, {"metadata": "write"}} {
		if _, err := issuer.Issue(context.Background(), 42, 99, p); err != ErrConfiguration {
			t.Fatalf("wanted configuration rejection, got %v", err)
		}
	}
}

func TestCredentialJSONDoesNotExposeToken(t *testing.T) {
	raw, err := json.Marshal(Credential{Token: "secret-installation-token", ExpiresAt: time.Now()})
	if err != nil || strings.Contains(string(raw), "secret-installation-token") {
		t.Fatal("credential JSON exposed token")
	}
}
