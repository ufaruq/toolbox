package githubapp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDiscoveryMetadataScopeAndRevocation(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	now := time.Now()
	revoked := false
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/app/installations/42":
			if strings.Count(r.Header.Get("Authorization"), ".") != 2 {
				t.Error("missing App JWT")
			}
			fmt.Fprint(w, `{"id":42,"app_id":123,"repository_selection":"selected","additional":"ignored"}`)
		case "/app/installations/42/access_tokens":
			var b [2048]byte
			n, _ := r.Body.Read(b[:])
			if string(b[:n]) != `{"permissions":{"metadata":"read"}}` {
				t.Error("broad discovery scope")
			}
			w.WriteHeader(201)
			fmt.Fprintf(w, `{"token":"metadata-discovery-secret","permissions":{"metadata":"read"},"repository_selection":"selected","expires_at":%q}`, now.Add(time.Hour).Format(time.RFC3339))
		case "/installation/repositories":
			fmt.Fprint(w, `{"total_count":1,"repositories":[{"id":99,"name":"repo","owner":{"login":"owner"}}]}`)
		case "/installation/token":
			revoked = true
			w.WriteHeader(204)
		default:
			t.Error("unexpected endpoint")
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	i := &Issuer{appID: "123", key: key, baseURL: srv.URL, http: srv.Client(), now: func() time.Time { return now }}
	repos, e := i.Repositories(context.Background(), 42)
	if e != nil || len(repos) != 1 || !revoked {
		t.Fatalf("discovery failed: %v revoked=%v", e, revoked)
	}
}
