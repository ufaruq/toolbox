package githubfixture

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func fixtureForTest(t *testing.T) (*Fixture, Config) {
	t.Helper()
	config := Config{
		AdminToken: "synthetic-admin-credential",
		Principals: []Principal{
			{Token: "github_pat_fixture_a", Login: "alice", ID: 101, Repository: "alice/private-a"},
			{Token: "github_pat_fixture_b", Login: "bob", ID: 102, Repository: "bob/private-b"},
		},
	}
	fixture, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	return fixture, config
}

func request(fixture http.Handler, path, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	response := httptest.NewRecorder()
	fixture.ServeHTTP(response, req)
	return response
}

func TestPrincipalAndRepositoryIsolation(t *testing.T) {
	fixture, config := fixtureForTest(t)
	for _, principal := range config.Principals {
		t.Run(principal.Login, func(t *testing.T) {
			profile := request(fixture, "/api/v3/user", principal.Token)
			if profile.Code != http.StatusOK {
				t.Fatalf("profile status = %d", profile.Code)
			}
			var decoded map[string]any
			if err := json.Unmarshal(profile.Body.Bytes(), &decoded); err != nil {
				t.Fatal(err)
			}
			if decoded["login"] != principal.Login || decoded["id"] != float64(principal.ID) {
				t.Fatalf("unexpected profile: %v", decoded)
			}
			for _, repositoryOwner := range config.Principals {
				issue := request(fixture, "/api/v3/repos/"+repositoryOwner.Repository+"/issues/7", principal.Token)
				want := http.StatusNotFound
				if repositoryOwner.Login == principal.Login {
					want = http.StatusOK
				}
				if issue.Code != want {
					t.Fatalf("issue %s status = %d, want %d", repositoryOwner.Repository, issue.Code, want)
				}
				if want == http.StatusNotFound && strings.Contains(issue.Body.String(), repositoryOwner.Login) {
					t.Fatal("cross-repository response disclosed owner data")
				}
			}
		})
	}
	if got := request(fixture, "/api/v3/user", "unknown").Code; got != http.StatusUnauthorized {
		t.Fatalf("unknown credential status = %d", got)
	}
	if got := request(fixture, "/__health", "").Code; got != http.StatusOK {
		t.Fatalf("health status = %d", got)
	}
}

func TestAuditIsAuthenticatedSanitizedAndConcurrent(t *testing.T) {
	fixture, config := fixtureForTest(t)
	var workers sync.WaitGroup
	for _, principal := range config.Principals {
		workers.Go(func() {
			request(fixture, "/api/v3/user", principal.Token)
			request(fixture, "/api/v3/repos/other/"+principal.Token+"/issues/1?token="+principal.Token, principal.Token)
		})
	}
	workers.Wait()
	if got := request(fixture, "/__audit", config.Principals[0].Token).Code; got != http.StatusUnauthorized {
		t.Fatalf("principal audit status = %d", got)
	}
	audit := request(fixture, "/__audit", config.AdminToken)
	if audit.Code != http.StatusOK {
		t.Fatalf("admin audit status = %d", audit.Code)
	}
	for _, principal := range config.Principals {
		if strings.Contains(audit.Body.String(), principal.Token) {
			t.Fatal("audit contains synthetic credential")
		}
	}
	if strings.Contains(audit.Body.String(), config.AdminToken) || strings.Contains(audit.Body.String(), "?token=") {
		t.Fatal("audit contains credential or query")
	}
	var events []Event
	if err := json.Unmarshal(audit.Body.Bytes(), &events); err != nil {
		t.Fatal(err)
	}
	if len(events) != 4 {
		t.Fatalf("audit has %d events, want 4", len(events))
	}
	for _, event := range events {
		if event.Principal != "alice" && event.Principal != "bob" {
			t.Fatalf("unexpected audit principal %q", event.Principal)
		}
	}
}

func TestInvalidConfigurationDoesNotDiscloseCredentials(t *testing.T) {
	_, config := fixtureForTest(t)
	config.Principals[1].Token = config.Principals[0].Token
	_, err := New(config)
	if err == nil {
		t.Fatal("duplicate credentials accepted")
	}
	if strings.Contains(err.Error(), config.Principals[0].Token) {
		t.Fatal("configuration error disclosed credential")
	}
}
