// Package githubfixture provides a small, credential-isolating GitHub API fixture.
// It deliberately implements only the endpoints exercised by the Docker MCP E2E test.
package githubfixture

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// Config contains synthetic credentials only. It must never be logged.
type Config struct {
	AdminToken string      `json:"admin_token"`
	Principals []Principal `json:"principals"`
}

// Principal is a fixture identity and its sole accessible repository.
type Principal struct {
	Token      string `json:"token"`
	Login      string `json:"login"`
	ID         int64  `json:"id"`
	Repository string `json:"repository"`
}

// Event is safe to log: credentials and query strings are excluded.
type Event struct {
	Principal  string `json:"principal"`
	Path       string `json:"path"`
	Repository string `json:"repository,omitempty"`
	Status     int    `json:"status"`
}

type Fixture struct {
	config  Config
	byToken map[string]Principal
	mu      sync.Mutex
	events  []Event
}

var safeName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)

func New(config Config) (*Fixture, error) {
	if config.AdminToken == "" || len(config.Principals) == 0 {
		return nil, errors.New("fixture requires an admin token and principals")
	}
	f := &Fixture{config: config, byToken: make(map[string]Principal)}
	for _, principal := range config.Principals {
		repo := strings.Split(principal.Repository, "/")
		if !strings.HasPrefix(principal.Token, "github_pat_") || principal.Token == config.AdminToken || principal.ID <= 0 || !safeName.MatchString(principal.Login) || len(repo) != 2 || !safeName.MatchString(repo[0]) || !safeName.MatchString(repo[1]) {
			return nil, errors.New("invalid synthetic fixture principal")
		}
		if _, exists := f.byToken[principal.Token]; exists {
			return nil, errors.New("duplicate fixture credential")
		}
		f.byToken[principal.Token] = principal
	}
	return f, nil
}

func (f *Fixture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-GitHub-Request-Id", "CONTROLLED-FIXTURE")
	w.Header().Set("X-GitHub-Enterprise-Version", "3.15.0")
	if r.Method != http.MethodGet {
		f.write(w, http.StatusMethodNotAllowed, map[string]string{"message": "Method not allowed"})
		return
	}
	if r.URL.Path == "/__health" {
		f.write(w, http.StatusOK, map[string]string{"status": "ok"})
		return
	}
	token := bearerToken(r.Header.Get("Authorization"))
	if r.URL.Path == "/__audit" {
		if token != f.config.AdminToken {
			f.write(w, http.StatusUnauthorized, map[string]string{"message": "Bad credentials"})
			return
		}
		f.mu.Lock()
		events := append([]Event{}, f.events...)
		f.mu.Unlock()
		f.write(w, http.StatusOK, events)
		return
	}
	principal, authenticated := f.byToken[token]
	event := Event{Principal: "unknown", Path: f.sanitize(r.URL.Path), Status: http.StatusUnauthorized}
	if !authenticated {
		f.record(event)
		f.write(w, event.Status, map[string]string{"message": "Bad credentials"})
		return
	}
	event.Principal = principal.Login
	if r.URL.Path == "/api/v3/user" {
		event.Status = http.StatusOK
		f.record(event)
		f.write(w, event.Status, user(principal))
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if len(parts) == 7 && parts[0] == "api" && parts[1] == "v3" && parts[2] == "repos" && parts[5] == "issues" {
		repository := parts[3] + "/" + parts[4]
		event.Repository = f.sanitize(repository)
		number, err := strconv.ParseInt(parts[6], 10, 64)
		if repository == principal.Repository && err == nil && number > 0 {
			event.Status = http.StatusOK
			f.record(event)
			f.write(w, event.Status, issue(principal, number))
			return
		}
	}
	// Authorization is checked before any repository data is constructed.
	event.Status = http.StatusNotFound
	f.record(event)
	f.write(w, event.Status, map[string]string{"message": "Not Found"})
}

func bearerToken(header string) string {
	parts := strings.Fields(header)
	if len(parts) != 2 || (!strings.EqualFold(parts[0], "bearer") && !strings.EqualFold(parts[0], "token")) {
		return ""
	}
	return parts[1]
}

func (f *Fixture) sanitize(value string) string {
	value = strings.ReplaceAll(value, f.config.AdminToken, "[redacted]")
	for token := range f.byToken {
		value = strings.ReplaceAll(value, token, "[redacted]")
	}
	return value
}

func (f *Fixture) record(event Event) {
	f.mu.Lock()
	f.events = append(f.events, event)
	f.mu.Unlock()
}

func (f *Fixture) write(w http.ResponseWriter, status int, value any) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func user(principal Principal) map[string]any {
	return map[string]any{
		"login": principal.Login, "id": principal.ID, "node_id": "FIXTURE_USER",
		"name": "Synthetic " + principal.Login, "type": "User", "site_admin": false,
		"url":        "https://fixture:9443/api/v3/users/" + principal.Login,
		"html_url":   "https://fixture:9443/" + principal.Login,
		"avatar_url": "https://fixture:9443/avatars/" + principal.Login,
		"created_at": "2024-01-01T00:00:00Z", "updated_at": "2024-01-02T00:00:00Z",
		"public_repos": 0, "public_gists": 0, "followers": 0, "following": 0,
	}
}

func issue(principal Principal, number int64) map[string]any {
	issueURL := "https://fixture:9443/api/v3/repos/" + principal.Repository + "/issues/" + strconv.FormatInt(number, 10)
	return map[string]any{
		"id": principal.ID*1000 + number, "node_id": "FIXTURE_ISSUE", "number": number,
		"title": "Private issue for " + principal.Login, "body": "Controlled data from " + principal.Repository,
		"state": "open", "locked": false, "user": user(principal),
		"url": issueURL, "html_url": "https://fixture:9443/" + principal.Repository + "/issues/" + strconv.FormatInt(number, 10),
		"repository_url": "https://fixture:9443/api/v3/repos/" + principal.Repository,
		"labels":         []any{}, "assignees": []any{}, "assignee": nil, "milestone": nil,
		"comments": 0, "created_at": "2024-01-01T00:00:00Z", "updated_at": "2024-01-02T00:00:00Z", "closed_at": nil,
		"author_association": "OWNER", "active_lock_reason": nil,
	}
}
