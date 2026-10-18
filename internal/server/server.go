// Package server exposes disjoint owner-session and agent-credential API surfaces.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ufaruq/toolbox/internal/domain"
	"github.com/ufaruq/toolbox/internal/ownerlogin"
	"github.com/ufaruq/toolbox/internal/security"
	"github.com/ufaruq/toolbox/internal/strict"
)

type Config struct {
	Repository domain.Repository
	Signer     *security.Signer
	Pepper     []byte
	Origin     string
	Fixture    bool
	OwnerOnly  bool
	OwnerLogin *ownerlogin.Service
	Readiness  func(context.Context) error
}
type Server struct {
	Config
	mux         *http.ServeMux
	limiterMu   sync.Mutex
	limits      map[string]window
	slots       chan struct{}
	integration Integration
}
type window struct {
	At    time.Time
	Count int
}

// Integration contains the provider boundary; raw provider tokens are never returned by agent APIs.
type Integration interface {
	Start(context.Context, string, string) (string, error)
	Complete(context.Context, string, string, string, string) (domain.Connection, error)
	Inspect(context.Context, string, string, func(context.Context) error) (Document, error)
	Read(context.Context, string, string, func(context.Context) error) (Document, error)
	Cleanup(context.Context, string, int64) error
	FixtureAuthorize(context.Context, string) (string, error)
}
type Document struct {
	FileID       string    `json:"file_id"`
	Name         string    `json:"name,omitempty"`
	MIME         string    `json:"mime_type"`
	Content      string    `json:"content,omitempty"`
	Bytes        int       `json:"bytes"`
	ModifiedTime string    `json:"observed_modified_time"`
	RetrievedAt  time.Time `json:"retrieved_at"`
}

func New(cfg Config, integration Integration) (*Server, error) {
	if cfg.Repository == nil || len(cfg.Pepper) < 32 || cfg.Origin == "" ||
		(cfg.OwnerOnly && (cfg.Fixture || cfg.OwnerLogin == nil || !validOwnerOrigin(cfg.Origin))) ||
		(!cfg.OwnerOnly && (cfg.Signer == nil || integration == nil || cfg.OwnerLogin != nil)) {
		return nil, errors.New("invalid server configuration")
	}
	s := &Server{Config: cfg, mux: http.NewServeMux(), limits: map[string]window{}, slots: make(chan struct{}, 8), integration: integration}
	s.routes()
	return s, nil
}
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	if (r.URL.RawQuery != "" || r.URL.ForceQuery) && r.URL.Path != "/oauth/callback" && r.URL.Path != "/fixture/authorize" && !(s.OwnerOnly && r.URL.Path == "/auth/oidc/callback") {
		fail(w, 400, "INVALID_QUERY")
		return
	}
	if r.Header.Get("X-HTTP-Method-Override") != "" || r.Header.Get("X-Method-Override") != "" {
		fail(w, 400, "INVALID_REQUEST")
		return
	}
	s.mux.ServeHTTP(w, r)
}
func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { jsonOut(w, 200, map[string]string{"status": "ok"}) })
	s.mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		check := s.Readiness
		if check == nil {
			check = s.Repository.Ping
		}
		if check(ctx) != nil {
			fail(w, 503, "DEPENDENCY_UNAVAILABLE")
			return
		}
		jsonOut(w, 200, map[string]string{"status": "ready"})
	})
	s.mux.HandleFunc("GET /v1/session", s.session)
	s.mux.HandleFunc("GET /v1/auth/config", s.authConfig)
	if s.OwnerOnly {
		s.mux.HandleFunc("POST /auth/oidc/start", s.startOwnerLogin)
		s.mux.HandleFunc("GET /auth/oidc/callback", s.ownerCallback)
		s.mux.HandleFunc("POST /v1/session/logout", s.logoutOwner)
		for _, pattern := range []string{
			"/v1/agents", "/v1/agents/", "/v1/credentials/", "/v1/connections", "/v1/connections/",
			"/v1/delegation-requests", "/v1/delegation-requests/", "/v1/delegation-tokens",
			"/v1/grants/", "/v1/tool-invocations", "/v1/audit", "/oauth/callback",
		} {
			s.mux.HandleFunc(pattern, func(w http.ResponseWriter, _ *http.Request) { fail(w, 503, "FEATURE_DISABLED") })
		}
		s.staticRoutes()
		return
	}
	s.mux.HandleFunc("POST /v1/agents", s.createAgent)
	s.mux.HandleFunc("POST /v1/agents/{id}/credentials", s.rotateCredential)
	s.mux.HandleFunc("POST /v1/credentials/{id}/revoke", s.revokeCredential)
	s.mux.HandleFunc("POST /v1/connections/google/start", s.startConnection)
	s.mux.HandleFunc("GET /oauth/callback", s.completeConnection)
	s.mux.HandleFunc("GET /v1/connections", s.connections)
	s.mux.HandleFunc("POST /v1/connections/{id}/disconnect", s.disconnect)
	s.mux.HandleFunc("POST /v1/delegation-requests", s.createRequest)
	s.mux.HandleFunc("GET /v1/delegation-requests/{id}", s.pollRequest)
	s.mux.HandleFunc("POST /v1/delegation-requests/{id}/review", s.reviewRequest)
	s.mux.HandleFunc("POST /v1/delegation-requests/{id}/approve", s.approveRequest)
	s.mux.HandleFunc("POST /v1/delegation-requests/{id}/deny", s.denyRequest)
	s.mux.HandleFunc("POST /v1/delegation-tokens", s.mintToken)
	s.mux.HandleFunc("POST /v1/grants/{id}/revoke", s.revokeGrant)
	s.mux.HandleFunc("POST /v1/tool-invocations", s.invoke)
	s.mux.HandleFunc("GET /v1/audit", s.audit)
	s.staticRoutes()
	if s.Fixture {
		s.mux.HandleFunc("POST /fixture/login", s.fixtureLogin)
		s.mux.HandleFunc("GET /fixture/authorize", s.fixtureAuthorize)
	}
}

func (s *Server) staticRoutes() {
	if s.OwnerOnly {
		s.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/" {
				http.NotFound(w, r)
				return
			}
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				w.Header().Set("Allow", "GET, HEAD")
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			s.home(w, r)
		})
	} else {
		s.mux.HandleFunc("GET /", s.home)
	}
	s.mux.HandleFunc("GET /app.js", s.appJS)
	s.mux.HandleFunc("GET /app.css", s.appCSS)
}
func jsonOut(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, status int, code string) {
	jsonOut(w, status, map[string]string{"error": code})
}
func body(w http.ResponseWriter, r *http.Request, v any) bool {
	if r.Header.Get("Content-Type") != "application/json" {
		fail(w, 400, "INVALID_CONTENT_TYPE")
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	b, e := io.ReadAll(r.Body)
	if e != nil || strict.Decode(b, v) != nil {
		fail(w, 400, "INVALID_SCHEMA")
		return false
	}
	return true
}
func (s *Server) allowed(key string, limit int) bool {
	s.limiterMu.Lock()
	defer s.limiterMu.Unlock()
	now := time.Now()
	v := s.limits[key]
	if now.Sub(v.At) >= time.Minute {
		v = window{At: now}
	}
	v.Count++
	s.limits[key] = v
	return v.Count <= limit
}
func (s *Server) owner(r *http.Request, mutate bool) (domain.Session, error) {
	var out domain.Session
	c, e := r.Cookie("toolbox_session")
	if e != nil || len(c.Value) != 43 {
		return out, domain.ErrDenied
	}
	if mutate && (r.Header.Get("Origin") != s.Origin || r.Header.Get("Sec-Fetch-Site") == "cross-site") {
		return out, domain.ErrDenied
	}
	e = s.Repository.Transact(r.Context(), func(st *domain.State) error {
		v, ok := st.Sessions[security.Hash(c.Value)]
		u := st.Users[v.UserID]
		if !ok || !st.Now.Before(v.ExpiresAt) || u.Status != "active" {
			return domain.ErrDenied
		}
		if s.OwnerOnly && !s.OwnerLogin.SessionBound(st, v.ID) {
			return domain.ErrDenied
		}
		if mutate && !security.Equal(v.CSRFHash, security.Hash(r.Header.Get("X-CSRF-Token"))) {
			return domain.ErrDenied
		}
		out = v
		return nil
	})
	return out, e
}
func (s *Server) requireOwner(w http.ResponseWriter, r *http.Request, mutate bool) (domain.Session, bool) {
	v, e := s.owner(r, mutate)
	if e != nil {
		fail(w, 403, "NOT_AUTHORIZED")
		return v, false
	}
	return v, true
}
func (s *Server) agent(r *http.Request) (domain.Agent, string, error) {
	var a domain.Agent
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return a, "", domain.ErrDenied
	}
	id, secret, e := security.CredentialParts(strings.TrimPrefix(h, "Bearer "))
	if e != nil {
		return a, "", domain.ErrDenied
	}
	e = s.Repository.Transact(r.Context(), func(st *domain.State) error {
		c, ok := st.Credentials[id]
		v := st.Agents[c.AgentID]
		if !ok || !credentialActive(st, id, v.ID) || !security.Equal(c.Hash, security.KeyedHash(s.Pepper, secret)) {
			return domain.ErrDenied
		}
		a = v
		return nil
	})
	return a, id, e
}
func credentialActive(st *domain.State, id, agentID string) bool {
	c, ok := st.Credentials[id]
	a := st.Agents[agentID]
	u := st.Users[a.OwnerID]
	return ok && c.AgentID == agentID && c.Status == "active" && st.Now.Before(c.ExpiresAt) && a.Status == "active" && u.Status == "active"
}
func (s *Server) requireAgent(w http.ResponseWriter, r *http.Request) (domain.Agent, string, bool) {
	a, id, e := s.agent(r)
	if e != nil {
		fail(w, 401, "INVALID_AGENT_CREDENTIAL")
		return a, id, false
	}
	if !s.allowed(a.ID, 120) {
		fail(w, 429, "RATE_LIMITED")
		return a, id, false
	}
	return a, id, true
}
func addAudit(st *domain.State, actorType, actorID, subject, action, grant, connection, resource, outcome, invocation string, bytes int) {
	st.Audits = append(st.Audits, domain.Audit{ID: security.ID(), At: st.Now, ActorType: actorType, ActorID: actorID, SubjectID: subject, Action: action, GrantID: grant, ConnectionID: connection, ResourceID: resource, Outcome: outcome, InvocationID: invocation, Bytes: bytes})
}
func grantCheck(st *domain.State, agentID, credentialID, grantID, fileID string, c *security.Claims) (domain.Grant, error) {
	g, ok := st.Grants[grantID]
	if !ok || g.AgentID != agentID || !credentialActive(st, credentialID, agentID) {
		return domain.Grant{}, domain.ErrDenied
	}
	conn := st.Connections[g.ConnectionID]
	if g.RevokedAt != nil {
		return g, errors.New("GRANT_REVOKED")
	}
	if !st.Now.Before(g.ExpiresAt) || st.Now.Before(g.NotBefore) {
		return g, errors.New("GRANT_EXPIRED")
	}
	if fileID != g.FileID {
		return g, errors.New("RESOURCE_NOT_ALLOWED")
	}
	if conn.Status != "active" || conn.Epoch != g.Epoch || conn.OwnerID != g.OwnerID || conn.Provider != "google_drive" || conn.Subject == "" || !domain.HasScope(conn.Scopes, domain.DriveScope) {
		return g, errors.New("CONNECTION_UNAVAILABLE")
	}
	if st.Agents[agentID].OwnerID != g.OwnerID || g.Tool != domain.Tool || g.Action != domain.Action || g.Version != 1 {
		return g, domain.ErrDenied
	}
	if _, ok := st.Resources[domain.ResourceKey(conn.ID, fileID)]; !ok {
		return g, domain.ErrDenied
	}
	if c != nil && (!c.Matches(g) || c.ExpiresAt <= st.Now.Unix()) {
		return g, domain.ErrDenied
	}
	return g, nil
}
