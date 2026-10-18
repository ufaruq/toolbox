package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ufaruq/toolbox/internal/connectors"
	"github.com/ufaruq/toolbox/internal/domain"
	"github.com/ufaruq/toolbox/internal/security"
	"github.com/ufaruq/toolbox/internal/store"
)

type invocationIntegration struct {
	Integration
	read func(context.Context, func(context.Context) error) (Document, error)
}

func (i invocationIntegration) Read(ctx context.Context, _, _ string, auth func(context.Context) error) (Document, error) {
	return i.read(ctx, auth)
}

// Reject writes inside the transaction so the test observes real rollback.
type invocationAuditRepository struct {
	domain.Repository
	failOutcome          string
	failedContextBounded bool
}

func (r *invocationAuditRepository) Transact(ctx context.Context, fn func(*domain.State) error) error {
	return r.Repository.Transact(ctx, func(st *domain.State) error {
		before := len(st.Audits)
		if err := fn(st); err != nil {
			return err
		}
		for _, event := range st.Audits[before:] {
			if event.Action != "tool.invocation" {
				continue
			}
			if event.Outcome == "failed" {
				deadline, ok := ctx.Deadline()
				r.failedContextBounded = ctx.Err() == nil && ok && time.Until(deadline) > 0 && time.Until(deadline) <= 5*time.Second
			}
			if event.Outcome == r.failOutcome {
				return errors.New("audit database unavailable")
			}
		}
		return nil
	})
}

func invocationFixture(t *testing.T) (*Server, *invocationAuditRepository, *http.Request) {
	t.Helper()
	repo := &invocationAuditRepository{Repository: store.NewMemory()}
	pepper := []byte(strings.Repeat("x", 32))
	id, credential, hash := security.NewCredential(pepper)
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := security.NewSigner("http://toolbox.test", "test", key)
	if err != nil {
		t.Fatal(err)
	}
	var token string
	if err := repo.Transact(context.Background(), func(st *domain.State) error {
		st.Users["owner"] = domain.User{ID: "owner", Issuer: "test", Subject: "owner", Status: "active"}
		st.Agents["agent"] = domain.Agent{ID: "agent", OwnerID: "owner", Status: "active"}
		st.Credentials[id] = domain.Credential{ID: id, AgentID: "agent", Hash: hash, Status: "active", ExpiresAt: st.Now.Add(time.Hour)}
		st.Connections["connection"] = domain.Connection{ID: "connection", OwnerID: "owner", Provider: "google_drive", Subject: "provider-owner", ClientID: "test", Status: "active", Epoch: 1, Scopes: []string{domain.DriveScope}}
		st.Resources[domain.ResourceKey("connection", "doc-A")] = domain.Resource{ConnectionID: "connection", FileID: "doc-A"}
		g := domain.Grant{ID: "grant", OwnerID: "owner", AgentID: "agent", ConnectionID: "connection", Tool: domain.Tool, Action: domain.Action, FileID: "doc-A", Epoch: 1, Version: 1, NotBefore: st.Now.Add(-time.Minute), ExpiresAt: st.Now.Add(time.Hour)}
		st.Grants[g.ID] = g
		var err error
		token, err = signer.Mint(g, st.Now)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	s, err := New(Config{Repository: repo, Signer: signer, Pepper: pepper, Origin: "http://toolbox.test"}, invocationIntegration{})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/v1/tool-invocations", strings.NewReader(`{"tool":"`+domain.Tool+`","grant_id":"grant","arguments":{"file_id":"doc-A"}}`))
	r.Header.Set("Authorization", "Bearer "+credential)
	r.Header.Set("Toolbox-Delegation", token)
	r.Header.Set("Content-Type", "application/json")
	return s, repo, r
}

func invocationEvents(t *testing.T, repo domain.Repository) []domain.Audit {
	t.Helper()
	var events []domain.Audit
	if err := repo.Transact(context.Background(), func(st *domain.State) error { events = append(events, st.Audits...); return nil }); err != nil {
		t.Fatal(err)
	}
	return events
}

func requireFailedInvocation(t *testing.T, repo domain.Repository) {
	t.Helper()
	events := invocationEvents(t, repo)
	if len(events) != 2 || events[0].Outcome != "started" || events[1].Outcome != "failed" || events[0].InvocationID != events[1].InvocationID || events[1].Bytes != 0 {
		t.Fatalf("want matching started/failed terminal audits, got %+v", events)
	}
}

func TestInvocationCancellationPersistsTerminalAudit(t *testing.T) {
	for _, scenario := range []string{"caller-cancelled-during-fetch", "deadline-during-fetch", "slot-wait-timeout"} {
		t.Run(scenario, func(t *testing.T) {
			s, repo, r := invocationFixture(t)
			var cancel context.CancelFunc
			var ctx context.Context
			if scenario == "caller-cancelled-during-fetch" {
				ctx, cancel = context.WithCancel(r.Context())
			} else {
				ctx, cancel = context.WithTimeout(r.Context(), 20*time.Millisecond)
			}
			defer cancel()
			r = r.WithContext(ctx)
			calls := 0
			s.integration = invocationIntegration{read: func(ctx context.Context, _ func(context.Context) error) (Document, error) {
				calls++
				if scenario == "caller-cancelled-during-fetch" {
					cancel()
				}
				<-ctx.Done()
				return Document{}, ctx.Err()
			}}
			if scenario == "slot-wait-timeout" {
				s.slots = make(chan struct{})
			}
			w := httptest.NewRecorder()
			s.ServeHTTP(w, r)
			if w.Code != 503 || strings.Contains(w.Body.String(), "content") {
				t.Errorf("wrong failure response: %d %s", w.Code, w.Body.String())
			}
			if scenario == "slot-wait-timeout" && calls != 0 {
				t.Error("slot timeout reached provider")
			}
			requireFailedInvocation(t, repo)
			if !repo.failedContextBounded {
				t.Error("terminal audit did not use live bounded context")
			}
		})
	}
}

func TestInvocationFinalAuthorizationDenialPersistsTerminalAudit(t *testing.T) {
	s, repo, r := invocationFixture(t)
	s.integration = invocationIntegration{read: func(ctx context.Context, auth func(context.Context) error) (Document, error) {
		if err := auth(ctx); err != nil {
			return Document{}, err
		}
		if err := repo.Transact(ctx, func(st *domain.State) error {
			g := st.Grants["grant"]
			now := st.Now
			g.RevokedAt = &now
			st.Grants[g.ID] = g
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return Document{Content: "private document"}, nil
	}}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 403 || strings.Contains(w.Body.String(), "private document") {
		t.Fatalf("final gate leaked content: %d %s", w.Code, w.Body.String())
	}
	requireFailedInvocation(t, repo)
}

func TestInvocationAuditWriteFailureFailsClosed(t *testing.T) {
	for _, outcome := range []string{"denied", "started", "failed", "succeeded"} {
		t.Run(outcome, func(t *testing.T) {
			s, repo, r := invocationFixture(t)
			repo.failOutcome = outcome
			calls := 0
			s.integration = invocationIntegration{read: func(context.Context, func(context.Context) error) (Document, error) {
				calls++
				if outcome == "failed" {
					return Document{}, connectors.ErrTooLarge
				}
				return Document{Content: "private document"}, nil
			}}
			if outcome == "denied" {
				r.Header.Set("Toolbox-Delegation", "malformed")
			}
			w := httptest.NewRecorder()
			s.ServeHTTP(w, r)
			if w.Code != 503 || !strings.Contains(w.Body.String(), "DEPENDENCY_UNAVAILABLE") {
				t.Errorf("audit storage failure misreported: %d %s", w.Code, w.Body.String())
			}
			if strings.Contains(w.Body.String(), "private document") || strings.Contains(w.Body.String(), "fixture-refresh-secret") {
				t.Error("failure response leaked provider data")
			}
			if (outcome == "denied" || outcome == "started") && calls != 0 {
				t.Error("failed initial audit permitted dispatch")
			}
			for _, event := range invocationEvents(t, repo) {
				if event.Outcome == outcome {
					t.Errorf("unpersisted event reported as committed: %+v", event)
				}
			}
			if outcome == "succeeded" {
				requireFailedInvocation(t, repo)
			}
		})
	}
}

func TestInvocationProviderFailureAuditHasNoProviderContent(t *testing.T) {
	s, repo, r := invocationFixture(t)
	s.integration = invocationIntegration{read: func(context.Context, func(context.Context) error) (Document, error) {
		return Document{}, errors.New("fixture-refresh-secret private document")
	}}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 503 {
		t.Fatalf("status %d", w.Code)
	}
	requireFailedInvocation(t, repo)
	for _, event := range invocationEvents(t, repo) {
		if event.ResourceID != "doc-A" || event.ConnectionID != "connection" || event.GrantID != "grant" || event.SubjectID != "owner" || event.ActorID != "agent" {
			t.Errorf("unexpected provider failure metadata: %+v", event)
		}
	}
}
