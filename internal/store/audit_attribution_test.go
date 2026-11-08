package store

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/ufaruq/toolbox/internal/domain"
)

func TestPostgresAuditCallerAttribution(t *testing.T) {
	p := testPostgres(t)
	ctx := context.Background()
	var event domain.Audit
	if err := p.Transact(ctx, func(s *domain.State) error {
		event = domain.Audit{ID: "attributed-event", At: s.Now, ActorType: "agent", ActorID: "agent", SubjectID: "owner", AgentID: "agent", CallerProfileID: "profile", ClientID: "registered-client", Action: "request.created", Outcome: "allowed"}
		s.Audits = append(s.Audits, event)
		return nil
	}); err != nil {
		t.Fatalf("persist attributed event: %v", err)
	}
	if err := p.Transact(ctx, func(s *domain.State) error {
		if len(s.Audits) != 1 || !reflect.DeepEqual(s.Audits[0], event) {
			t.Fatal("audit caller attribution did not round trip")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatal(err)
	}
	reject := func(t *testing.T, fields map[string]any) {
		t.Helper()
		row := map[string]any{}
		for k, v := range payload {
			row[k] = v
		}
		row["ID"] = "rejected-event"
		for k, v := range fields {
			row[k] = v
		}
		body, err := json.Marshal(row)
		if err != nil {
			t.Fatal(err)
		}
		_, err = p.pool.Exec(ctx, "INSERT INTO audit_events(payload) VALUES($1)", body)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "23514" {
			t.Fatalf("expected payload constraint rejection, got %v", err)
		}
	}
	t.Run("unknown secret field", func(t *testing.T) { reject(t, map[string]any{"AccessToken": "secret-canary"}) })
	for _, field := range []string{"AgentID", "CallerProfileID", "ClientID"} {
		t.Run(field+" null", func(t *testing.T) { reject(t, map[string]any{field: nil}) })
		t.Run(field+" non-string", func(t *testing.T) { reject(t, map[string]any{field: 123}) })
	}
	t.Run("legacy payload remains valid", func(t *testing.T) {
		legacy := map[string]any{}
		for k, v := range payload {
			legacy[k] = v
		}
		legacy["ID"] = "legacy-event"
		for _, field := range []string{"AgentID", "CallerProfileID", "ClientID"} {
			delete(legacy, field)
		}
		body, err := json.Marshal(legacy)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := p.pool.Exec(ctx, "INSERT INTO audit_events(payload) VALUES($1)", body); err != nil {
			t.Fatal(err)
		}
		if err := p.Transact(ctx, func(s *domain.State) error {
			if len(s.Audits) != 2 || s.Audits[1].ID != "legacy-event" || s.Audits[1].AgentID != "" || s.Audits[1].CallerProfileID != "" || s.Audits[1].ClientID != "" {
				t.Fatal("legacy audit payload no longer readable")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})
}
