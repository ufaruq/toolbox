package store

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/ufaruq/toolbox/internal/domain"
)

// Use the persisted JSON contract so these tests can demonstrate missing record
// support before the domain types are introduced.
func recordState(t *testing.T, s *domain.State) map[string]any {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}
func applyRecords(t *testing.T, s *domain.State, records map[string]any) {
	t.Helper()
	b, err := json.Marshal(records)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, s); err != nil {
		t.Fatal(err)
	}
}
func callerRecords(now time.Time) map[string]any {
	return map[string]any{
		"CallerProfiles": map[string]any{"p1": map[string]any{
			"ID": "p1", "OwnerID": "u1", "AgentID": "a1", "Issuer": "https://issuer.example", "UserID": "u1", "ClientID": "cli1", "Label": "Desktop", "Status": "active", "Tools": []any{domain.Tool}, "ApprovedAt": now, "ExpiresAt": now.Add(time.Hour),
		}},
	}
}
func exerciseCallerRecords(t *testing.T, r domain.Repository) {
	t.Helper()
	ctx := context.Background()
	seed(t, r)
	if err := r.Transact(ctx, func(s *domain.State) error {
		applyRecords(t, s, callerRecords(s.Now))
		s.Agents["a3"] = domain.Agent{ID: "a3", OwnerID: "u1", Status: "active"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	t.Run("persist records", func(t *testing.T) {
		if err := r.Transact(ctx, func(s *domain.State) error {
			got := recordState(t, s)
			for collection, id := range map[string]string{"CallerProfiles": "p1"} {
				records, ok := got[collection].(map[string]any)
				if !ok {
					t.Errorf("missing %s", collection)
					continue
				}
				if _, ok := records[id]; !ok {
					t.Errorf("missing %s record", collection)
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})
	invalidChanges := map[string]func(map[string]any){
		"nil profiles":                    func(s map[string]any) { s["CallerProfiles"] = nil },
		"otherwise valid agent rebinding": func(s map[string]any) { s["CallerProfiles"].(map[string]any)["p1"].(map[string]any)["AgentID"] = "a3" },
		"otherwise valid owner identity rebinding": func(s map[string]any) {
			p := s["CallerProfiles"].(map[string]any)["p1"].(map[string]any)
			p["OwnerID"], p["UserID"], p["AgentID"], p["ClientID"] = "u2", "u2", "a2", "cli2"
		},
	}
	for _, field := range []string{"OwnerID", "AgentID", "Issuer", "UserID", "ClientID"} {
		field := field
		invalidChanges["immutable profile "+field] = func(s map[string]any) { s["CallerProfiles"].(map[string]any)["p1"].(map[string]any)[field] = "changed" }
	}
	for name, change := range invalidChanges {
		t.Run(name, func(t *testing.T) {
			err := r.Transact(ctx, func(s *domain.State) error {
				records := recordState(t, s)
				// Feature support is asserted separately; populate absent collections so
				// unsupported repositories fail invariants rather than panicking here.
				for k, v := range callerRecords(s.Now) {
					if records[k] == nil {
						records[k] = v
					}
				}
				change(records)
				applyRecords(t, s, records)
				return nil
			})
			if !errors.Is(err, ErrInvariant) {
				t.Fatalf("wanted invariant rejection, got %v", err)
			}
		})
	}
	profileCases := map[string]map[string]any{
		"duplicate identity":                    {"AgentID": "a3"},
		"duplicate agent":                       {"ClientID": "cli2"},
		"owner mismatch":                        {"OwnerID": "u2", "AgentID": "a2", "ClientID": "cli2"},
		"agent owner mismatch":                  {"AgentID": "a2", "ClientID": "cli2"},
		"missing owner":                         {"OwnerID": "missing", "AgentID": "a3", "ClientID": "cli2"},
		"missing agent":                         {"AgentID": "missing", "ClientID": "cli2"},
		"issuer owner mismatch":                 {"Issuer": "https://other.example", "AgentID": "a3", "ClientID": "cli2"},
		"uid owner mismatch":                    {"UserID": "other", "AgentID": "a3", "ClientID": "cli2"},
		"invalid status":                        {"Status": "pending", "AgentID": "a3", "ClientID": "cli2"},
		"missing approval":                      {"ApprovedAt": time.Time{}, "AgentID": "a3", "ClientID": "cli2"},
		"missing expiry":                        {"ExpiresAt": time.Time{}, "AgentID": "a3", "ClientID": "cli2"},
		"expiry at zero after ancient approval": {"ApprovedAt": time.Date(0, 1, 1, 0, 0, 0, 0, time.UTC), "ExpiresAt": time.Time{}, "AgentID": "a3", "ClientID": "cli2"},
		"expiry before approval":                {"ExpiresAt": time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC), "AgentID": "a3", "ClientID": "cli2"},
	}
	for name, fields := range profileCases {
		t.Run(name, func(t *testing.T) {
			err := r.Transact(ctx, func(s *domain.State) error {
				records := callerRecords(s.Now)
				p := records["CallerProfiles"].(map[string]any)["p1"].(map[string]any)
				p["ID"] = "p2"
				for k, v := range fields {
					p[k] = v
				}
				current := recordState(t, s)
				profiles, ok := current["CallerProfiles"].(map[string]any)
				if !ok {
					profiles = map[string]any{}
				}
				profiles["p2"] = p
				s.Agents["a3"] = domain.Agent{ID: "a3", OwnerID: "u1", Status: "active"}
				applyRecords(t, s, map[string]any{"CallerProfiles": profiles})
				return nil
			})
			if !errors.Is(err, ErrInvariant) {
				t.Fatalf("wanted invariant rejection, got %v", err)
			}
		})
	}
	t.Run("owner identity cannot drift", func(t *testing.T) {
		err := r.Transact(ctx, func(s *domain.State) error { u := s.Users["u1"]; u.Subject = "changed"; s.Users[u.ID] = u; return nil })
		if !errors.Is(err, ErrInvariant) {
			t.Fatalf("wanted invariant rejection, got %v", err)
		}
	})
	t.Run("disable and update label", func(t *testing.T) {
		if err := r.Transact(ctx, func(s *domain.State) error {
			records := recordState(t, s)
			if records["CallerProfiles"] == nil {
				return errors.New("profiles unavailable")
			}
			p := records["CallerProfiles"].(map[string]any)["p1"].(map[string]any)
			p["Status"] = "disabled"
			p["Label"] = "Renamed"
			applyRecords(t, s, records)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})
}
func TestMemoryCallerRecords(t *testing.T)   { exerciseCallerRecords(t, NewMemory()) }
func TestPostgresCallerRecords(t *testing.T) { exerciseCallerRecords(t, testPostgres(t)) }

func TestMemoryCallerRecordExpiryAndHashes(t *testing.T) {
	for _, collection := range []string{"CallerProfiles"} {
		fields := []string{"ExpiresAt"}
		for _, field := range fields {
			t.Run(collection+" missing "+field, func(t *testing.T) {
				r := NewMemory()
				seed(t, r)
				err := r.Transact(context.Background(), func(s *domain.State) error {
					records := callerRecords(s.Now)
					id := "p1"
					v := records[collection].(map[string]any)[id].(map[string]any)
					if field == "ExpiresAt" {
						v[field] = time.Time{}
					} else {
						v[field] = ""
					}
					applyRecords(t, s, records)
					return nil
				})
				if !errors.Is(err, ErrInvariant) {
					t.Fatalf("wanted invariant rejection, got %v", err)
				}
			})
		}
	}
}

func TestPostgresCallerDatabaseConstraints(t *testing.T) {
	p := testPostgres(t)
	seed(t, p)
	ctx := context.Background()
	if err := p.Transact(ctx, func(s *domain.State) error {
		applyRecords(t, s, callerRecords(s.Now))
		s.Agents["a3"] = domain.Agent{ID: "a3", OwnerID: "u1", Status: "active"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	reject := func(t *testing.T, query string, args ...any) {
		t.Helper()
		_, err := p.pool.Exec(ctx, query, args...)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || len(pgErr.Code) < 2 || pgErr.Code[:2] != "23" {
			t.Fatalf("expected SQL integrity rejection, got %v", err)
		}
	}
	for _, field := range []string{"ID", "OwnerID", "AgentID", "Issuer", "UserID", "ClientID"} {
		t.Run("immutable "+field, func(t *testing.T) {
			reject(t, "UPDATE caller_profiles SET payload=jsonb_set(payload,ARRAY[$1],to_jsonb('changed'::text)) WHERE id='p1'", field)
		})
	}
	for name, query := range map[string]string{
		"owner identity drift": `UPDATE users SET payload=jsonb_set(payload,'{Subject}','"changed"') WHERE id='u1'`,
		"raw token prohibited": `UPDATE caller_profiles SET payload=payload || '{"AccessToken":"secret"}'::jsonb WHERE id='p1'`,
	} {
		t.Run(name, func(t *testing.T) { reject(t, query) })
	}
	for name, fields := range map[string]map[string]any{
		"unique tuple": {"AgentID": "a3"}, "unique agent": {"ClientID": "cli2"}, "owner identity": {"AgentID": "a3", "ClientID": "cli2", "UserID": "other"}, "agent owner": {"AgentID": "a2", "ClientID": "cli2"}, "status": {"AgentID": "a3", "ClientID": "cli2", "Status": "pending"}, "expiry": {"AgentID": "a3", "ClientID": "cli2", "ExpiresAt": time.Time{}},
	} {
		t.Run(name, func(t *testing.T) {
			records := callerRecords(time.Now())
			profile := records["CallerProfiles"].(map[string]any)["p1"].(map[string]any)
			profile["ID"] = "p2"
			for k, v := range fields {
				profile[k] = v
			}
			body, err := json.Marshal(profile)
			if err != nil {
				t.Fatal(err)
			}
			reject(t, "INSERT INTO caller_profiles(payload) VALUES($1)", body)
		})
	}
}

func TestNewStateCallerMaps(t *testing.T) {
	state := recordState(t, domain.NewState())
	for _, name := range []string{"CallerProfiles"} {
		if !reflect.DeepEqual(state[name], map[string]any{}) {
			t.Errorf("%s not initialized", name)
		}
	}
}
