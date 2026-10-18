package app_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ufaruq/toolbox/internal/domain"
	"github.com/ufaruq/toolbox/internal/store"
)

func TestDeniedInvocationsCommitOwnerScopedAuditBeforeAnyDispatch(t *testing.T) {
	for _, reason := range []string{"resource", "revoked", "expired", "invalid-token", "foreign-grant"} {
		t.Run(reason, func(t *testing.T) {
			var offset atomic.Int64
			h := newHarness(t, store.NewMemoryWithClock(func() time.Time { return time.Now().Add(time.Duration(offset.Load())) }))
			h.approve()
			file := "doc-A"
			switch reason {
			case "resource":
				file = "doc-B"
			case "invalid-token":
				h.delegation = "malformed-delegation-token"
			case "revoked":
				h.call("POST", "/v1/grants/"+h.grant+"/revoke", map[string]any{}, "", "", 200)
			case "expired":
				offset.Store(int64(2 * time.Hour))
			case "foreign-grant":
				if err := h.repo.Transact(context.Background(), func(st *domain.State) error {
					st.Users["foreign-owner"] = domain.User{ID: "foreign-owner", Issuer: "fixture", Subject: "foreign", Status: "active"}
					st.Agents["foreign-agent"] = domain.Agent{ID: "foreign-agent", OwnerID: "foreign-owner", Status: "active"}
					c := st.Connections[h.connection]
					c.ID, c.OwnerID = "foreign-connection", "foreign-owner"
					st.Connections[c.ID] = c
					st.Resources[domain.ResourceKey(c.ID, "foreign-document")] = domain.Resource{ConnectionID: c.ID, FileID: "foreign-document"}
					g := st.Grants[h.grant]
					g.ID, g.OwnerID, g.AgentID, g.ConnectionID, g.FileID = "foreign-grant", c.OwnerID, "foreign-agent", c.ID, "foreign-document"
					st.Grants[g.ID] = g
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				h.grant, file = "foreign-grant", "foreign-document"
			}
			before, reads := h.drive.Calls.Load(), h.secrets.Reads.Load()
			h.invoke(file, 403)
			if before != h.drive.Calls.Load() || reads != h.secrets.Reads.Load() {
				t.Fatal("denial crossed provider/secret boundary")
			}
			if err := h.repo.Transact(context.Background(), func(st *domain.State) error {
				count := 0
				for _, event := range st.Audits {
					if event.Action != "tool.invocation" {
						continue
					}
					count++
					if event.Outcome != "denied" || event.ActorID != h.agentID || event.SubjectID != st.Agents[h.agentID].OwnerID || event.InvocationID == "" {
						t.Errorf("incorrect denial audit: %+v", event)
					}
					if event.GrantID != "" || event.ConnectionID != "" || event.ResourceID != "" {
						t.Errorf("denial retained untrusted identifiers: %+v", event)
					}
					b, _ := json.Marshal(event)
					if strings.Contains(string(b), "foreign-") || strings.Contains(string(b), "malformed-delegation-token") {
						t.Error("untrusted metadata leaked")
					}
				}
				if count != 1 {
					t.Errorf("want one committed denial, got %d", count)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCancellationDuringProviderExportPersistsFailure(t *testing.T) {
	h := newHarness(t, nil)
	h.approve()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.drive.Before = func(r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/export") {
			cancel()
		}
	}
	r := httptest.NewRequest("POST", "/v1/tool-invocations", strings.NewReader(`{"tool":"`+domain.Tool+`","grant_id":"`+h.grant+`","arguments":{"file_id":"doc-A"}}`)).WithContext(ctx)
	r.Header.Set("Authorization", "Bearer "+h.credential)
	r.Header.Set("Toolbox-Delegation", h.delegation)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.api.ServeHTTP(w, r)
	if ctx.Err() == nil || w.Code != 503 || strings.Contains(w.Body.String(), "Synthetic document") {
		t.Fatalf("cancelled export response: %d %s", w.Code, w.Body.String())
	}
	if err := h.repo.Transact(context.Background(), func(st *domain.State) error {
		var events []domain.Audit
		for _, event := range st.Audits {
			if event.Action == "tool.invocation" {
				events = append(events, event)
			}
		}
		if len(events) != 2 || events[0].Outcome != "started" || events[1].Outcome != "failed" || events[0].InvocationID != events[1].InvocationID {
			t.Errorf("missing terminal export failure: %+v", events)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
