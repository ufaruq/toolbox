package mcpclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// rawReviewGateway keeps the provider request bytes visible and can model a
// stateful gateway without relying on the SDK server's graceful close behavior.
type reviewInventoryFraming struct {
	sse    bool
	status int
}

func rawReviewGateway(t *testing.T, schema json.RawMessage, token string, call func(http.ResponseWriter, *http.Request, json.RawMessage), remove func(http.ResponseWriter, *http.Request), inventoryFraming ...reviewInventoryFraming) Gateway {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			if remove != nil {
				remove(w, r)
			} else {
				w.WriteHeader(http.StatusNoContent)
			}
			return
		}
		var msg struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params struct {
				Arguments json.RawMessage `json:"arguments"`
			} `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
			http.Error(w, "invalid JSON", 400)
			return
		}
		if len(msg.ID) == 0 {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		if msg.Method == "tools/call" {
			call(w, r, msg.ID)
			return
		}
		var result any
		switch msg.Method {
		case "initialize":
			if remove != nil {
				w.Header().Set("Mcp-Session-Id", "review-session")
			}
			result = map[string]any{"protocolVersion": ProtocolVersion, "capabilities": map[string]any{"tools": map[string]any{}}, "serverInfo": map[string]any{"name": "review-gateway", "version": "1"}}
		case "tools/list":
			result = map[string]any{"tools": []any{map[string]any{"name": "read", "inputSchema": schema}}}
		default:
			http.Error(w, "unexpected method", 400)
			return
		}
		framing := reviewInventoryFraming{}
		if msg.Method == "tools/list" && len(inventoryFraming) > 0 {
			framing = inventoryFraming[0]
		}
		if framing.status != 0 {
			w.Header().Set("Content-Type", "application/json")
			if framing.sse {
				w.Header().Set("Content-Type", "text/event-stream")
			}
			w.WriteHeader(framing.status)
		}
		if msg.Method == "tools/list" && framing.sse {
			w.Header().Set("Content-Type", "text/event-stream")
			payload, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": msg.ID, "result": result})
			if err != nil {
				t.Error(err)
				return
			}
			_, _ = fmt.Fprintf(w, "event: message\ndata: %s\n\n", payload)
			return
		}
		writeReviewResult(w, msg.ID, result)
	}))
	t.Cleanup(s.Close)
	return Gateway{Binding: Binding{ID: "review", OwnerID: "owner", ConnectionID: "connection", Epoch: 1}, Endpoint: s.URL + "/mcp", BearerToken: token, ServerName: "review-gateway", ServerVersion: "1", Tools: []Tool{{Name: "read", InputSchema: schema}}}
}

func writeReviewResult(w http.ResponseWriter, id json.RawMessage, result any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
}

func reviewTextResult(text string) map[string]any {
	return map[string]any{"content": []any{map[string]any{"type": "text", "text": text}}}
}

func TestReviewStatefulCancellation(t *testing.T) {
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	g := rawReviewGateway(t, testSchema, "gateway-review-private-token", func(w http.ResponseWriter, r *http.Request, id json.RawMessage) {
		started <- struct{}{}
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
		w.WriteHeader(http.StatusNoContent)
	})
	c := newTestClient(t, g)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := c.CallTool(ctx, g.Binding, "read", json.RawMessage(`{"value":"ok"}`)); done <- err }()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("call never started")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation error: %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		unblock()
		<-done
		t.Fatal("stateful session DELETE exceeded caller cancellation budget")
	}
}

func TestReviewArgumentPrecision(t *testing.T) {
	schema := json.RawMessage(`{"type":"object","properties":{"id":{"type":"integer"}},"required":["id"],"additionalProperties":false}`)
	var wireArguments string
	g := rawReviewGateway(t, schema, "gateway-review-private-token", func(w http.ResponseWriter, r *http.Request, id json.RawMessage) {
		// The raw request body was consumed by the dispatch helper; the client
		// result contains no numbers, so inspect the outbound request below.
		writeReviewResult(w, id, reviewTextResult("ok"))
	}, nil)
	c := newTestClient(t, g)
	base := c.http.Transport
	c.http.Transport = reviewCaptureTransport{base: base, captured: &wireArguments}
	_, err := c.CallTool(context.Background(), g.Binding, "read", json.RawMessage(`{"id":9007199254740993}`))
	if errors.Is(err, ErrArguments) {
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(wireArguments, "9007199254740993") {
		t.Fatalf("integer argument silently changed: %s", wireArguments)
	}
}

type reviewCaptureTransport struct {
	base     http.RoundTripper
	captured *string
}

func (rt reviewCaptureTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.GetBody != nil {
		b, err := r.GetBody()
		if err == nil {
			var msg struct {
				Method string `json:"method"`
				Params struct {
					Arguments json.RawMessage `json:"arguments"`
				} `json:"params"`
			}
			_ = json.NewDecoder(b).Decode(&msg)
			_ = b.Close()
			if msg.Method == "tools/call" {
				*rt.captured = string(msg.Params.Arguments)
			}
		}
	}
	return rt.base.RoundTrip(r)
}

func TestReviewSchemaDigestPrecision(t *testing.T) {
	a, err := SchemaDigest(json.RawMessage(`{"type":"object","properties":{"id":{"const":9007199254740992}}}`))
	if err != nil {
		t.Fatal(err)
	}
	b, err := SchemaDigest(json.RawMessage(`{"type":"object","properties":{"id":{"const":9007199254740993}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("different exact integer constraints have identical schema fingerprints")
	}
}

func TestReviewEscapedBearer(t *testing.T) {
	for _, token := range []string{`gateway-<private-token`, `gateway-"private-token`} {
		t.Run(token, func(t *testing.T) {
			g := rawReviewGateway(t, testSchema, token, func(w http.ResponseWriter, r *http.Request, id json.RawMessage) {
				writeReviewResult(w, id, reviewTextResult(token))
			}, nil)
			c, err := New(Config{Gateways: []Gateway{g}})
			if errors.Is(err, ErrConfiguration) {
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			out, err := c.CallTool(context.Background(), g.Binding, "read", json.RawMessage(`{"value":"ok"}`))
			if err == nil || strings.Contains(out.Text, token) {
				t.Fatalf("gateway credential released: error=%v", err)
			}
		})
	}
}

func TestReviewRejectsNeedsInput(t *testing.T) {
	g := rawReviewGateway(t, testSchema, "gateway-review-private-token", func(w http.ResponseWriter, r *http.Request, id json.RawMessage) {
		result := reviewTextResult("partial operation, awaiting external approval")
		result["resultType"] = "input_required"
		result["requestState"] = "opaque-state"
		writeReviewResult(w, id, result)
	}, nil)
	c := newTestClient(t, g)
	out, err := c.CallTool(context.Background(), g.Binding, "read", json.RawMessage(`{"value":"ok"}`))
	if !errors.Is(err, ErrUnsupportedContent) || out.Text != "" {
		t.Fatalf("unsupported input-required result accepted: %#v, %v", out, err)
	}
}

func TestReviewInventoryPreservesSchemaFidelity(t *testing.T) {
	pinned := json.RawMessage(`{"type":"object","properties":{"value":{"const":1}},"required":["value"],"additionalProperties":false}`)
	for _, tc := range []struct {
		name       string
		wireSchema json.RawMessage
	}{
		{"fractional-constraint-drift", json.RawMessage(`{"type":"object","properties":{"value":{"const":1.0000000000000001}},"required":["value"],"additionalProperties":false}`)},
		{"duplicate-schema-constraint", json.RawMessage(`{"type":"object","properties":{"value":{"const":0,"const":1}},"required":["value"],"additionalProperties":false}`)},
	} {
		for _, framing := range []struct {
			name   string
			sse    bool
			status int
		}{{"json", false, 0}, {"sse", true, 0}, {"json-201", false, http.StatusCreated}, {"sse-201", true, http.StatusCreated}} {
			t.Run(tc.name+"/"+framing.name, func(t *testing.T) {
				var calls atomic.Int64
				g := rawReviewGateway(t, tc.wireSchema, "gateway-review-private-token", func(w http.ResponseWriter, r *http.Request, id json.RawMessage) {
					calls.Add(1)
					writeReviewResult(w, id, reviewTextResult("ok"))
				}, nil, reviewInventoryFraming{sse: framing.sse, status: framing.status})
				g.Tools[0].InputSchema = pinned
				c := newTestClient(t, g)
				out, err := c.CallTool(context.Background(), g.Binding, "read", json.RawMessage(`{"value":1}`))
				if err == nil || out.Text != "" || calls.Load() != 0 {
					t.Fatalf("invalid raw inventory lost its meaning before schema pin check: output=%q error=%v dispatched=%d", out.Text, err, calls.Load())
				}
			})
		}
	}
}

func TestReviewMissingSessionDoesNotRetry(t *testing.T) {
	for _, protocolError := range []bool{false, true} {
		t.Run(fmt.Sprint("protocol-error-", protocolError), func(t *testing.T) {
			var calls atomic.Int64
			g := rawReviewGateway(t, testSchema, "gateway-review-private-token", func(w http.ResponseWriter, r *http.Request, id json.RawMessage) {
				calls.Add(1)
				if protocolError {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusNotFound)
					_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": -32000, "message": "session gone"}})
				} else {
					http.Error(w, "session gone", http.StatusNotFound)
				}
			}, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
			c := newTestClient(t, g)
			out, err := c.CallTool(context.Background(), g.Binding, "read", json.RawMessage(`{"value":"ok"}`))
			if !errors.Is(err, ErrUnavailable) || out.Text != "" || calls.Load() != 1 {
				t.Fatalf("missing session after dispatch: output=%q error=%v calls=%d", out.Text, err, calls.Load())
			}
		})
	}
}
