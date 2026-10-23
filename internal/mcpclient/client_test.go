package mcpclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

var testSchema = json.RawMessage(`{"type":"object","properties":{"value":{"type":"string"}},"required":["value"],"additionalProperties":false}`)

type fixture struct {
	server   *httptest.Server
	calls    atomic.Int64
	starts   chan struct{}
	release  chan struct{}
	block    bool
	large    bool
	callback bool
	failHTTP bool
}

func newFixture(t *testing.T, token, identity string, schema json.RawMessage, setup func(*fixture)) *fixture {
	t.Helper()
	f := &fixture{starts: make(chan struct{}, 20), release: make(chan struct{})}
	if setup != nil {
		setup(f)
	}
	s := mcp.NewServer(&mcp.Implementation{Name: "fixture-gateway", Version: "1"}, nil)
	mcp.AddTool[map[string]any, any](s, &mcp.Tool{Name: "read", InputSchema: schema}, func(ctx context.Context, r *mcp.CallToolRequest, a map[string]any) (*mcp.CallToolResult, any, error) {
		f.calls.Add(1)
		f.starts <- struct{}{}
		if f.block {
			select {
			case <-ctx.Done():
			case <-f.release:
			}
			return nil, nil, context.Canceled
		}
		if f.callback {
			caps := r.Session.InitializeParams().Capabilities
			if caps.RootsV2 != nil || caps.Sampling != nil || caps.Elicitation != nil {
				return nil, nil, errors.New("unexpected client capabilities")
			}
			_, err := r.Session.Elicit(ctx, &mcp.ElicitParams{Message: "do not approve"})
			if err == nil {
				return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "callback unexpectedly accepted"}}}, nil, nil
			}
			return nil, nil, err
		}
		value := identity + ":" + fmt.Sprint(a["value"])
		if f.large {
			value = strings.Repeat("X", 2<<20)
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: value}}}, nil, nil
	})
	h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return s }, &mcp.StreamableHTTPOptions{Stateless: !f.callback, JSONResponse: true, PropagateRequestCancellation: true})
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, "wrong secret", http.StatusUnauthorized)
			return
		}
		if f.failHTTP && r.Method == "POST" {
			b, _ := io.ReadAll(r.Body)
			r.Body = io.NopCloser(strings.NewReader(string(b)))
			var msg struct {
				Method string `json:"method"`
			}
			_ = json.Unmarshal(b, &msg)
			if msg.Method == "tools/call" {
				f.calls.Add(1)
				http.Error(w, "provider secret must not escape", 500)
				return
			}
		}
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(f.server.Close)
	t.Cleanup(func() { close(f.release) })
	return f
}

func gateway(f *fixture, id string) Gateway {
	return Gateway{Binding: Binding{ID: id, OwnerID: id, ConnectionID: "connection-" + id, Epoch: 1}, Endpoint: f.server.URL + "/mcp", BearerToken: "gateway-" + id + "-private-token", ServerName: "fixture-gateway", ServerVersion: "1", Tools: []Tool{{Name: "read", InputSchema: testSchema}}}
}

func newTestClient(t *testing.T, gs ...Gateway) *Client {
	t.Helper()
	c, err := New(Config{Gateways: gs})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestClientBindingIsolation(t *testing.T) {
	a := newFixture(t, "gateway-a-private-token", "owner-a", testSchema, nil)
	b := newFixture(t, "gateway-b-private-token", "owner-b", testSchema, nil)
	ga, gb := gateway(a, "a"), gateway(b, "b")
	c := newTestClient(t, ga, gb)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		for _, g := range []Gateway{ga, gb} {
			wg.Add(1)
			go func(g Gateway) {
				defer wg.Done()
				v, err := c.CallTool(context.Background(), g.Binding, "read", json.RawMessage(`{"value":"ok"}`))
				if err != nil || v.Text != "owner-"+g.Binding.ID+":ok" {
					t.Errorf("isolated call %s: %q %v", g.Binding.ID, v.Text, err)
				}
			}(g)
		}
	}
	wg.Wait()
	for _, mutate := range []func(*Binding){func(b *Binding) { b.OwnerID = "other" }, func(b *Binding) { b.ConnectionID = "other" }, func(b *Binding) { b.Epoch++ }} {
		binding := ga.Binding
		mutate(&binding)
		before := a.calls.Load()
		if _, err := c.CallTool(context.Background(), binding, "read", json.RawMessage(`{"value":"ok"}`)); !errors.Is(err, ErrBinding) {
			t.Fatalf("forged binding: %v", err)
		}
		if a.calls.Load() != before {
			t.Fatal("forged binding reached server")
		}
	}
}

func TestClientInventoryPin(t *testing.T) {
	f := newFixture(t, "gateway-a-private-token", "owner-a", json.RawMessage(`{"type":"object","properties":{"value":{"type":"integer"}},"required":["value"],"additionalProperties":false}`), nil)
	g := gateway(f, "a")
	c := newTestClient(t, g)
	if _, err := c.CallTool(context.Background(), g.Binding, "read", json.RawMessage(`{"value":"ok"}`)); !errors.Is(err, ErrSchemaChanged) {
		t.Fatalf("schema drift: %v", err)
	}
	if f.calls.Load() != 0 {
		t.Fatal("changed schema dispatched")
	}
}

func TestClientNegotiation(t *testing.T) {
	f := newFixture(t, "gateway-a-private-token", "owner-a", testSchema, nil)
	g := gateway(f, "a")
	g.ServerVersion = "wrong"
	c := newTestClient(t, g)
	if _, err := c.ListTools(context.Background(), g.Binding); !errors.Is(err, ErrProtocol) {
		t.Fatalf("server identity mismatch: %v", err)
	}
}

func TestClientArgumentsAndToolCeiling(t *testing.T) {
	f := newFixture(t, "gateway-a-private-token", "owner-a", testSchema, nil)
	g := gateway(f, "a")
	c := newTestClient(t, g)
	for _, args := range []string{`{"value":3}`, `{"value":"a","extra":true}`, `{"value":"a","value":"b"}`, `[]`, `null`, `{} trailing`} {
		if _, err := c.CallTool(context.Background(), g.Binding, "read", json.RawMessage(args)); !errors.Is(err, ErrArguments) {
			t.Errorf("invalid arguments %q: %v", args, err)
		}
	}
	if _, err := c.CallTool(context.Background(), g.Binding, "mcp-add", json.RawMessage(`{}`)); !errors.Is(err, ErrToolNotAllowed) {
		t.Fatal(err)
	}
	if f.calls.Load() != 0 {
		t.Fatal("invalid request dispatched")
	}
}

func TestClientResultLimits(t *testing.T) {
	f := newFixture(t, "gateway-a-private-token", "owner-a", testSchema, func(f *fixture) { f.large = true })
	g := gateway(f, "a")
	c := newTestClient(t, g)
	v, err := c.CallTool(context.Background(), g.Binding, "read", json.RawMessage(`{"value":"ok"}`))
	if err == nil || v.Text != "" {
		t.Fatal("oversize result released")
	}
}

func TestClientCancellation(t *testing.T) {
	f := newFixture(t, "gateway-a-private-token", "owner-a", testSchema, func(f *fixture) { f.block = true })
	g := gateway(f, "a")
	c := newTestClient(t, g)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := c.CallTool(ctx, g.Binding, "read", json.RawMessage(`{"value":"ok"}`)); done <- err }()
	select {
	case <-f.starts:
	case <-time.After(3 * time.Second):
		t.Fatal("call not started")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancel: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation ignored")
	}
}

func TestClientNoRetry(t *testing.T) {
	f := newFixture(t, "gateway-a-private-token", "owner-a", testSchema, func(f *fixture) { f.failHTTP = true })
	g := gateway(f, "a")
	c := newTestClient(t, g)
	_, err := c.CallTool(context.Background(), g.Binding, "read", json.RawMessage(`{"value":"ok"}`))
	if err == nil || strings.Contains(err.Error(), "provider secret") {
		t.Fatalf("failure leaked or absent: %v", err)
	}
	if n := f.calls.Load(); n != 1 {
		t.Fatalf("dispatched %d times", n)
	}
}

func TestClientRejectsCallbacks(t *testing.T) {
	f := newFixture(t, "gateway-a-private-token", "owner-a", testSchema, func(f *fixture) { f.callback = true })
	g := gateway(f, "a")
	c := newTestClient(t, g)
	if _, err := c.CallTool(context.Background(), g.Binding, "read", json.RawMessage(`{"value":"ok"}`)); !errors.Is(err, ErrToolFailed) {
		t.Fatalf("callback request succeeded: %v", err)
	}
}

func TestClientClose(t *testing.T) {
	f := newFixture(t, "gateway-a-private-token", "owner-a", testSchema, nil)
	g := gateway(f, "a")
	c := newTestClient(t, g)
	_ = c.Close()
	if _, err := c.ListTools(context.Background(), g.Binding); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
}

func TestClientConfiguration(t *testing.T) {
	f := newFixture(t, "gateway-a-private-token", "owner-a", testSchema, nil)
	base := gateway(f, "a")
	for _, mutate := range []func(*Gateway){func(g *Gateway) { g.Endpoint = "http://example.com/mcp" }, func(g *Gateway) { g.Endpoint = f.server.URL + "/mcp?secret=bad" }, func(g *Gateway) { g.Endpoint = "https://user:secret@example.com/mcp" }, func(g *Gateway) { g.BearerToken = "bad\r\nheader" }, func(g *Gateway) { g.Binding.Epoch = 0 }} {
		g := base
		mutate(&g)
		if c, err := New(Config{Gateways: []Gateway{g}}); err == nil {
			_ = c.Close()
			t.Fatal("unsafe configuration accepted")
		}
	}
}

func TestClientRejectsEquivalentEndpoints(t *testing.T) {
	for _, tc := range []struct{ name, a, b string }{
		{"default-https-port", "https://gateway.example/mcp", "https://gateway.example:443/mcp"},
		{"hostname-case", "https://gateway.example/mcp", "https://GATEWAY.EXAMPLE/mcp"},
		{"scheme-case", "https://gateway.example/mcp", "HTTPS://gateway.example/mcp"},
		{"trailing-dns-dot", "https://gateway.example/mcp", "https://gateway.example./mcp"},
		{"port-leading-zero", "https://gateway.example:8443/mcp", "https://gateway.example:08443/mcp"},
		{"default-http-port", "http://127.0.0.1/mcp", "http://127.0.0.1:80/mcp"},
		{"ipv6-spelling", "https://[::1]/mcp", "https://[0:0:0:0:0:0:0:1]:443/mcp"},
		{"ipv4-mapped-ipv6", "http://127.0.0.1:8811/mcp", "http://[::ffff:127.0.0.1]:8811/mcp"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := Gateway{Binding: Binding{ID: "a", OwnerID: "a", ConnectionID: "a", Epoch: 1}, Endpoint: tc.a, BearerToken: "gateway-a-private-token", ServerName: "fixture-gateway", ServerVersion: "1", Tools: []Tool{{Name: "read", InputSchema: testSchema}}}
			b := a
			b.Binding = Binding{ID: "b", OwnerID: "b", ConnectionID: "b", Epoch: 1}
			b.Endpoint, b.BearerToken = tc.b, "gateway-b-private-token"
			c, err := New(Config{Gateways: []Gateway{a, b}})
			if c != nil {
				_ = c.Close()
			}
			if !errors.Is(err, ErrConfiguration) {
				t.Fatalf("equivalent endpoints accepted: %v", err)
			}
		})
	}
}

func TestClientCanonicalEndpointDispatch(t *testing.T) {
	f := newFixture(t, "gateway-a-private-token", "owner-a", testSchema, nil)
	g := gateway(f, "a")
	u, err := url.Parse(g.Endpoint)
	if err != nil {
		t.Fatal(err)
	}
	// A noncanonical spelling must still attach its bearer only to the
	// configured destination after normalization.
	g.Endpoint = "http://127.0.0.1:0" + u.Port() + "/mcp"
	c := newTestClient(t, g)
	result, err := c.CallTool(context.Background(), g.Binding, "read", json.RawMessage(`{"value":"ok"}`))
	if err != nil || result.Text != "owner-a:ok" || f.calls.Load() != 1 {
		t.Fatalf("canonical endpoint dispatch: output=%q error=%v calls=%d", result.Text, err, f.calls.Load())
	}
}
