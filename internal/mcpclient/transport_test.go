package mcpclient

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestTransportFramingBounds(t *testing.T) {
	for _, tc := range []struct {
		name   string
		length int64
		data   string
	}{
		{"content-length", MaxBytes + 1, strings.Repeat("a", MaxBytes+1)},
		{"chunked", -1, strings.Repeat("a", MaxBytes+1)},
		{"small-sse-events", -1, strings.Repeat("event: message\ndata: {}\n\n", MaxBytes/20)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			transport := boundedTransport{base: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{ContentLength: tc.length, Body: io.NopCloser(strings.NewReader(tc.data))}, nil
			})}
			r, _ := http.NewRequest(http.MethodPost, "http://127.0.0.1/mcp", nil)
			res, err := transport.RoundTrip(r)
			var body []byte
			if err == nil {
				defer res.Body.Close()
				body, err = io.ReadAll(res.Body)
			}
			if !errors.Is(err, ErrResultTooLarge) || len(body) > MaxBytes {
				t.Fatalf("bound failed: bytes=%d error=%v", len(body), err)
			}
		})
	}
}

func TestClientRejectsRedirect(t *testing.T) {
	var followed atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { followed.Add(1); t.Error("redirect target reached") }))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/mcp", http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	g := Gateway{Binding: Binding{ID: "a", OwnerID: "a", ConnectionID: "a", Epoch: 1}, Endpoint: source.URL + "/mcp", BearerToken: "gateway-a-private-token", ServerName: "fixture-gateway", ServerVersion: "1", Tools: []Tool{{Name: "read", InputSchema: testSchema}}}
	c := newTestClient(t, g)
	if _, err := c.ListTools(context.Background(), g.Binding); err == nil {
		t.Fatal("redirect accepted")
	}
	if followed.Load() != 0 {
		t.Fatal("gateway credential redirected")
	}
}

func TestClientTLS(t *testing.T) {
	f := newFixture(t, "gateway-a-private-token", "owner-a", testSchema, nil)
	tlsServer := httptest.NewTLSServer(f.server.Config.Handler)
	defer tlsServer.Close()
	g := gateway(f, "a")
	g.Endpoint = tlsServer.URL + "/mcp"
	roots := x509.NewCertPool()
	roots.AddCert(tlsServer.Certificate())
	c, err := New(Config{Gateways: []Gateway{g}, RootCAs: roots})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err = c.ListTools(context.Background(), g.Binding); err != nil {
		t.Fatal(err)
	}
}

func TestClientDifferentServiceSchemas(t *testing.T) {
	numeric := json.RawMessage(`{"type":"object","properties":{"value":{"type":"integer"}},"required":["value"],"additionalProperties":false}`)
	a := newFixture(t, "gateway-a-private-token", "service-a", testSchema, nil)
	b := newFixture(t, "gateway-b-private-token", "service-b", numeric, nil)
	ga, gb := gateway(a, "a"), gateway(b, "b")
	gb.Tools[0].InputSchema = numeric
	c := newTestClient(t, ga, gb)
	for _, tc := range []struct {
		binding    Binding
		args, text string
	}{{ga.Binding, `{"value":"ok"}`, "service-a:ok"}, {gb.Binding, `{"value":7}`, "service-b:7"}} {
		out, err := c.CallTool(context.Background(), tc.binding, "read", json.RawMessage(tc.args))
		if err != nil || out.Text != tc.text {
			t.Fatalf("independent schema: output=%q error=%v", out.Text, err)
		}
	}
	if _, err := c.CallTool(context.Background(), gb.Binding, "read", json.RawMessage(`{"value":"ok"}`)); !errors.Is(err, ErrArguments) {
		t.Fatal("wrong service schema accepted")
	}
	if a.calls.Load() != 1 || b.calls.Load() != 1 {
		t.Fatal("schema-invalid request dispatched")
	}
}
