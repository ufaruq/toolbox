package tokens

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOpenBaoKVv2ProtocolAndCAS(t *testing.T) {
	version := int64(0)
	var stored map[string]any
	deleted := false
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/toolbox/data/oauth/transaction" || r.Header.Get("X-Vault-Token") != "fixture-workload-token" || r.Header.Get("X-Vault-Namespace") != "fixture" {
			t.Error("bad KV request envelope")
			w.WriteHeader(400)
			return
		}
		switch r.Method {
		case "POST":
			var request struct {
				Data    map[string]any `json:"data"`
				Options struct {
					CAS int64 `json:"cas"`
				} `json:"options"`
			}
			if json.NewDecoder(r.Body).Decode(&request) != nil {
				w.WriteHeader(400)
				return
			}
			if request.Options.CAS != version {
				w.WriteHeader(400)
				io.WriteString(w, `{"errors":["check-and-set parameter did not match the current version"]}`)
				return
			}
			version++
			stored = request.Data
			deleted = false
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"version": version}})
		case "GET":
			if version == 0 || deleted {
				w.WriteHeader(404)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"data": stored, "metadata": map[string]any{"version": version, "deletion_time": "", "destroyed": false}}})
		case "DELETE":
			deleted = true
			w.WriteHeader(204)
		default:
			w.WriteHeader(405)
		}
	}))
	defer server.Close()
	store, e := NewOpenBao(OpenBaoConfig{Address: server.URL, Mount: "toolbox", Token: "fixture-workload-token", Namespace: "fixture"})
	if e != nil {
		t.Fatal(e)
	}
	fixtureClient := server.Client()
	fixtureClient.CheckRedirect = store.client.CheckRedirect
	store.client = fixtureClient
	ctx := context.Background()
	var out map[string]string
	if _, e = store.GetJSON(ctx, "oauth/transaction", &out); e != ErrNotFound {
		t.Fatal("missing KV not reported")
	}
	v, e := store.PutJSON(ctx, "oauth/transaction", map[string]string{"verifier": "fixture-pkce-verifier"}, 0)
	if e != nil || v != 1 {
		t.Fatal("KV create failed", e)
	}
	if _, e = store.PutJSON(ctx, "oauth/transaction", map[string]string{"verifier": "different"}, 0); e != ErrCAS {
		t.Fatal("CAS was not enforced")
	}
	v, e = store.GetJSON(ctx, "oauth/transaction", &out)
	if e != nil || v != 1 || out["verifier"] != "fixture-pkce-verifier" {
		t.Fatal("wrong KV typed content")
	}
	if e = store.DeleteJSON(ctx, "oauth/transaction"); e != nil {
		t.Fatal(e)
	}
	if _, e = store.GetJSON(ctx, "oauth/transaction", &out); e != ErrNotFound {
		t.Fatal("deleted KV still readable")
	}
}
func TestOpenBaoRefusesRedirectAndRedactsErrors(t *testing.T) {
	calls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Location", "http://127.0.0.1/steal")
		w.WriteHeader(302)
		io.WriteString(w, "CANARY-CREDENTIAL-IN-PROVIDER-ERROR")
	}))
	defer server.Close()
	store, e := NewOpenBao(OpenBaoConfig{Address: server.URL, Mount: "toolbox", Token: "fixture-token"})
	if e != nil {
		t.Fatal(e)
	}
	client := server.Client()
	client.CheckRedirect = store.client.CheckRedirect
	store.client = client
	_, _, e = store.Get(context.Background(), "connections/c")
	if e != ErrUnavailable || calls != 1 || strings.Contains(e.Error(), "CANARY") {
		t.Fatal("redirect followed or error leaked")
	}
}
func TestOpenBaoRejectsUnsafeConfigurationAndPaths(t *testing.T) {
	for _, address := range []string{"http://bao.local", "https://user:pass@bao.local", "https://bao.local/v1", "https://bao.local?x=1", "https://bao.local#fragment"} {
		if _, e := NewOpenBao(OpenBaoConfig{Address: address, Mount: "toolbox", Token: "fixture"}); e == nil {
			t.Fatal("unsafe address accepted")
		}
	}
	store, e := NewOpenBao(OpenBaoConfig{Address: "https://bao.local", Mount: "toolbox", Token: "fixture"})
	if e != nil {
		t.Fatal(e)
	}
	for _, path := range []string{"../tokens", "connections/c?x=1", "connections//c", "connections/%2e%2e", "/connections/c"} {
		if _, _, e := store.Get(context.Background(), path); e != ErrUnavailable {
			t.Fatal("path escaped secret mount")
		}
	}
	transport := store.client.Transport.(*http.Transport)
	if transport.Proxy != nil {
		t.Fatal("Bao inherited proxy")
	}
}
func TestMemoryStoreCASAndDefensiveCopies(t *testing.T) {
	s := NewMemorySecretStore()
	ctx := context.Background()
	b := Bundle{ConnectionID: "c", Scopes: []string{"scope"}}
	v, e := s.Put(ctx, Path("c"), b, 0)
	if e != nil || v != 1 {
		t.Fatal(e)
	}
	b.Scopes[0] = "mutated"
	read, _, _ := s.Get(ctx, Path("c"))
	if read.Scopes[0] != "scope" {
		t.Fatal("store retained caller slice")
	}
	read.Scopes[0] = "mutated again"
	read, _, _ = s.Get(ctx, Path("c"))
	if read.Scopes[0] != "scope" {
		t.Fatal("store leaked mutable slice")
	}
	if _, e = s.Put(ctx, Path("c"), b, 0); e != ErrCAS {
		t.Fatal("CAS create overwrite accepted")
	}
}

func TestFixtureHTTPRequiresExplicitLocalDestination(t *testing.T) {
	for _, address := range []string{"http://127.0.0.1:8200", "http://[::1]:8200", "http://localhost:8200", "http://openbao:8200"} {
		if _, e := NewOpenBaoFixture(OpenBaoConfig{Address: address, Mount: "toolbox", Token: "fixture"}); e != nil {
			t.Fatal("fixture destination rejected", e)
		}
		if _, e := NewOpenBao(OpenBaoConfig{Address: address, Mount: "toolbox", Token: "fixture"}); e == nil {
			t.Fatal("production accepted fixture HTTP")
		}
	}
	for _, address := range []string{"http://example.com", "http://10.0.0.2", "http://openbao.attacker.example", "http://localhost.attacker.example"} {
		if _, e := NewOpenBaoFixture(OpenBaoConfig{Address: address, Mount: "toolbox", Token: "fixture"}); e == nil {
			t.Fatal("nonlocal HTTP accepted")
		}
	}
}
