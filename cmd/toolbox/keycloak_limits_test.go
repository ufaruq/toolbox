package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/ufaruq/toolbox/internal/identity"
	"github.com/ufaruq/toolbox/internal/keycloakrealm"
)

type reviewTransport struct{ calls int }

func (r *reviewTransport) RoundTrip(*http.Request) (*http.Response, error) {
	r.calls++
	return nil, errors.New("review discovery sentinel")
}

func reviewRealm() keycloakrealm.Config {
	return keycloakrealm.Config{Realm: "toolbox", Origin: "http://127.0.0.1:8080", OwnerClientID: "owner", OwnerClientSecret: "synthetic-secret", OktaIssuer: "https://example.okta.com", OktaClientID: "upstream", OktaClientSecret: "synthetic-secret", MCPClients: map[string]string{"agent": "Agent"}, MCPRedirectURIs: map[string][]string{"agent": {"http://127.0.0.1:49152/callback"}}}
}

func TestRealmOwnerClientRuntimeLimit(t *testing.T) {
	for _, size := range []int{256, 257} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			c := reviewRealm()
			c.OwnerClientID = strings.Repeat("o", size)
			_, renderErr := keycloakrealm.Render(c)
			if (renderErr != nil) != (size > 256) {
				t.Fatalf("generator limit mismatch: size=%d error=%v", size, renderErr)
			}
			tr := &reviewTransport{}
			_, err := identity.NewAccess(context.Background(), identity.AccessConfig{Provider: "keycloak", Issuer: "https://login.example/realms/toolbox", OwnerIssuer: "https://login.example/realms/toolbox", Audience: c.Origin + "/mcp", OwnerClientID: c.OwnerClientID, Clients: c.MCPClients, HTTPClient: &http.Client{Transport: tr}})
			if err == nil {
				t.Fatal("expected initialization to stop")
			}
			if size == 256 && tr.calls == 0 {
				t.Fatal("control never reached discovery")
			}
			if size == 257 && tr.calls != 0 {
				t.Fatal("oversized owner unexpectedly reached discovery")
			}
			t.Logf("owner bytes=%d: generator error=%v, runtime discovery requests=%d, runtime error=%v", size, renderErr, tr.calls, err)
		})
	}
}

func TestRealmMCPRegistrationRuntimeLimits(t *testing.T) {
	for _, tc := range []struct {
		name        string
		size, count int
		field       string
		rejected    bool
	}{
		{"id-256", 256, 1, "id", false}, {"id-257", 257, 1, "id", true},
		{"name-256", 256, 1, "name", false}, {"name-257", 257, 1, "name", true},
		{"clients-128", 1, 128, "count", false}, {"clients-129", 1, 129, "count", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := reviewRealm()
			c.MCPClients = map[string]string{}
			c.MCPRedirectURIs = map[string][]string{}
			for i := 0; i < tc.count; i++ {
				id, name := fmt.Sprintf("agent-%d", i), "Agent"
				if tc.field == "id" {
					id = strings.Repeat("a", tc.size)
				}
				if tc.field == "name" {
					name = strings.Repeat("n", tc.size)
				}
				c.MCPClients[id] = name
				c.MCPRedirectURIs[id] = []string{"http://127.0.0.1:49152/callback"}
			}
			if _, err := keycloakrealm.Render(c); (err != nil) != tc.rejected {
				t.Fatalf("generator limit mismatch: %v", err)
			}
			raw, _ := json.Marshal(c.MCPClients)
			env := map[string]string{"TOOLBOX_IDENTITY_PROVIDER": "keycloak", "TOOLBOX_MCP_ISSUER": "https://login.example/realms/toolbox", "TOOLBOX_MCP_CLIENTS": string(raw)}
			_, err := loadMCPConfig(func(k string) string { return env[k] }, env["TOOLBOX_MCP_ISSUER"], c.OwnerClientID, c.Origin)
			if (err != nil) != tc.rejected {
				t.Fatalf("unexpected runtime result: %v", err)
			}
			t.Logf("generator/runtime rejected=%t", err != nil)
		})
	}
}
