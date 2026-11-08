package app_test

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/ufaruq/toolbox/internal/domain"
	"github.com/ufaruq/toolbox/internal/security"
)

func rotatedPeppers(t *testing.T) *security.PepperRing {
	t.Helper()
	r, err := security.NewPepperRing(security.PepperConfig{Active: "new", Keys: map[string]string{"legacy": base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", 32))), "new": base64.StdEncoding.EncodeToString([]byte(strings.Repeat("y", 32)))}})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestCredentialPepperRotation(t *testing.T) {
	h := newHarness(t, nil)
	h.api.PepperKeys = rotatedPeppers(t)
	h.call("POST", "/v1/delegation-requests", map[string]any{"tool": domain.Tool, "file_id": "doc-A", "duration_seconds": 60}, h.credential, "", 201)
	if err := h.repo.Transact(context.Background(), func(st *domain.State) error {
		for _, c := range st.Credentials {
			if c.AgentID == h.agentID && c.PepperID != "new" {
				t.Fatal("successful authentication did not upgrade pepper version")
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestSessionCSRFUsesOriginalPepper(t *testing.T) {
	h := newHarness(t, nil)
	h.api.PepperKeys = rotatedPeppers(t)
	v := h.call("GET", "/v1/session", nil, "", "", 200)
	if v["csrf_token"] != h.csrf {
		t.Fatal("pepper rotation changed the existing session CSRF token")
	}
	h.call("POST", "/v1/agents", map[string]any{"name": "after rotation"}, "", "", 201)
}

func TestRemovedSessionPepperDeniesMutation(t *testing.T) {
	h := newHarness(t, nil)
	ring, err := security.NewPepperRing(security.PepperConfig{Active: "new", Keys: map[string]string{"new": base64.StdEncoding.EncodeToString([]byte(strings.Repeat("y", 32)))}})
	if err != nil {
		t.Fatal(err)
	}
	h.api.PepperKeys = ring
	h.call("POST", "/v1/agents", map[string]any{"name": "must not be created"}, "", "", 403)
}
