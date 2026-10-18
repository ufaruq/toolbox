package gdrive

import (
	"context"
	"net/http"
	"testing"

	"github.com/ufaruq/toolbox/internal/connectors"
	"github.com/ufaruq/toolbox/internal/domain"
)

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestManifestIsStaticAndDefensivelyCopied(t *testing.T) {
	m := Manifest()
	if m.Tool != domain.Tool || m.Action != domain.Action || !m.ReadOnly || m.MaxBytes != domain.MaxBytes || len(m.RequiredScopes) != 1 || m.RequiredScopes[0] != domain.DriveScope {
		t.Fatal("manifest authority mismatch")
	}
	m.RequiredScopes[0] = "widened"
	if Manifest().RequiredScopes[0] != domain.DriveScope {
		t.Fatal("manifest mutated")
	}
}
func TestInvalidArgumentsNeverTouchCredentials(t *testing.T) {
	client := NewFixture(transportFunc(func(*http.Request) (*http.Response, error) { t.Fatal("invalid input dispatched"); return nil, nil }))
	access := func(context.Context) (string, error) { t.Fatal("invalid input accessed credential"); return "", nil }
	auth := func(context.Context) error { t.Fatal("invalid input crossed validation"); return nil }
	if _, e := client.Execute(context.Background(), "a%2Fb", access, auth); e != connectors.ErrInvalidInput {
		t.Fatal(e)
	}
	if _, e := client.Inspect(context.Background(), "../a", access, auth); e != connectors.ErrInvalidInput {
		t.Fatal(e)
	}
}
