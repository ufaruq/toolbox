package app

import (
	"context"
	"testing"
)

func TestUnavailableIntegrationFailsClosed(t *testing.T) {
	i := UnavailableIntegration{}
	if i.Available() {
		t.Fatal("missing provider advertised as available")
	}
	ctx := context.Background()
	if url, err := i.Start(ctx, "owner", "session"); err == nil || url != "" {
		t.Fatal("missing provider started authorization")
	}
	if c, err := i.Complete(ctx, "owner", "session", "state", "code"); err == nil || c.ID != "" {
		t.Fatal("missing provider returned connection")
	}
	for _, read := range []bool{false, true} {
		auth := func(context.Context) error { return nil }
		if read {
			if d, err := i.Read(ctx, "connection", "file", auth); err == nil || d.Content != "" || d.Bytes != 0 {
				t.Fatal("missing provider returned content")
			}
		} else {
			if d, err := i.Inspect(ctx, "connection", "file", auth); err == nil || d.FileID != "" {
				t.Fatal("missing provider returned metadata")
			}
		}
	}
	if err := i.Cleanup(ctx, "connection", 1); err == nil {
		t.Fatal("missing provider pretended cleanup succeeded")
	}
	if url, err := i.FixtureAuthorize(ctx, "https://example.test"); err == nil || url != "" {
		t.Fatal("hosted provider substituted fixture")
	}
}
