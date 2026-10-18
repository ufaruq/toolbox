package tokens

import (
	"context"
	"testing"
	"time"

	"github.com/ufaruq/toolbox/internal/domain"
)

func TestRefreshRejectsBroaderScopesWithoutLosingRotation(t *testing.T) {
	m, r, s, p := fixture(t)
	p.refresh = func(context.Context, string) (RefreshResult, error) {
		return RefreshResult{AccessToken: "new-access", RefreshToken: "rotated", Expiry: m.now().Add(time.Hour), Scopes: []string{domain.DriveScope, "https://www.googleapis.com/auth/drive"}}, nil
	}
	if token, err := m.Access(context.Background(), "c", allow); token != "" || err != ErrReauth {
		t.Fatal("broader response released an access lease", err)
	}
	b, _, err := s.Get(context.Background(), Path("c"))
	if err != nil || b.State != StateCleanup || b.RefreshToken != "rotated" || b.AccessToken != "" || r.connection().Status != "needs_reauth" {
		t.Fatal("broader rotation was not preserved in cleanup-only state", err)
	}
}
