package tokens

import (
	"context"
	"testing"
	"time"

	"github.com/ufaruq/toolbox/internal/domain"
)

// A refresh response received after disconnect still contains credential material
// that must be retired. It must not become an active connection or be forgotten.
func TestReviewDisconnectDuringRotationRevokesNewCredential(t *testing.T) {
	m, repo, secrets, provider := fixture(t)
	provider.refresh = func(context.Context, string) (RefreshResult, error) {
		if err := repo.Transact(context.Background(), func(st *domain.State) error {
			c := st.Connections["c"]
			c.Status = "disconnecting"
			c.Epoch++
			st.Connections[c.ID] = c
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return RefreshResult{AccessToken: "NEW-ACCESS-AFTER-DISCONNECT", RefreshToken: "NEW-REFRESH-AFTER-DISCONNECT", Expiry: m.now().Add(time.Hour)}, nil
	}
	var revoked []string
	provider.revoke = func(_ context.Context, token string) error {
		revoked = append(revoked, token)
		return nil // Includes already-invalid old tokens, as the Google adapter does.
	}
	if token, err := m.Access(context.Background(), "c", allow); err == nil || token != "" {
		t.Fatal("disconnect must block credential use")
	}
	if err := m.Tombstone(context.Background(), "c", 2); err != nil {
		t.Fatal(err)
	}
	for _, token := range revoked {
		if token == "NEW-REFRESH-AFTER-DISCONNECT" {
			bundle, _, err := secrets.Get(context.Background(), Path("c"))
			if err != nil || bundle.State != StateTombstoned || bundle.AccessToken != "" || bundle.RefreshToken != "" {
				t.Fatal("cleanup did not leave an empty tombstone", err)
			}
			return
		}
	}
	t.Fatalf("cleanup never revoked the known rotated credential; revoked only %q", revoked)
}
