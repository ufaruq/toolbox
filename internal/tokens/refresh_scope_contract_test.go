package tokens

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/ufaruq/toolbox/internal/domain"
)

func setRefreshScopeContract(t *testing.T, m *Manager, r *testRepo, s *spyStore, connectionScopes, storedScopes []string, cached bool) {
	t.Helper()
	b, version, err := s.Get(context.Background(), Path("c"))
	if err != nil {
		t.Fatal(err)
	}
	b.Scopes = slices.Clone(storedScopes)
	if cached {
		b.Expiry = m.now().Add(time.Hour)
	}
	version, err = s.Put(context.Background(), Path("c"), b, version)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Transact(context.Background(), func(st *domain.State) error {
		c := st.Connections["c"]
		c.Scopes = slices.Clone(connectionScopes)
		c.SecretVersion = version
		st.Connections["c"] = c
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestRefreshPreservesScopeContracts(t *testing.T) {
	legacy := []string{domain.DriveScope}
	standard := []string{"openid", domain.DriveScope}
	corporate := []string{"openid", "email", domain.DriveScope}
	for _, tc := range []struct {
		name                         string
		connection, stored, response []string
	}{
		{"legacy omitted scopes", legacy, legacy, nil},
		{"legacy optional openid", legacy, legacy, standard},
		{"standard omitted scopes", standard, standard, nil},
		{"standard without openid", standard, standard, legacy},
		{"standard with legacy bundle", standard, legacy, standard},
		{"corporate omitted scopes", corporate, corporate, nil},
		{"corporate explicit scopes", corporate, corporate, corporate},
		{"corporate reordered scopes", corporate, []string{"email", domain.DriveScope, "openid"}, []string{domain.DriveScope, "openid", "email"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, r, s, p := fixture(t)
			setRefreshScopeContract(t, m, r, s, tc.connection, tc.stored, false)
			p.refresh = func(context.Context, string) (RefreshResult, error) {
				return RefreshResult{AccessToken: "new-access", RefreshToken: "rotated", Expiry: m.now().Add(time.Hour), Scopes: tc.response}, nil
			}
			if token, err := m.Access(context.Background(), "c", allow); err != nil || token != "new-access" {
				t.Fatalf("valid contract did not release refreshed access: token=%q err=%v", token, err)
			}
			b, _, err := s.Get(context.Background(), Path("c"))
			want := tc.response
			if len(want) == 0 {
				want = tc.stored
			}
			if err != nil || b.State != StateActive || !slices.Equal(b.Scopes, want) || r.connection().Status != "active" || p.calls.Load() != 1 {
				t.Fatalf("refresh did not preserve accepted scopes: state=%q scopes=%v err=%v", b.State, b.Scopes, err)
			}
		})
	}
}

func TestRefreshRejectsScopeContractChanges(t *testing.T) {
	legacy := []string{domain.DriveScope}
	standard := []string{"openid", domain.DriveScope}
	corporate := []string{"openid", "email", domain.DriveScope}
	for _, tc := range []struct {
		name                         string
		connection, stored, response []string
	}{
		{"legacy gains email", legacy, legacy, corporate},
		{"standard gains email", standard, standard, corporate},
		{"corporate loses email", corporate, corporate, standard},
		{"corporate loses openid", corporate, corporate, []string{"email", domain.DriveScope}},
		{"corporate loses identity", corporate, corporate, legacy},
		{"corporate loses drive", corporate, corporate, []string{"openid", "email"}},
		{"corporate gains scope", corporate, corporate, []string{"openid", "email", domain.DriveScope, "profile"}},
		{"corporate repeats scope", corporate, corporate, []string{"openid", "email", domain.DriveScope, "email"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, r, s, p := fixture(t)
			setRefreshScopeContract(t, m, r, s, tc.connection, tc.stored, false)
			p.refresh = func(context.Context, string) (RefreshResult, error) {
				return RefreshResult{AccessToken: "new-access", RefreshToken: "rotated", Expiry: m.now().Add(time.Hour), Scopes: tc.response}, nil
			}
			if token, err := m.Access(context.Background(), "c", allow); token != "" || err != ErrReauth {
				t.Fatalf("changed contract released refreshed access: token=%q err=%v", token, err)
			}
			b, _, err := s.Get(context.Background(), Path("c"))
			if err != nil || b.State != StateCleanup || b.RefreshToken != "rotated" || b.AccessToken != "" || r.connection().Status != "needs_reauth" || p.calls.Load() != 1 {
				t.Fatalf("rejected rotation lost cleanup credentials: state=%q err=%v", b.State, err)
			}
		})
	}
}

func TestAccessRejectsMismatchedEmailScopeContracts(t *testing.T) {
	standard := []string{"openid", domain.DriveScope}
	corporate := []string{"openid", "email", domain.DriveScope}
	for _, tc := range []struct {
		name               string
		connection, stored []string
	}{
		{"connection did not opt in", standard, corporate},
		{"bundle did not opt in", corporate, standard},
		{"connection has extra scope", append(slices.Clone(corporate), "profile"), corporate},
		{"bundle has extra scope", corporate, append(slices.Clone(corporate), "profile")},
		{"connection lacks openid", []string{"email", domain.DriveScope}, corporate},
		{"bundle lacks openid", corporate, []string{"email", domain.DriveScope}},
	} {
		for _, cached := range []bool{false, true} {
			name := tc.name + "/expired"
			if cached {
				name = tc.name + "/cached"
			}
			t.Run(name, func(t *testing.T) {
				m, r, s, p := fixture(t)
				setRefreshScopeContract(t, m, r, s, tc.connection, tc.stored, cached)
				if token, err := m.Access(context.Background(), "c", allow); token != "" || err != ErrReauth {
					t.Fatalf("mismatched contract released access: token=%q err=%v", token, err)
				}
				if p.calls.Load() != 0 || r.connection().Status != "needs_reauth" {
					t.Fatal("mismatched stored contract reached refresh or remained active")
				}
			})
		}
	}
}
