package server

import (
	"context"
	"errors"
	"fmt"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/ufaruq/toolbox/internal/domain"
	"github.com/ufaruq/toolbox/internal/security"
	"github.com/ufaruq/toolbox/internal/tokens"
)

func TestHostedLoginRequiresConfiguredIdentity(t *testing.T) {
	s, _, _ := invocationFixture(t)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest("GET", "/auth/login", nil))
	if w.Code != 503 {
		t.Fatalf("unconfigured identity login = %d, want 503", w.Code)
	}
}

func TestOwnerLoginBrowserBindingExpiryAndOneUse(t *testing.T) {
	for _, scenario := range []string{"success-replay", "wrong-browser", "expired", "exchange-failure", "extra-param", "duplicate-param", "malformed-param"} {
		t.Run(scenario, func(t *testing.T) {
			s, repo, _, idp := callerFixture(t)
			w := httptest.NewRecorder()
			s.ServeHTTP(w, httptest.NewRequest("GET", "/auth/login", nil))
			if w.Code != 303 {
				t.Fatalf("start: %d %s", w.Code, w.Body)
			}
			cookies := w.Result().Cookies()
			if len(cookies) != 1 {
				t.Fatal("missing browser cookie")
			}
			cookie := cookies[0]
			if !cookie.HttpOnly || !cookie.Secure || cookie.Path != "/auth/okta/callback" || cookie.MaxAge != 600 {
				t.Fatalf("weak cookie: %+v", cookie)
			}
			var tx domain.OwnerLogin
			if e := repo.Transact(context.Background(), func(st *domain.State) error {
				for _, v := range st.OwnerLogins {
					tx = v
				}
				return nil
			}); e != nil {
				t.Fatal(e)
			}
			if tx.StateHash != security.Hash(idp.state) || tx.NonceHash != security.Hash(idp.nonce) || tx.BrowserHash != security.Hash(cookie.Value) {
				t.Fatal("login binding not hashed")
			}
			if scenario == "wrong-browser" {
				cookie.Value = security.Random()
			}
			if scenario == "expired" {
				// Keep persisted immutable expiry and advance the database clock.
				s.Repository = &loginClockRepository{Repository: repo, now: tx.ExpiresAt.Add(time.Second)}
			}
			if scenario == "exchange-failure" {
				idp.reject = true
			}
			path := "/auth/okta/callback?state=" + url.QueryEscape(idp.state) + "&code=code"
			if scenario == "extra-param" {
				path += "&owner_id=other"
			}
			if scenario == "malformed-param" {
				path += "&bad=%"
			}
			if scenario == "duplicate-param" {
				path += "&code=other"
			}
			callback := func() *httptest.ResponseRecorder {
				r := httptest.NewRequest("GET", path, nil)
				r.AddCookie(cookie)
				w := httptest.NewRecorder()
				s.ServeHTTP(w, r)
				return w
			}
			w = callback()
			if scenario == "success-replay" {
				if w.Code != 303 {
					t.Fatalf("valid callback: %d %s", w.Code, w.Body)
				}
				sessions := w.Result().Cookies()
				found := false
				for _, c := range sessions {
					if c.Name == "toolbox_session" {
						found = true
						if !c.Secure || !c.HttpOnly || c.MaxAge != 28800 {
							t.Fatal("weak owner session")
						}
					}
				}
				if !found {
					t.Fatal("no owner session")
				}
				if second := callback(); second.Code != 400 {
					t.Fatalf("replay: %d", second.Code)
				}
				if idp.exchanges != 1 {
					t.Fatalf("replay re-exchanged: %d", idp.exchanges)
				}
			} else {
				if w.Code != 400 {
					t.Fatalf("invalid login %s: %d %s", scenario, w.Code, w.Body)
				}
				if scenario == "exchange-failure" {
					idp.reject = false
					if next := callback(); next.Code != 400 {
						t.Fatalf("failed exchange transaction reused: %d", next.Code)
					}
					if idp.exchanges != 1 {
						t.Fatal("consumed failed transaction re-exchanged")
					}
				} else if idp.exchanges != 0 {
					t.Fatal("invalid binding reached exchange")
				}
			}
			if scenario == "success-replay" || scenario == "exchange-failure" {
				var v loginSecret
				if _, e := s.LoginSecrets.GetJSON(context.Background(), tx.SecretRef, &v); !errors.Is(e, tokens.ErrNotFound) {
					t.Fatalf("verifier retained: %v", e)
				}
			}
		})
	}
}

type loginClockRepository struct {
	domain.Repository
	now time.Time
}

func (r *loginClockRepository) Transact(ctx context.Context, fn func(*domain.State) error) error {
	return r.Repository.Transact(ctx, func(st *domain.State) error { st.Now = r.now; return fn(st) })
}
func TestOwnerLogoutRequiresCSRFAndDeletesSession(t *testing.T) {
	s, _, _, _ := callerFixture(t)
	cookie, csrf := ownerCookie(t, s, "owner")
	if w := ownerPost(s, "/auth/logout", "{}", cookie, ""); w.Code != 403 {
		t.Fatalf("logout without CSRF: %d", w.Code)
	}
	if w := ownerPost(s, "/auth/logout", "{}", cookie, csrf); w.Code != 200 {
		t.Fatalf("logout: %d", w.Code)
	}
	r := httptest.NewRequest("GET", "/v1/session", nil)
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("logged-out session reused: %d", w.Code)
	}
}

type loginSecretRecorder struct {
	tokens.JSONStore
	puts                int
	failPut, failDelete bool
	beforePut           func()
}

func (s *loginSecretRecorder) PutJSON(ctx context.Context, p string, v any, cas int64) (int64, error) {
	s.puts++
	if s.beforePut != nil {
		s.beforePut()
	}
	version, e := s.JSONStore.PutJSON(ctx, p, v, cas)
	if s.failPut {
		return version, tokens.ErrUnavailable
	}
	return version, e
}
func (s *loginSecretRecorder) DeleteJSON(ctx context.Context, p string) error {
	if s.failDelete {
		return tokens.ErrUnavailable
	}
	return s.JSONStore.DeleteJSON(ctx, p)
}
func TestOwnerLoginCapacityPrecedesSecretWrite(t *testing.T) {
	s, repo, _, _ := callerFixture(t)
	secrets := &loginSecretRecorder{JSONStore: s.LoginSecrets}
	s.LoginSecrets = secrets
	if e := repo.Transact(context.Background(), func(st *domain.State) error {
		for n := 0; n < 1000; n++ {
			id := fmt.Sprintf("login-%d", n)
			st.OwnerLogins[id] = domain.OwnerLogin{ID: id, StateHash: id, NonceHash: id, BrowserHash: id, SecretRef: "owner-logins/" + id, ExpiresAt: st.Now.Add(time.Minute)}
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest("GET", "/auth/login", nil))
	if w.Code != 503 || secrets.puts != 0 {
		t.Fatalf("capacity not enforced before secret write: %d, writes=%d", w.Code, secrets.puts)
	}
}
func TestOwnerLoginGlobalRateLimit(t *testing.T) {
	s, _, _, _ := callerFixture(t)
	secrets := &loginSecretRecorder{JSONStore: s.LoginSecrets}
	s.LoginSecrets = secrets
	for n := 0; n < 61; n++ {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/auth/login", nil)
		r.RemoteAddr = fmt.Sprintf("192.0.2.%d:1234", n)
		s.ServeHTTP(w, r)
		if n < 60 && w.Code != 303 {
			t.Fatalf("login %d: %d", n, w.Code)
		}
		if n == 60 && w.Code != 429 {
			t.Fatalf("global login limit: %d", w.Code)
		}
	}
	if secrets.puts != 60 {
		t.Fatalf("rate-limited login wrote secret: %d", secrets.puts)
	}
}
func TestOwnerLoginReservationAndPartialSecretFailure(t *testing.T) {
	for _, deleteFails := range []bool{false, true} {
		t.Run(fmt.Sprintf("delete-fails-%t", deleteFails), func(t *testing.T) {
			s, repo, _, _ := callerFixture(t)
			secrets := &loginSecretRecorder{JSONStore: s.LoginSecrets, failPut: true, failDelete: deleteFails}
			secrets.beforePut = func() {
				if e := repo.Transact(context.Background(), func(st *domain.State) error {
					if len(st.OwnerLogins) != 1 {
						t.Error("secret written without durable reservation")
					}
					return nil
				}); e != nil {
					t.Fatal(e)
				}
			}
			s.LoginSecrets = secrets
			w := httptest.NewRecorder()
			s.ServeHTTP(w, httptest.NewRequest("GET", "/auth/login", nil))
			if w.Code != 503 {
				t.Fatalf("partial secret failure: %d", w.Code)
			}
			if e := repo.Transact(context.Background(), func(st *domain.State) error {
				want := 0
				if deleteFails {
					want = 1
				}
				if len(st.OwnerLogins) != want {
					t.Fatalf("reservation cleanup=%d, want%d", len(st.OwnerLogins), want)
				}
				return nil
			}); e != nil {
				t.Fatal(e)
			}
		})
	}
}
func TestOwnerLoginCleanupRetriesExpiredVerifiers(t *testing.T) {
	s, repo, _, _ := callerFixture(t)
	secrets := &loginSecretRecorder{JSONStore: s.LoginSecrets, failDelete: true}
	s.LoginSecrets = secrets
	if e := repo.Transact(context.Background(), func(st *domain.State) error {
		for _, id := range []string{"expired", "active", "consumed"} {
			expiry := st.Now.Add(time.Minute)
			if id == "expired" {
				expiry = st.Now.Add(-time.Minute)
			}
			st.OwnerLogins[id] = domain.OwnerLogin{ID: id, StateHash: id, NonceHash: id, BrowserHash: id, SecretRef: "owner-logins/" + id, ExpiresAt: expiry, Consumed: id == "consumed"}
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	if _, e := secrets.JSONStore.PutJSON(context.Background(), "owner-logins/expired", loginSecret{Verifier: "private-verifier"}, 0); e != nil {
		t.Fatal(e)
	}
	if e := s.CleanupOnce(context.Background()); e != nil {
		t.Fatal(e)
	}
	if e := repo.Transact(context.Background(), func(st *domain.State) error {
		if len(st.OwnerLogins) != 3 {
			t.Fatal("failed verifier deletion dropped retry record")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	secrets.failDelete = false
	if e := s.CleanupOnce(context.Background()); e != nil {
		t.Fatal(e)
	}
	if e := repo.Transact(context.Background(), func(st *domain.State) error {
		if _, ok := st.OwnerLogins["expired"]; ok {
			t.Fatal("expired login not cleaned")
		}
		if len(st.OwnerLogins) != 2 {
			t.Fatal("unexpired login cleaned during callback window")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	var out loginSecret
	if _, e := secrets.GetJSON(context.Background(), "owner-logins/expired", &out); !errors.Is(e, tokens.ErrNotFound) {
		t.Fatalf("expired verifier retained: %v", e)
	}
}

type blockingLoginDeletion struct{ tokens.JSONStore }

func (blockingLoginDeletion) DeleteJSON(ctx context.Context, _ string) error {
	<-ctx.Done()
	return ctx.Err()
}
func TestOwnerLoginCleanupHonorsJobDeadline(t *testing.T) {
	s, repo, _, _ := callerFixture(t)
	s.LoginSecrets = blockingLoginDeletion{JSONStore: s.LoginSecrets}
	if e := repo.Transact(context.Background(), func(st *domain.State) error {
		st.OwnerLogins["expired"] = domain.OwnerLogin{ID: "expired", StateHash: "state", NonceHash: "nonce", BrowserHash: "browser", SecretRef: "owner-logins/expired", ExpiresAt: st.Now.Add(-time.Minute)}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	e := s.CleanupOnce(ctx)
	if !errors.Is(e, context.DeadlineExceeded) || time.Since(start) > 500*time.Millisecond {
		t.Fatalf("cleanup escaped job deadline: %v after %v", e, time.Since(start))
	}
}

func TestPrunedOwnerLoginRejectsReplay(t *testing.T) {
	s, repo, _, idp := callerFixture(t)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest("GET", "/auth/login", nil))
	if w.Code != 303 {
		t.Fatal(w.Code)
	}
	cookie := w.Result().Cookies()[0]
	path := "/auth/okta/callback?state=" + url.QueryEscape(idp.state) + "&code=code"
	callback := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", path, nil)
		r.AddCookie(cookie)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w
	}
	if w := callback(); w.Code != 303 {
		t.Fatal(w.Code)
	}
	var expiry time.Time
	if e := repo.Transact(context.Background(), func(st *domain.State) error {
		for _, v := range st.OwnerLogins {
			expiry = v.ExpiresAt
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	s.Repository = &loginClockRepository{Repository: repo, now: expiry.Add(time.Second)}
	if e := s.CleanupOnce(context.Background()); e != nil {
		t.Fatal(e)
	}
	if w := callback(); w.Code != 400 {
		t.Fatalf("pruned replay accepted: %d", w.Code)
	}
	if idp.exchanges != 1 {
		t.Fatal("pruned replay reached exchange")
	}
}
