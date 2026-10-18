package ownerlogin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/ufaruq/toolbox/internal/domain"
	"github.com/ufaruq/toolbox/internal/security"
	"github.com/ufaruq/toolbox/internal/store"
	"github.com/ufaruq/toolbox/internal/tokens"
)

type loginClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *loginClock) Now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *loginClock) Add(d time.Duration) { c.mu.Lock(); defer c.mu.Unlock(); c.now = c.now.Add(d) }

type loginProvider struct {
	mu       sync.Mutex
	identity Identity
	err      error
	calls    atomic.Int32
	entered  chan struct{}
	release  chan struct{}
}

func (p *loginProvider) AuthorizationURL(state, nonce, challenge string) (string, error) {
	v := url.Values{"state": {state}, "nonce": {nonce}, "code_challenge": {challenge}}
	return "https://idp.example/authorize?" + v.Encode(), nil
}
func (p *loginProvider) Exchange(ctx context.Context, code, verifier, nonceHash string) (Identity, error) {
	p.calls.Add(1)
	if p.entered != nil {
		select {
		case p.entered <- struct{}{}:
		default:
		}
		select {
		case <-p.release:
		case <-ctx.Done():
			return Identity{}, ctx.Err()
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.identity, p.err
}
func (p *loginProvider) setIdentity(identity Identity) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.identity = identity
}

type loginRepo struct {
	domain.Repository
	mu            sync.Mutex
	failNext      bool
	uncertainNext bool
}

func (r *loginRepo) Transact(ctx context.Context, fn func(*domain.State) error) error {
	r.mu.Lock()
	fail, uncertain := r.failNext, r.uncertainNext
	r.failNext, r.uncertainNext = false, false
	r.mu.Unlock()
	if fail {
		return errors.New("database unavailable")
	}
	err := r.Repository.Transact(ctx, fn)
	if err == nil && uncertain {
		return errors.New("commit acknowledgement lost")
	}
	return err
}
func (r *loginRepo) fail(uncertain bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if uncertain {
		r.uncertainNext = true
	} else {
		r.failNext = true
	}
}

type loginSecrets struct {
	tokens.JSONStore
	mu                                      sync.Mutex
	putErr, getErr, deleteErr, uncertainPut bool
	refs                                    []string
	afterPut                                func()
}

func (s *loginSecrets) PutJSON(ctx context.Context, path string, in any, cas int64) (int64, error) {
	s.mu.Lock()
	fail, uncertain, afterPut := s.putErr, s.uncertainPut, s.afterPut
	s.refs = append(s.refs, path)
	s.mu.Unlock()
	if fail {
		return 0, tokens.ErrUnavailable
	}
	v, e := s.JSONStore.PutJSON(ctx, path, in, cas)
	if e == nil && afterPut != nil {
		afterPut()
	}
	if uncertain && e == nil {
		return 0, tokens.ErrUnavailable
	}
	return v, e
}
func (s *loginSecrets) GetJSON(ctx context.Context, path string, out any) (int64, error) {
	s.mu.Lock()
	fail := s.getErr
	s.mu.Unlock()
	if fail {
		return 0, tokens.ErrUnavailable
	}
	return s.JSONStore.GetJSON(ctx, path, out)
}
func (s *loginSecrets) DeleteJSON(ctx context.Context, path string) error {
	s.mu.Lock()
	fail := s.deleteErr
	s.mu.Unlock()
	if fail {
		return tokens.ErrUnavailable
	}
	return s.JSONStore.DeleteJSON(ctx, path)
}
func (s *loginSecrets) setErrors(put, get, del, uncertain bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.putErr, s.getErr, s.deleteErr, s.uncertainPut = put, get, del, uncertain
}

type loginFixture struct {
	service  *Service
	repo     *loginRepo
	secrets  *loginSecrets
	provider *loginProvider
	clock    *loginClock
	cfg      ServiceConfig
}

func newLoginFixture(t *testing.T) *loginFixture {
	t.Helper()
	c := &loginClock{now: time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)}
	r := &loginRepo{Repository: store.NewMemoryWithClock(c.Now)}
	ss := &loginSecrets{JSONStore: tokens.NewMemorySecretStore()}
	p := &loginProvider{identity: Identity{Issuer: "https://idp.example", Subject: "owner-1"}}
	cfg := ServiceConfig{Issuer: "https://idp.example", ClientID: "client", RedirectURI: "http://127.0.0.1:8080/auth/oidc/callback", Pepper: []byte(strings.Repeat("p", 32))}
	svc, e := NewService(r, ss, p, cfg)
	if e != nil {
		t.Fatal(e)
	}
	return &loginFixture{svc, r, ss, p, c, cfg}
}
func (f *loginFixture) start(t *testing.T, previous string) (StartResult, string) {
	t.Helper()
	r, e := f.service.Start(context.Background(), previous)
	if e != nil {
		t.Fatal(e)
	}
	u, e := url.Parse(r.AuthorizationURL)
	if e != nil {
		t.Fatal(e)
	}
	return r, u.Query().Get("state")
}
func (f *loginFixture) snapshot(t *testing.T) *domain.State {
	t.Helper()
	var out domain.State
	e := f.repo.Transact(context.Background(), func(st *domain.State) error {
		b, e := json.Marshal(st)
		if e != nil {
			return e
		}
		return json.Unmarshal(b, &out)
	})
	if e != nil {
		t.Fatal(e)
	}
	return &out
}
func (f *loginFixture) complete(t *testing.T, prior string) LoginResult {
	t.Helper()
	r, state := f.start(t, prior)
	result, e := f.service.Complete(context.Background(), state, "code", r.BrowserToken)
	if e != nil {
		t.Fatal(e)
	}
	return result
}
func (f *loginFixture) prior(t *testing.T) string {
	t.Helper()
	id := security.Hash(security.Random())
	e := f.repo.Transact(context.Background(), func(st *domain.State) error {
		st.Users["prior-owner"] = domain.User{ID: "prior-owner", Issuer: "https://prior.example", Subject: "prior-sub", Status: "active"}
		st.Sessions[id] = domain.Session{ID: id, UserID: "prior-owner", CSRFHash: security.Hash("csrf"), ExpiresAt: st.Now.Add(time.Hour)}
		st.OAuth["google-tx"] = domain.OAuthTransaction{ID: "google-tx", OwnerID: "prior-owner", SessionID: id, StateHash: security.Hash("state"), NonceHash: security.Hash("nonce"), SecretRef: "oauth-transactions/google-tx", ExpiresAt: st.Now.Add(time.Minute)}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	return id
}
func liveLoginSessions(st *domain.State) int {
	n := 0
	for _, s := range st.Sessions {
		if st.Now.Before(s.ExpiresAt) {
			n++
		}
	}
	return n
}

func TestOwnerLoginLifecycle(t *testing.T) {
	f := newLoginFixture(t)
	prior := f.prior(t)
	r, state := f.start(t, prior)
	if r.ExpiresAt.Sub(f.clock.Now()) != 600*time.Second {
		t.Fatal("transaction lifetime")
	}
	if len(r.BrowserToken) != 43 {
		t.Fatal("binding entropy")
	}
	st := f.snapshot(t)
	var tx domain.OwnerLoginTransaction
	for _, v := range st.OwnerLogins {
		tx = v
	}
	var secret struct {
		Verifier string `json:"verifier"`
	}
	if _, e := f.secrets.GetJSON(context.Background(), tx.SecretRef, &secret); e != nil || len(secret.Verifier) != 43 {
		t.Fatal("missing secret verifier", e)
	}
	b, _ := json.Marshal(st)
	for _, raw := range []string{secret.Verifier, state, r.BrowserToken} {
		if strings.Contains(string(b), raw) {
			t.Fatal("raw login material in snapshot")
		}
	}
	result, e := f.service.Complete(context.Background(), state, "code", r.BrowserToken)
	if e != nil {
		t.Fatal(e)
	}
	st = f.snapshot(t)
	session := st.Sessions[security.Hash(result.SessionToken)]
	if len(result.SessionToken) != 43 || session.UserID != result.UserID || session.CSRFHash != security.Hash(result.CSRFToken) || result.CSRFToken != security.KeyedHash(f.cfg.Pepper, result.SessionToken) || session.ExpiresAt.Sub(st.Now) != 8*time.Hour {
		t.Fatal("session contract")
	}
	if _, exists := st.Sessions[prior]; !exists || st.Now.Before(st.Sessions[prior].ExpiresAt) {
		t.Fatal("prior session must expire, not delete")
	}
	if st.OAuth["google-tx"].SessionID != prior {
		t.Fatal("google relationship lost")
	}
	for _, tx := range st.OwnerLogins {
		if tx.Status != "complete" || tx.IssuedSessionID != session.ID {
			t.Fatal("missing durable session relationship")
		}
	}
	if len(st.Audits) != 1 || st.Audits[0].ActorID != result.UserID {
		t.Fatal("missing sanitized audit")
	}
	svc, e := NewService(f.repo, f.secrets, f.provider, f.cfg)
	if e != nil {
		t.Fatal(e)
	}
	f.service = svc
	again := f.complete(t, "")
	if again.UserID != result.UserID {
		t.Fatal("identity changed after restart")
	}
	if security.KeyedHash(f.cfg.Pepper, result.SessionToken) != result.CSRFToken {
		t.Fatal("restart csrf")
	}
	f.provider.setIdentity(Identity{Issuer: f.cfg.Issuer, Subject: "owner-2"})
	other := f.complete(t, "")
	if other.UserID == result.UserID {
		t.Fatal("subjects linked")
	}
	f.cfg.Issuer = "https://other.example"
	f.provider.setIdentity(Identity{Issuer: f.cfg.Issuer, Subject: "owner-1"})
	f.service, e = NewService(f.repo, f.secrets, f.provider, f.cfg)
	if e != nil {
		t.Fatal(e)
	}
	another := f.complete(t, "")
	if another.UserID == result.UserID {
		t.Fatal("issuers linked")
	}
}
func TestOwnerLoginRejectsReplayAndWrongBrowser(t *testing.T) {
	f := newLoginFixture(t)
	r, state := f.start(t, "")
	if _, e := f.service.Complete(context.Background(), state, "code", security.Random()); e == nil {
		t.Fatal("wrong binding accepted")
	}
	if e := f.service.Reject(context.Background(), state, security.Random()); e == nil {
		t.Fatal("wrong rejection binding accepted")
	}
	if f.provider.calls.Load() != 0 {
		t.Fatal("wrong browser exchanged")
	}
	if _, e := f.service.Complete(context.Background(), state, "code", r.BrowserToken); e != nil {
		t.Fatal(e)
	}
	if _, e := f.service.Complete(context.Background(), state, "code", r.BrowserToken); e == nil {
		t.Fatal("replay accepted")
	}
	if f.provider.calls.Load() != 1 {
		t.Fatal("replay exchanged")
	}
	r, state = f.start(t, "")
	if e := f.service.Reject(context.Background(), state, r.BrowserToken); e != nil {
		t.Fatal(e)
	}
	if _, e := f.service.Complete(context.Background(), state, "code", r.BrowserToken); e == nil {
		t.Fatal("rejected callback accepted")
	}
	r, state = f.start(t, "")
	f.clock.Add(600 * time.Second)
	if _, e := f.service.Complete(context.Background(), state, "code", r.BrowserToken); e == nil {
		t.Fatal("expired accepted")
	}
}
func TestOwnerLoginConcurrentCallbacks(t *testing.T) {
	f := newLoginFixture(t)
	f.provider.entered = make(chan struct{}, 1)
	f.provider.release = make(chan struct{})
	r, state := f.start(t, "")
	done := make(chan error, 1)
	go func() { _, e := f.service.Complete(context.Background(), state, "code", r.BrowserToken); done <- e }()
	<-f.provider.entered
	if _, e := f.service.Complete(context.Background(), state, "code", r.BrowserToken); e == nil {
		t.Fatal("concurrent callback accepted")
	}
	close(f.provider.release)
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	if f.provider.calls.Load() != 1 || liveLoginSessions(f.snapshot(t)) != 1 {
		t.Fatal("duplicate exchange/session")
	}
}
func TestLogoutDuringExchange(t *testing.T) {
	for _, mode := range []string{"logout-session", "logout-binding", "expiry", "disable"} {
		t.Run(mode, func(t *testing.T) {
			f := newLoginFixture(t)
			prior := f.prior(t)
			f.provider.entered = make(chan struct{}, 1)
			f.provider.release = make(chan struct{})
			r, state := f.start(t, prior)
			done := make(chan error, 1)
			go func() { _, e := f.service.Complete(context.Background(), state, "code", r.BrowserToken); done <- e }()
			<-f.provider.entered
			switch mode {
			case "logout-session":
				if e := f.service.Logout(context.Background(), prior, ""); e != nil {
					t.Fatal(e)
				}
			case "logout-binding":
				if e := f.service.Logout(context.Background(), "", r.BrowserToken); e != nil {
					t.Fatal(e)
				}
			case "expiry":
				f.clock.Add(601 * time.Second)
			case "disable":
				if e := f.repo.Transact(context.Background(), func(st *domain.State) error {
					st.Users["disabled"] = domain.User{ID: "disabled", Issuer: f.cfg.Issuer, Subject: "owner-1", Status: "disabled"}
					return nil
				}); e != nil {
					t.Fatal(e)
				}
			}
			close(f.provider.release)
			if e := <-done; e == nil {
				t.Fatal("cancelled exchange issued session")
			}
			st := f.snapshot(t)
			for _, session := range st.Sessions {
				if session.UserID != "prior-owner" && st.Now.Before(session.ExpiresAt) {
					t.Fatal("replacement live")
				}
			}
			if mode == "disable" && st.Users["disabled"].Status != "disabled" {
				t.Fatal("disabled identity reactivated")
			}
		})
	}
}
func TestLogoutBeforeCallbackCookieDelivery(t *testing.T) {
	f := newLoginFixture(t)
	prior := f.prior(t)
	r, state := f.start(t, prior)
	result, e := f.service.Complete(context.Background(), state, "code", r.BrowserToken)
	if e != nil {
		t.Fatal(e)
	}
	if e = f.service.Cleanup(context.Background()); e != nil {
		t.Fatal(e)
	}
	if len(f.snapshot(t).OwnerLogins) != 1 {
		t.Fatal("completed relationship cleaned before delivery")
	}
	if e = f.service.Logout(context.Background(), "", r.BrowserToken); e != nil {
		t.Fatal(e)
	}
	st := f.snapshot(t)
	if st.Now.Before(st.Sessions[security.Hash(result.SessionToken)].ExpiresAt) {
		t.Fatal("delayed cookie restores access")
	}
	if e = f.service.Cleanup(context.Background()); e != nil {
		t.Fatal(e)
	}
	if len(f.snapshot(t).OwnerLogins) != 0 {
		t.Fatal("expired replacement metadata retained")
	}
}
func TestOwnerLoginUnauthenticatedLogoutDenied(t *testing.T) {
	f := newLoginFixture(t)
	r, _ := f.start(t, "")
	for _, pair := range [][2]string{{"", ""}, {"unknown", ""}, {"", security.Random()}, {"unknown", security.Random()}} {
		if e := f.service.Logout(context.Background(), pair[0], pair[1]); !errors.Is(e, domain.ErrDenied) {
			t.Fatal("unauthenticated logout accepted", e)
		}
	}
	if e := f.service.Logout(context.Background(), "", r.BrowserToken); e != nil {
		t.Fatal(e)
	}
}
func TestOwnerLoginPersistenceFailure(t *testing.T) {
	for _, mode := range []string{"secret-write", "uncertain-secret-write", "secret-read", "start-db", "uncertain-consume", "final-db", "uncertain-final-db"} {
		t.Run(mode, func(t *testing.T) {
			f := newLoginFixture(t)
			switch mode {
			case "secret-write":
				f.secrets.setErrors(true, false, false, false)
			case "uncertain-secret-write":
				f.secrets.setErrors(false, false, false, true)
			}
			if strings.Contains(mode, "secret-write") {
				if r, e := f.service.Start(context.Background(), ""); e == nil || r.AuthorizationURL != "" {
					t.Fatal("failed start published URL")
				}
				return
			}
			if mode == "start-db" {
				f.repo.fail(false)
				if r, e := f.service.Start(context.Background(), ""); e == nil || r.AuthorizationURL != "" {
					t.Fatal("failed DB published URL")
				}
				return
			}
			r, state := f.start(t, "")
			switch mode {
			case "secret-read":
				f.secrets.setErrors(false, true, false, false)
			case "uncertain-consume":
				f.repo.fail(true)
			case "final-db", "uncertain-final-db":
				f.provider.entered = make(chan struct{}, 1)
				f.provider.release = make(chan struct{})
			}
			done := make(chan error, 1)
			go func() {
				result, e := f.service.Complete(context.Background(), state, "code", r.BrowserToken)
				if e != nil && result.SessionToken != "" {
					e = errors.New("failure exposed session")
				}
				done <- e
			}()
			if mode == "final-db" || mode == "uncertain-final-db" {
				<-f.provider.entered
				f.repo.fail(mode == "uncertain-final-db")
				close(f.provider.release)
			}
			if e := <-done; e == nil {
				t.Fatal("persistence failure accepted")
			}
			if _, e := f.service.Complete(context.Background(), state, "code", r.BrowserToken); e == nil {
				t.Fatal("failed exchange replay accepted")
			}
			if liveLoginSessions(f.snapshot(t)) != 0 {
				t.Fatal("persistence failure left live session")
			}
		})
	}
}
func TestOwnerLoginCleanupRetriesSecretFailure(t *testing.T) {
	f := newLoginFixture(t)
	r, state := f.start(t, "")
	f.secrets.setErrors(false, false, true, false)
	if e := f.service.Reject(context.Background(), state, r.BrowserToken); e != nil {
		t.Fatal(e)
	}
	if e := f.service.Cleanup(context.Background()); e == nil {
		t.Fatal("secret failure swallowed")
	}
	if len(f.snapshot(t).OwnerLogins) != 1 {
		t.Fatal("metadata deleted before secret cleanup")
	}
	f.secrets.setErrors(false, false, false, false)
	if e := f.service.Cleanup(context.Background()); e != nil {
		t.Fatal(e)
	}
	if len(f.snapshot(t).OwnerLogins) != 0 {
		t.Fatal("cleanup not retried")
	}
}
func TestOwnerLoginPriorSessionExpiryDuringExchange(t *testing.T) {
	f := newLoginFixture(t)
	prior := f.prior(t)
	f.provider.entered = make(chan struct{}, 1)
	f.provider.release = make(chan struct{})
	r, state := f.start(t, prior)
	done := make(chan error, 1)
	go func() { _, e := f.service.Complete(context.Background(), state, "code", r.BrowserToken); done <- e }()
	<-f.provider.entered
	if e := f.repo.Transact(context.Background(), func(st *domain.State) error {
		p := st.Sessions[prior]
		p.ExpiresAt = st.Now
		st.Sessions[prior] = p
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	close(f.provider.release)
	if e := <-done; e == nil {
		t.Fatal("expired prior session restored")
	}
}

func TestOwnerLoginCapacityAndCleanupBound(t *testing.T) {
	f := newLoginFixture(t)
	err := f.repo.Transact(context.Background(), func(st *domain.State) error {
		for i := 0; i < activeLoginLimit; i++ {
			id := security.ID()
			st.OwnerLogins[id] = domain.OwnerLoginTransaction{ID: id, StateHash: security.Hash(id), BrowserHash: security.Hash("binding" + id), NonceHash: security.Hash("nonce" + id), SecretRef: ownerSecretPath(id), Issuer: f.cfg.Issuer, ClientID: f.cfg.ClientID, RedirectURI: f.cfg.RedirectURI, Status: "pending", ExpiresAt: st.Now.Add(TransactionLifetime)}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if result, err := f.service.Start(context.Background(), ""); !errors.Is(err, ErrCapacity) || result.AuthorizationURL != "" {
		t.Fatal("active limit not enforced", err)
	}
	f.clock.Add(TransactionLifetime)
	if err := f.service.Cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(f.snapshot(t).OwnerLogins) != activeLoginLimit-cleanupBatch {
		t.Fatal("cleanup exceeded batch bound")
	}
	if _, err := f.service.Start(context.Background(), ""); err != nil {
		t.Fatal("expired logins exhausted capacity", err)
	}
}

func TestOwnerLoginCancellationDoesNotRevokeOtherBrowsers(t *testing.T) {
	f := newLoginFixture(t)
	a, stateA := f.start(t, "")
	sessionA, err := f.service.Complete(context.Background(), stateA, "code", a.BrowserToken)
	if err != nil {
		t.Fatal(err)
	}
	b, stateB := f.start(t, "")
	sessionB, err := f.service.Complete(context.Background(), stateB, "code", b.BrowserToken)
	if err != nil {
		t.Fatal(err)
	}
	pending, statePending := f.start(t, security.Hash(sessionB.SessionToken))
	if err = f.service.Logout(context.Background(), "", a.BrowserToken); err != nil {
		t.Fatal(err)
	}
	st := f.snapshot(t)
	if st.Now.Before(st.Sessions[security.Hash(sessionA.SessionToken)].ExpiresAt) || !st.Now.Before(st.Sessions[security.Hash(sessionB.SessionToken)].ExpiresAt) {
		t.Fatal("binding revoked unrelated browser")
	}
	if _, err = f.service.Complete(context.Background(), statePending, "code", pending.BrowserToken); err != nil {
		t.Fatal("other browser's pending transaction cancelled", err)
	}
}

func TestOwnerLoginRejectsChangedConfigurationAndSecret(t *testing.T) {
	for _, mode := range []string{"issuer", "client", "callback", "secret"} {
		t.Run(mode, func(t *testing.T) {
			f := newLoginFixture(t)
			r, state := f.start(t, "")
			cfg := f.cfg
			switch mode {
			case "issuer":
				cfg.Issuer = "https://another.example"
			case "client":
				cfg.ClientID = "another"
			case "callback":
				cfg.RedirectURI = "http://localhost:8080/auth/oidc/callback"
			case "secret":
				var tx domain.OwnerLoginTransaction
				for _, v := range f.snapshot(t).OwnerLogins {
					tx = v
				}
				var secret loginSecret
				version, err := f.secrets.GetJSON(context.Background(), tx.SecretRef, &secret)
				if err != nil {
					t.Fatal(err)
				}
				secret.TransactionID = security.ID()
				if _, err = f.secrets.PutJSON(context.Background(), tx.SecretRef, secret, version); err != nil {
					t.Fatal(err)
				}
			}
			svc, err := NewService(f.repo, f.secrets, f.provider, cfg)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = svc.Complete(context.Background(), state, "code", r.BrowserToken); err == nil {
				t.Fatal("changed binding accepted")
			}
			if f.provider.calls.Load() != 0 {
				t.Fatal("changed binding exchanged code")
			}
		})
	}
}

func TestOwnerLoginProviderFailureConsumesTransaction(t *testing.T) {
	for _, identity := range []Identity{{Issuer: "https://another.example", Subject: "owner"}, {Issuer: "https://idp.example", Subject: ""}, {Issuer: "https://idp.example", Subject: "bad\nsubject"}} {
		f := newLoginFixture(t)
		f.provider.setIdentity(identity)
		r, state := f.start(t, "")
		if _, err := f.service.Complete(context.Background(), state, "code", r.BrowserToken); err == nil {
			t.Fatal("unverified identity accepted")
		}
		if _, err := f.service.Complete(context.Background(), state, "code", r.BrowserToken); err == nil {
			t.Fatal("bad identity replayed")
		}
		if f.provider.calls.Load() != 1 {
			t.Fatal("bad identity exchange repeated")
		}
	}
	f := newLoginFixture(t)
	f.provider.err = errors.New("secret provider body")
	r, state := f.start(t, "")
	if _, err := f.service.Complete(context.Background(), state, "code", r.BrowserToken); err != ErrProvider {
		t.Fatal("provider error exposed", err)
	}
}

func TestOwnerLoginCleanupHonorsCancellation(t *testing.T) {
	f := newLoginFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := f.service.Cleanup(ctx); err == nil {
		t.Fatal("cancelled cleanup succeeded")
	}
}

func TestOwnerLoginCleanupAfterConfigurationChange(t *testing.T) {
	f := newLoginFixture(t)
	_, _ = f.start(t, "")
	var ref string
	for _, tx := range f.snapshot(t).OwnerLogins {
		ref = tx.SecretRef
	}
	f.clock.Add(TransactionLifetime)
	cfg := f.cfg
	cfg.Issuer = "https://replacement.example"
	cfg.ClientID = "replacement-client"
	cfg.RedirectURI = "http://localhost:9090/auth/oidc/callback"
	svc, err := NewService(f.repo, f.secrets, f.provider, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err = svc.Cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(f.snapshot(t).OwnerLogins) != 0 {
		t.Fatal("historical configuration metadata retained")
	}
	var secret loginSecret
	if _, err = f.secrets.GetJSON(context.Background(), ref, &secret); !errors.Is(err, tokens.ErrNotFound) {
		t.Fatal("historical verifier retained", err)
	}
}

// Real adapter acceptance is isolated in its own disposable PostgreSQL schema;
// OpenBao paths use fresh UUIDs and contain only synthetic verifier material.
func TestOwnerLoginPostgresOpenBao(t *testing.T) {
	dsn, address := os.Getenv("TOOLBOX_TEST_DATABASE_URL"), os.Getenv("TOOLBOX_TEST_OPENBAO_ADDR")
	if dsn == "" || address == "" {
		t.Skip("set TOOLBOX_TEST_DATABASE_URL and TOOLBOX_TEST_OPENBAO_ADDR/TOKEN for disposable owner-login adapter acceptance")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := "owner_login_test_" + strings.ReplaceAll(security.ID(), "-", "")
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
		admin.Close(ctx)
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := admin.Exec(cleanupCtx, "DROP SCHEMA "+quoted+" CASCADE"); err != nil {
			t.Error(err)
		}
		admin.Close(cleanupCtx)
	})
	dbDSN := dsn + " search_path=" + schema
	if parsed, parseErr := url.Parse(dsn); parseErr == nil && (parsed.Scheme == "postgres" || parsed.Scheme == "postgresql") {
		query := parsed.Query()
		query.Set("search_path", schema)
		parsed.RawQuery = query.Encode()
		dbDSN = parsed.String()
	}
	db, err := store.OpenPostgres(ctx, dbDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	if err = db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	secrets, err := tokens.NewOpenBaoFixture(tokens.OpenBaoConfig{Address: address, Mount: "secret", Token: os.Getenv("TOOLBOX_TEST_OPENBAO_TOKEN")})
	if err != nil {
		t.Fatal(err)
	}
	provider := &loginProvider{identity: Identity{Issuer: "https://idp.example", Subject: "synthetic-owner"}}
	cfg := ServiceConfig{Issuer: provider.identity.Issuer, ClientID: "synthetic-client", RedirectURI: "http://127.0.0.1:8080/auth/oidc/callback", Pepper: []byte(strings.Repeat("s", 32))}
	svc, err := NewService(db, secrets, provider, cfg)
	if err != nil {
		t.Fatal(err)
	}
	start, err := svc.Start(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(start.AuthorizationURL)
	state := u.Query().Get("state")
	var tx domain.OwnerLoginTransaction
	if err = db.Transact(ctx, func(st *domain.State) error {
		for _, candidate := range st.OwnerLogins {
			tx = candidate
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = secrets.DeleteJSON(cleanupCtx, tx.SecretRef)
	})
	var secret loginSecret
	version, err := secrets.GetJSON(ctx, tx.SecretRef, &secret)
	if err != nil || version < 1 || len(secret.Verifier) != 43 {
		t.Fatal("real verifier write/read", err)
	}
	if _, err = secrets.PutJSON(ctx, tx.SecretRef, secret, version-1); !errors.Is(err, tokens.ErrCAS) {
		t.Fatal("real store CAS not enforced", err)
	}
	first, err := svc.Complete(ctx, state, "synthetic-code", start.BrowserToken)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = secrets.GetJSON(ctx, tx.SecretRef, &secret); !errors.Is(err, tokens.ErrNotFound) {
		t.Fatal("real verifier not hidden after exchange", err)
	}
	priorID := security.Hash(first.SessionToken)
	if err = db.Transact(ctx, func(st *domain.State) error {
		st.OAuth["synthetic-google"] = domain.OAuthTransaction{ID: "synthetic-google", OwnerID: first.UserID, SessionID: priorID, StateHash: security.Hash("state"), NonceHash: security.Hash("nonce"), SecretRef: "oauth-transactions/synthetic-google", ExpiresAt: st.Now.Add(time.Minute)}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	next, err := svc.Start(ctx, priorID)
	if err != nil {
		t.Fatal(err)
	}
	u, _ = url.Parse(next.AuthorizationURL)
	second, err := svc.Complete(ctx, u.Query().Get("state"), "synthetic-code", next.BrowserToken)
	if err != nil {
		t.Fatal(err)
	}
	if first.UserID != second.UserID {
		t.Fatal("real adapter changed owner identity")
	}
	if err = db.Transact(ctx, func(st *domain.State) error {
		if _, ok := st.Sessions[priorID]; !ok || st.Now.Before(st.Sessions[priorID].ExpiresAt) || st.OAuth["synthetic-google"].SessionID != priorID {
			return fmt.Errorf("rotation lost expired Google FK parent")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err = svc.Cleanup(ctx); err != nil {
		t.Fatal(err)
	}
	if err = svc.Logout(ctx, "", next.BrowserToken); err != nil {
		t.Fatal(err)
	}
	if err = svc.Cleanup(ctx); err != nil {
		t.Fatal(err)
	}
	if err = db.Transact(ctx, func(st *domain.State) error {
		if len(st.OwnerLogins) != 0 || st.Now.Before(st.Sessions[security.Hash(second.SessionToken)].ExpiresAt) {
			return fmt.Errorf("real logout/cleanup left usable replacement")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestOwnerLoginReplacementStartsShareCancellation(t *testing.T) {
	f := newLoginFixture(t)
	f.provider.entered = make(chan struct{}, 1)
	f.provider.release = make(chan struct{})
	a, stateA := f.start(t, "")
	done := make(chan error, 1)
	go func() {
		_, err := f.service.Complete(context.Background(), stateA, "code", a.BrowserToken)
		done <- err
	}()
	<-f.provider.entered
	type outcome struct {
		result StartResult
		err    error
	}
	starts := make(chan outcome, 2)
	for i := 0; i < 2; i++ {
		go func() {
			result, err := f.service.Start(context.Background(), "", a.BrowserToken)
			starts <- outcome{result, err}
		}()
	}
	for i := 0; i < 2; i++ {
		out := <-starts
		if out.err != nil {
			if !errors.Is(out.err, domain.ErrDenied) {
				t.Fatal(out.err)
			}
			continue
		}
		if out.result.BrowserToken != a.BrowserToken {
			t.Fatal("replacement changed cancellation binding")
		}
	}
	pending := 0
	for _, tx := range f.snapshot(t).OwnerLogins {
		if tx.Status == "pending" {
			pending++
		}
	}
	if pending != 1 {
		t.Fatal("replacement starts did not retire earlier transaction")
	}
	if err := f.service.Logout(context.Background(), "", a.BrowserToken); err != nil {
		t.Fatal(err)
	}
	close(f.provider.release)
	if err := <-done; err == nil {
		t.Fatal("superseded callback restored access after logout")
	}
	if liveLoginSessions(f.snapshot(t)) != 0 {
		t.Fatal("replacement logout left live session")
	}
}

func TestOwnerLoginReplacementProtectsAuthenticatedPrior(t *testing.T) {
	f := newLoginFixture(t)
	start, state := f.start(t, "")
	first, err := f.service.Complete(context.Background(), state, "code", start.BrowserToken)
	if err != nil {
		t.Fatal(err)
	}
	prior := security.Hash(first.SessionToken)
	replacement, err := f.service.Start(context.Background(), prior, start.BrowserToken)
	if err != nil {
		t.Fatal(err)
	}
	if !ownerSessionLive(f.snapshot(t), prior) {
		t.Fatal("replacement start expired its authenticated prior")
	}
	u, _ := url.Parse(replacement.AuthorizationURL)
	second, err := f.service.Complete(context.Background(), u.Query().Get("state"), "code", replacement.BrowserToken)
	if err != nil {
		t.Fatal(err)
	}
	st := f.snapshot(t)
	if ownerSessionLive(st, prior) || !ownerSessionLive(st, security.Hash(second.SessionToken)) {
		t.Fatal("protected prior did not rotate")
	}
	if err = f.service.Logout(context.Background(), "", replacement.BrowserToken); err != nil {
		t.Fatal(err)
	}
	if liveLoginSessions(f.snapshot(t)) != 0 {
		t.Fatal("shared binding failed to revoke replacement")
	}
}

func TestOwnerLoginReplacementRevokesUndeliveredSession(t *testing.T) {
	f := newLoginFixture(t)
	start, state := f.start(t, "")
	first, err := f.service.Complete(context.Background(), state, "code", start.BrowserToken)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.service.Start(context.Background(), "", start.BrowserToken); err != nil {
		t.Fatal(err)
	}
	if ownerSessionLive(f.snapshot(t), security.Hash(first.SessionToken)) {
		t.Fatal("superseded undelivered session remains live")
	}
	invented := security.Random()
	result, err := f.service.Start(context.Background(), "", invented)
	if err != nil {
		t.Fatal(err)
	}
	if result.BrowserToken == invented {
		t.Fatal("caller invented binding accepted")
	}
}

func TestOwnerLoginPublishFailureCleansOrphan(t *testing.T) {
	for _, uncertain := range []bool{false, true} {
		t.Run(fmt.Sprint(uncertain), func(t *testing.T) {
			f := newLoginFixture(t)
			f.secrets.afterPut = func() { f.repo.fail(uncertain) }
			f.secrets.setErrors(false, false, true, false)
			if result, err := f.service.Start(context.Background(), ""); err == nil || result.AuthorizationURL != "" || result.BrowserToken != "" {
				t.Fatal("failed publish exposed authorization state")
			}
			if len(f.secrets.refs) != 1 {
				t.Fatal("failure did not exercise verifier publication")
			}
			ref := f.secrets.refs[0]
			f.secrets.setErrors(false, false, false, false)
			if err := f.service.Cleanup(context.Background()); err != nil {
				t.Fatal(err)
			}
			var secret loginSecret
			if _, err := f.secrets.GetJSON(context.Background(), ref, &secret); !errors.Is(err, tokens.ErrNotFound) {
				t.Fatal("orphan verifier not retried", err)
			}
		})
	}
}

func TestOwnerLoginLogoutDuringStartPublication(t *testing.T) {
	for _, mode := range []string{"pending", "complete"} {
		t.Run(mode, func(t *testing.T) {
			f := newLoginFixture(t)
			start, state := f.start(t, "")
			if mode == "complete" {
				if _, err := f.service.Complete(context.Background(), state, "code", start.BrowserToken); err != nil {
					t.Fatal(err)
				}
			}
			entered, release := make(chan struct{}), make(chan struct{})
			f.secrets.afterPut = func() { close(entered); <-release }
			type outcome struct {
				result StartResult
				err    error
			}
			done := make(chan outcome, 1)
			go func() {
				result, err := f.service.Start(context.Background(), "", start.BrowserToken)
				done <- outcome{result, err}
			}()
			<-entered
			if err := f.service.Logout(context.Background(), "", start.BrowserToken); err != nil {
				t.Fatal(err)
			}
			close(release)
			out := <-done
			if out.err == nil || out.result.AuthorizationURL != "" || out.result.BrowserToken != "" {
				t.Fatal("in-flight start survived logout")
			}
			st := f.snapshot(t)
			if liveLoginSessions(st) != 0 {
				t.Fatal("in-flight start left live session")
			}
			for _, tx := range st.OwnerLogins {
				if tx.Status == "pending" || tx.Status == "exchanging" {
					t.Fatal("in-flight start left usable callback")
				}
			}
		})
	}
}

func TestOwnerLoginSessionConfigurationBinding(t *testing.T) {
	f := newLoginFixture(t)
	prior := f.prior(t)
	result := f.complete(t, "")
	sessionID := security.Hash(result.SessionToken)
	st := f.snapshot(t)
	if f.service.SessionBound(st, prior) || !f.service.SessionBound(st, sessionID) {
		t.Fatal("fixture/prior session not distinguished from verified login")
	}
	cfg := f.cfg
	cfg.ClientID = "rotated-client"
	replacement, err := NewService(f.repo, f.secrets, f.provider, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if replacement.SessionBound(st, sessionID) {
		t.Fatal("old client session remains authorized after reconfiguration")
	}
}
