package server

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/ufaruq/toolbox/internal/domain"
	"github.com/ufaruq/toolbox/internal/security"
)

type loginSecret struct {
	Verifier string `json:"verifier"`
}

const loginCookie = "toolbox_owner_login"
const maxOwnerLogins = 1000

var errLoginCapacity = errors.New("owner login capacity reached")

func (s *Server) clearLoginSecret(ctx context.Context, ref string) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	return s.LoginSecrets.DeleteJSON(ctx, ref)
}
func (s *Server) ownerLogin(w http.ResponseWriter, r *http.Request) {
	if s.Identity == nil || s.LoginSecrets == nil {
		fail(w, 503, "IDENTITY_UNAVAILABLE")
		return
	}
	if !s.allowed("owner-login", 60) {
		fail(w, 429, "RATE_LIMITED")
		return
	}
	state, nonce, verifier, browser := security.Random(), security.Random(), security.Random(), security.Random()
	id := security.ID()
	ref := "owner-logins/" + id
	url, e := s.Identity.AuthorizationURL(state, nonce, verifier)
	if e != nil {
		fail(w, 503, "IDENTITY_UNAVAILABLE")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	e = s.Repository.Transact(ctx, func(st *domain.State) error {
		if len(st.OwnerLogins) >= maxOwnerLogins {
			return errLoginCapacity
		}
		st.OwnerLogins[id] = domain.OwnerLogin{ID: id, StateHash: security.Hash(state), NonceHash: security.Hash(nonce), BrowserHash: security.Hash(browser), SecretRef: ref, ExpiresAt: st.Now.Add(10 * time.Minute)}
		return nil
	})
	if e != nil {
		fail(w, 503, "IDENTITY_UNAVAILABLE")
		return
	}
	if _, e = s.LoginSecrets.PutJSON(ctx, ref, loginSecret{Verifier: verifier}, 0); e != nil {
		// A failed write may still have persisted the verifier. Retain the durable
		// reservation for retry if deletion cannot be confirmed.
		if s.clearLoginSecret(ctx, ref) == nil {
			cleanupCtx, cleanupCancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
			defer cleanupCancel()
			_ = s.Repository.Transact(cleanupCtx, func(st *domain.State) error { delete(st.OwnerLogins, id); return nil })
		}
		fail(w, 503, "IDENTITY_UNAVAILABLE")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: loginCookie, Value: browser, Path: "/auth/okta/callback", HttpOnly: true, Secure: !s.Fixture, SameSite: http.SameSiteLaxMode, MaxAge: 600})
	http.Redirect(w, r, url, http.StatusSeeOther)
}
func (s *Server) ownerCallback(w http.ResponseWriter, r *http.Request) {
	if s.Identity == nil || s.LoginSecrets == nil {
		fail(w, 503, "IDENTITY_UNAVAILABLE")
		return
	}
	q, queryErr := url.ParseQuery(r.URL.RawQuery)
	if queryErr != nil || len(q) != 2 || len(q["state"]) != 1 || len(q["code"]) != 1 || len(q.Get("state")) != 43 || len(q.Get("code")) < 1 || len(q.Get("code")) > 4096 {
		fail(w, 400, "INVALID_CALLBACK")
		return
	}
	cookie, e := r.Cookie(loginCookie)
	if e != nil || len(cookie.Value) != 43 {
		fail(w, 400, "LOGIN_REJECTED")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	var login domain.OwnerLogin
	e = s.Repository.Transact(ctx, func(st *domain.State) error {
		for id, tx := range st.OwnerLogins {
			if security.Equal(tx.StateHash, security.Hash(q.Get("state"))) {
				if tx.Consumed || !st.Now.Before(tx.ExpiresAt) || !security.Equal(tx.BrowserHash, security.Hash(cookie.Value)) {
					return domain.ErrDenied
				}
				tx.Consumed = true
				st.OwnerLogins[id] = tx
				login = tx
				return nil
			}
		}
		return domain.ErrDenied
	})
	if e != nil {
		fail(w, 400, "LOGIN_REJECTED")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: loginCookie, Value: "", Path: "/auth/okta/callback", HttpOnly: true, Secure: !s.Fixture, SameSite: http.SameSiteLaxMode, MaxAge: -1})
	defer s.clearLoginSecret(ctx, login.SecretRef)
	var secret loginSecret
	if _, e = s.LoginSecrets.GetJSON(ctx, login.SecretRef, &secret); e != nil {
		fail(w, 400, "LOGIN_REJECTED")
		return
	}
	owner, e := s.Identity.Complete(ctx, q.Get("code"), secret.Verifier, login.NonceHash)
	if e != nil || owner.Issuer != s.Identity.Issuer() || owner.UserID == "" {
		fail(w, 400, "LOGIN_REJECTED")
		return
	}
	raw := security.Random()
	id := security.Hash(raw)
	csrf := security.KeyedHash(s.Pepper, raw)
	e = s.Repository.Transact(ctx, func(st *domain.State) error {
		user := domain.User{}
		for _, u := range st.Users {
			if u.Issuer == owner.Issuer && u.Subject == owner.UserID {
				user = u
				break
			}
		}
		if user.ID == "" {
			user = domain.User{ID: security.ID(), Issuer: owner.Issuer, Subject: owner.UserID, Status: "active"}
			st.Users[user.ID] = user
		}
		if user.Status != "active" {
			return domain.ErrDenied
		}
		st.Sessions[id] = domain.Session{ID: id, UserID: user.ID, CSRFHash: security.Hash(csrf), ExpiresAt: st.Now.Add(8 * time.Hour)}
		return nil
	})
	if e != nil {
		fail(w, 400, "LOGIN_REJECTED")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "toolbox_session", Value: raw, Path: "/", HttpOnly: true, Secure: !s.Fixture, SameSite: http.SameSiteLaxMode, MaxAge: 8 * 3600})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
func (s *Server) ownerLogout(w http.ResponseWriter, r *http.Request) {
	owner, ok := s.requireOwner(w, r, true)
	if !ok {
		return
	}
	var in struct{}
	if !body(w, r, &in) {
		return
	}
	if e := s.Repository.Transact(r.Context(), func(st *domain.State) error { delete(st.Sessions, owner.ID); return nil }); e != nil {
		fail(w, 503, "DEPENDENCY_UNAVAILABLE")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "toolbox_session", Value: "", Path: "/", HttpOnly: true, Secure: !s.Fixture, SameSite: http.SameSiteLaxMode, MaxAge: -1})
	jsonOut(w, 200, map[string]string{"status": "signed_out"})
}

// cleanupOwnerLogins keeps the durable retry reference until verifier deletion
// succeeds. Unexpired transactions remain available to callbacks in progress.
func (s *Server) cleanupOwnerLogins(ctx context.Context) error {
	if s.LoginSecrets == nil {
		return nil
	}
	var expired []domain.OwnerLogin
	if e := s.Repository.Transact(ctx, func(st *domain.State) error {
		for _, v := range st.OwnerLogins {
			if !st.Now.Before(v.ExpiresAt) {
				expired = append(expired, v)
			}
		}
		return nil
	}); e != nil {
		return e
	}
	for _, v := range expired {
		if e := ctx.Err(); e != nil {
			return e
		}
		deleteCtx, deleteCancel := context.WithTimeout(ctx, 2*time.Second)
		deleteErr := s.LoginSecrets.DeleteJSON(deleteCtx, v.SecretRef)
		deleteCancel()
		if e := ctx.Err(); e != nil {
			return e
		}
		if deleteErr != nil {
			continue
		}
		if e := s.Repository.Transact(ctx, func(st *domain.State) error {
			current, ok := st.OwnerLogins[v.ID]
			if ok && current.SecretRef == v.SecretRef && !st.Now.Before(current.ExpiresAt) {
				delete(st.OwnerLogins, v.ID)
			}
			return nil
		}); e != nil {
			return e
		}
	}
	return nil
}
