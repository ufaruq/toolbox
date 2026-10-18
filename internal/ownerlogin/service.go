// Package ownerlogin establishes first-party sessions from verified OIDC identities.
package ownerlogin

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ufaruq/toolbox/internal/domain"
	"github.com/ufaruq/toolbox/internal/security"
	"github.com/ufaruq/toolbox/internal/tokens"
)

const (
	TransactionLifetime = 600 * time.Second
	SessionLifetime     = 8 * time.Hour
	activeLoginLimit    = 500
	cleanupBatch        = 100
	cleanupTimeout      = 3 * time.Second
)

var (
	ErrConfiguration = errors.New("INVALID_OWNER_LOGIN_CONFIGURATION")
	ErrCallback      = errors.New("INVALID_OWNER_LOGIN_CALLBACK")
	ErrPersistence   = errors.New("OWNER_LOGIN_PERSISTENCE_FAILED")
	ErrProvider      = errors.New("OWNER_LOGIN_PROVIDER_FAILED")
	ErrCapacity      = errors.New("OWNER_LOGIN_CAPACITY_EXHAUSTED")
)

type ServiceConfig struct {
	Issuer, ClientID, RedirectURI string
	Pepper                        []byte
}
type StartResult struct {
	AuthorizationURL, BrowserToken string
	ExpiresAt                      time.Time
}
type LoginResult struct {
	SessionToken, CSRFToken, UserID string
	ExpiresAt                       time.Time
}
type Service struct {
	repo          domain.Repository
	secrets       tokens.JSONStore
	provider      Provider
	cfg           ServiceConfig
	cleanupMu     sync.Mutex
	orphanMu      sync.Mutex
	orphans       map[string]struct{}
	cleanupCursor string
}

// loginSecret is confined to the credential store; it never enters a repository snapshot.
type loginSecret struct {
	Verifier      string    `json:"verifier"`
	TransactionID string    `json:"transaction_id"`
	ExpiresAt     time.Time `json:"expires_at"`
}

func NewService(repo domain.Repository, secrets tokens.JSONStore, provider Provider, cfg ServiceConfig) (*Service, error) {
	issuer, e := url.Parse(cfg.Issuer)
	callback, ce := url.Parse(cfg.RedirectURI)
	if repo == nil || secrets == nil || provider == nil || len(cfg.Pepper) != 32 || e != nil || issuer.Scheme != "https" || issuer.Host == "" || issuer.User != nil || issuer.RawQuery != "" || issuer.Fragment != "" || cfg.ClientID == "" || len(cfg.ClientID) > 2048 || strings.ContainsAny(cfg.ClientID, "\r\n\x00") || ce != nil || callback.Scheme != "http" || callback.Host == "" || callback.User != nil || callback.Path != "/auth/oidc/callback" || callback.RawQuery != "" || callback.Fragment != "" {
		return nil, ErrConfiguration
	}
	cfg.Pepper = append([]byte(nil), cfg.Pepper...)
	return &Service{repo: repo, secrets: secrets, provider: provider, cfg: cfg, orphans: map[string]struct{}{}}, nil
}

// Issuer is the immutable trusted issuer used to bind callback metadata.
func (s *Service) Issuer() string { return s.cfg.Issuer }

// SessionBound distinguishes sessions issued by this immutable login configuration
// from fixture sessions or sessions issued for a different OIDC application.
// Call it only inside a repository transaction.
func (s *Service) SessionBound(st *domain.State, sessionID string) bool {
	session, exists := st.Sessions[sessionID]
	if !exists || st.Users[session.UserID].Issuer != s.cfg.Issuer {
		return false
	}
	for _, tx := range st.OwnerLogins {
		if tx.Status == "complete" && tx.IssuedSessionID == sessionID && s.bound(tx) {
			return true
		}
	}
	return false
}

func ownerSecretPath(id string) string { return "owner-login/" + id }
func ownerChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
func ownerRandomValid(raw string) bool {
	b, e := base64.RawURLEncoding.DecodeString(raw)
	return e == nil && len(raw) == 43 && len(b) == 32
}
func ownerSessionLive(st *domain.State, id string) bool {
	v, ok := st.Sessions[id]
	return ok && st.Now.Before(v.ExpiresAt) && st.Users[v.UserID].Status == "active"
}
func ownerLoginScopeLive(st *domain.State, tx domain.OwnerLoginTransaction) bool {
	return (tx.Status == "pending" || tx.Status == "exchanging") && st.Now.Before(tx.ExpiresAt) || tx.Status == "complete" && ownerSessionLive(st, tx.IssuedSessionID)
}
func (s *Service) bound(tx domain.OwnerLoginTransaction) bool {
	return tx.Issuer == s.cfg.Issuer && tx.ClientID == s.cfg.ClientID && tx.RedirectURI == s.cfg.RedirectURI && ownerSecretRefValid(tx)
}
func ownerSecretRefValid(tx domain.OwnerLoginTransaction) bool {
	return tx.ID != "" && !strings.ContainsAny(tx.ID, "/\\") && tx.SecretRef == ownerSecretPath(tx.ID)
}
func (s *Service) matching(st *domain.State, id, state, browser string) (domain.OwnerLoginTransaction, bool) {
	tx, ok := st.OwnerLogins[id]
	return tx, ok && s.bound(tx) && security.Equal(tx.StateHash, security.Hash(state)) && security.Equal(tx.BrowserHash, security.Hash(browser))
}
func (s *Service) rememberOrphan(ref string) {
	s.orphanMu.Lock()
	s.orphans[ref] = struct{}{}
	s.orphanMu.Unlock()
}
func (s *Service) hideSecret(ctx context.Context, ref string) error {
	cleanupCtx, cancel := context.WithTimeout(ctx, cleanupTimeout)
	defer cancel()
	err := s.secrets.DeleteJSON(cleanupCtx, ref)
	if err != nil && !errors.Is(err, tokens.ErrNotFound) {
		return ErrPersistence
	}
	s.orphanMu.Lock()
	delete(s.orphans, ref)
	s.orphanMu.Unlock()
	return nil
}

// Start stores a verifier before publishing its one-use, browser-bound transaction.
// previousSessionID is a repository key obtained from an authenticated browser
// cookie. A recognized existing HttpOnly login binding is retained so overlapping
// replacement starts share one cancellation scope.
func (s *Service) Start(ctx context.Context, previousSessionID string, existingBrowserToken ...string) (StartResult, error) {
	var none StartResult
	s.orphanMu.Lock()
	tooManyOrphans := len(s.orphans) >= activeLoginLimit
	s.orphanMu.Unlock()
	if tooManyOrphans {
		return none, ErrCapacity
	}
	id := security.ID()
	state, nonce, browser, verifier := id+"."+security.Random(), security.Random(), security.Random(), security.Random()
	browserHash := ""
	var source domain.OwnerLoginTransaction
	var suppliedBrowser string
	if len(existingBrowserToken) == 1 && ownerRandomValid(existingBrowserToken[0]) {
		suppliedBrowser = existingBrowserToken[0]
	}
	var expiry time.Time
	check := func(st *domain.State) error {
		if previousSessionID != "" && !ownerSessionLive(st, previousSessionID) {
			return domain.ErrDenied
		}
		active := 0
		for _, tx := range st.OwnerLogins {
			if browserHash != "" && security.Equal(tx.BrowserHash, browserHash) {
				continue
			}
			if (tx.Status == "pending" || tx.Status == "exchanging") && st.Now.Before(tx.ExpiresAt) {
				active++
			}
		}
		if active >= activeLoginLimit {
			return ErrCapacity
		}
		return nil
	}
	if err := s.repo.Transact(ctx, func(st *domain.State) error {
		if suppliedBrowser != "" {
			candidateHash := security.Hash(suppliedBrowser)
			for _, tx := range st.OwnerLogins {
				if ownerSecretRefValid(tx) && security.Equal(tx.BrowserHash, candidateHash) && ownerLoginScopeLive(st, tx) {
					// Prefer the current pending generation over a retained completion.
					if source.ID == "" || source.Status == "complete" {
						source = tx
					}
				}
			}
			if source.ID != "" {
				browser, browserHash = suppliedBrowser, candidateHash
			}
		}
		if e := check(st); e != nil {
			return e
		}
		expiry = st.Now.Add(TransactionLifetime)
		return nil
	}); err != nil {
		return none, err
	}
	authURL, err := s.provider.AuthorizationURL(state, nonce, ownerChallenge(verifier))
	if err != nil {
		return none, ErrProvider
	}
	ref := ownerSecretPath(id)
	secret := loginSecret{Verifier: verifier, TransactionID: id, ExpiresAt: expiry}
	if _, err = s.secrets.PutJSON(ctx, ref, secret, 0); err != nil {
		s.rememberOrphan(ref)
		_ = s.hideSecret(context.WithoutCancel(ctx), ref)
		return none, ErrPersistence
	}
	err = s.repo.Transact(ctx, func(st *domain.State) error {
		if source.ID != "" {
			current, exists := st.OwnerLogins[source.ID]
			if !exists || current.Status != source.Status || current.IssuedSessionID != source.IssuedSessionID || !ownerLoginScopeLive(st, current) {
				return domain.ErrDenied
			}
		}
		if e := check(st); e != nil {
			return e
		}
		if !st.Now.Before(expiry) {
			return ErrCallback
		}
		if _, exists := st.OwnerLogins[id]; exists {
			return ErrCallback
		}
		if browserHash != "" {
			for oldID, previous := range st.OwnerLogins {
				if !ownerSecretRefValid(previous) || !security.Equal(previous.BrowserHash, browserHash) {
					continue
				}
				if previous.Status == "pending" || previous.Status == "exchanging" {
					previous.Status = "cancelled"
					st.OwnerLogins[oldID] = previous
				}
				if previous.Status == "complete" && previous.IssuedSessionID != previousSessionID {
					if issued, ok := st.Sessions[previous.IssuedSessionID]; ok {
						issued.ExpiresAt = st.Now
						st.Sessions[issued.ID] = issued
					}
				}
			}
		}
		st.OwnerLogins[id] = domain.OwnerLoginTransaction{ID: id, StateHash: security.Hash(state), BrowserHash: security.Hash(browser), NonceHash: security.Hash(nonce), SecretRef: ref, Issuer: s.cfg.Issuer, ClientID: s.cfg.ClientID, RedirectURI: s.cfg.RedirectURI, PreviousSessionID: previousSessionID, Status: "pending", ExpiresAt: expiry}
		return nil
	})
	if err != nil {
		s.rememberOrphan(ref)
		_ = s.hideSecret(context.WithoutCancel(ctx), ref)
		return none, err
	}
	return StartResult{AuthorizationURL: authURL, BrowserToken: browser, ExpiresAt: expiry}, nil
}

// Complete fences the non-idempotent provider call with an irreversible database transition.
func (s *Service) Complete(ctx context.Context, state, code, browserToken string) (result LoginResult, resultErr error) {
	id, _, err := security.CredentialParts(state)
	if err != nil || !ownerRandomValid(browserToken) || len(code) == 0 || len(code) > 4096 || strings.ContainsAny(code, "\r\n\x00") {
		return result, ErrCallback
	}
	var tx domain.OwnerLoginTransaction
	err = s.repo.Transact(ctx, func(st *domain.State) error {
		candidate, ok := s.matching(st, id, state, browserToken)
		if !ok || candidate.Status != "pending" || !st.Now.Before(candidate.ExpiresAt) || (candidate.PreviousSessionID != "" && !ownerSessionLive(st, candidate.PreviousSessionID)) {
			return ErrCallback
		}
		candidate.Status = "exchanging"
		st.OwnerLogins[id] = candidate
		tx = candidate
		return nil
	})
	if err != nil {
		return result, err
	}
	// Cleanup is detached and bounded, and a failure leaves durable metadata for the worker.
	defer func() {
		if resultErr != nil {
			s.failExchange(ctx, id, "")
		}
		_ = s.hideSecret(context.WithoutCancel(ctx), tx.SecretRef)
	}()
	var secret loginSecret
	if _, err = s.secrets.GetJSON(ctx, tx.SecretRef, &secret); err != nil {
		return LoginResult{}, ErrPersistence
	}
	if secret.TransactionID != tx.ID || !secret.ExpiresAt.Equal(tx.ExpiresAt) || !ownerRandomValid(secret.Verifier) {
		return LoginResult{}, ErrCallback
	}
	identity, err := s.provider.Exchange(ctx, code, secret.Verifier, tx.NonceHash)
	if err != nil {
		return LoginResult{}, ErrProvider
	}
	if identity.Issuer != s.cfg.Issuer || !ownerSubjectValid(identity.Subject) {
		return LoginResult{}, ErrCallback
	}
	raw := security.Random()
	sessionID := security.Hash(raw)
	csrf := security.KeyedHash(s.cfg.Pepper, raw)
	var completed LoginResult
	err = s.repo.Transact(ctx, func(st *domain.State) error {
		current, ok := s.matching(st, id, state, browserToken)
		if !ok || current.Status != "exchanging" || !st.Now.Before(current.ExpiresAt) || (current.PreviousSessionID != "" && !ownerSessionLive(st, current.PreviousSessionID)) {
			return ErrCallback
		}
		var user domain.User
		for _, candidate := range st.Users {
			if candidate.Issuer == identity.Issuer && candidate.Subject == identity.Subject {
				user = candidate
				break
			}
		}
		if user.ID != "" && user.Status != "active" {
			return domain.ErrDenied
		}
		if user.ID == "" {
			user = domain.User{ID: security.ID(), Issuer: identity.Issuer, Subject: identity.Subject, Status: "active"}
			st.Users[user.ID] = user
		}
		expiry := st.Now.Add(SessionLifetime)
		st.Sessions[sessionID] = domain.Session{ID: sessionID, UserID: user.ID, CSRFHash: security.Hash(csrf), ExpiresAt: expiry}
		if current.PreviousSessionID != "" {
			prior := st.Sessions[current.PreviousSessionID]
			prior.ExpiresAt = st.Now
			st.Sessions[prior.ID] = prior
		}
		current.Status = "complete"
		current.IssuedSessionID = sessionID
		st.OwnerLogins[id] = current
		st.Audits = append(st.Audits, domain.Audit{ID: security.ID(), At: st.Now, ActorType: "user", ActorID: user.ID, SubjectID: user.ID, Action: "owner.login", Outcome: "allowed"})
		completed = LoginResult{SessionToken: raw, CSRFToken: csrf, UserID: user.ID, ExpiresAt: expiry}
		return nil
	})
	if err != nil {
		// A lost commit acknowledgement must not leave an issued replacement usable.
		s.failExchange(ctx, id, sessionID)
		return LoginResult{}, err
	}
	return completed, nil
}
func ownerSubjectValid(subject string) bool {
	if subject == "" || len(subject) > 255 || !utf8.ValidString(subject) {
		return false
	}
	for _, r := range subject {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
func (s *Service) failExchange(ctx context.Context, id, issuedSessionID string) {
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
	defer cancel()
	_ = s.repo.Transact(cleanupCtx, func(st *domain.State) error {
		tx, ok := st.OwnerLogins[id]
		if !ok || !s.bound(tx) {
			return nil
		}
		if tx.Status == "exchanging" {
			tx.Status = "failed"
			st.OwnerLogins[id] = tx
		}
		if issuedSessionID != "" && tx.Status == "complete" && tx.IssuedSessionID == issuedSessionID {
			if session, ok := st.Sessions[issuedSessionID]; ok {
				session.ExpiresAt = st.Now
				st.Sessions[issuedSessionID] = session
			}
		}
		return nil
	})
}

// Reject consumes only a correctly bound pending provider-denial callback.
func (s *Service) Reject(ctx context.Context, state, browserToken string) error {
	id, _, err := security.CredentialParts(state)
	if err != nil || !ownerRandomValid(browserToken) {
		return ErrCallback
	}
	var ref string
	err = s.repo.Transact(ctx, func(st *domain.State) error {
		tx, ok := s.matching(st, id, state, browserToken)
		if !ok || tx.Status != "pending" || !st.Now.Before(tx.ExpiresAt) {
			return ErrCallback
		}
		tx.Status = "cancelled"
		st.OwnerLogins[id] = tx
		ref = tx.SecretRef
		return nil
	})
	if err != nil {
		return err
	}
	_ = s.hideSecret(context.WithoutCancel(ctx), ref)
	return nil
}

// Logout accepts an already authenticated session key, or an unguessable browser
// binding that authorizes cancellation of only its own login/replacement. HTTP
// callers must validate the session cookie and CSRF before passing a session key.
func (s *Service) Logout(ctx context.Context, sessionID, browserToken string) error {
	browserHash := ""
	if ownerRandomValid(browserToken) {
		browserHash = security.Hash(browserToken)
	}
	return s.repo.Transact(ctx, func(st *domain.State) error {
		authenticated := sessionID != "" && ownerSessionLive(st, sessionID)
		matchingIDs := map[string]bool{}
		for id, tx := range st.OwnerLogins {
			if s.bound(tx) && browserHash != "" && security.Equal(tx.BrowserHash, browserHash) && (tx.Status == "pending" || tx.Status == "exchanging" || tx.Status == "complete") {
				matchingIDs[id] = true
			}
		}
		if !authenticated && len(matchingIDs) == 0 {
			return domain.ErrDenied
		}
		actor := ""
		if authenticated {
			session := st.Sessions[sessionID]
			actor = session.UserID
			session.ExpiresAt = st.Now
			st.Sessions[sessionID] = session
		}
		for id, tx := range st.OwnerLogins {
			bound := matchingIDs[id]
			if !bound && (!authenticated || tx.PreviousSessionID != sessionID) {
				continue
			}
			if tx.Status == "pending" || tx.Status == "exchanging" {
				tx.Status = "cancelled"
				st.OwnerLogins[id] = tx
			}
			// An expired prior session alone grants no authority over its replacement.
			if bound && tx.Status == "complete" && tx.IssuedSessionID != "" {
				if replacement, ok := st.Sessions[tx.IssuedSessionID]; ok {
					replacement.ExpiresAt = st.Now
					st.Sessions[replacement.ID] = replacement
					if actor == "" {
						actor = replacement.UserID
					}
				}
			}
		}
		if actor != "" {
			st.Audits = append(st.Audits, domain.Audit{ID: security.ID(), At: st.Now, ActorType: "user", ActorID: actor, SubjectID: actor, Action: "owner.logout", Outcome: "allowed"})
		}
		return nil
	})
}

// Cleanup hides current verifier versions before removing eligible metadata. A
// rotating cursor prevents retained completed rows from starving newer cleanup.
// Historical secret-version destruction requires a separate retention policy.
func (s *Service) Cleanup(ctx context.Context) error {
	s.cleanupMu.Lock()
	defer s.cleanupMu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	budget := cleanupBatch
	s.orphanMu.Lock()
	refs := make([]string, 0, len(s.orphans))
	for ref := range s.orphans {
		refs = append(refs, ref)
	}
	s.orphanMu.Unlock()
	slices.Sort(refs)
	var cleanupErr error
	for _, ref := range refs {
		if ctx.Err() != nil {
			return ErrPersistence
		}
		if budget == 0 {
			break
		}
		budget--
		if e := s.hideSecret(ctx, ref); e != nil {
			cleanupErr = e
		}
	}
	if budget == 0 {
		return cleanupErr
	}
	candidates := []domain.OwnerLoginTransaction{}
	err := s.repo.Transact(ctx, func(st *domain.State) error {
		ids := []string{}
		for id, tx := range st.OwnerLogins {
			if tx.Status == "complete" || tx.Status == "failed" || tx.Status == "cancelled" || !st.Now.Before(tx.ExpiresAt) {
				ids = append(ids, id)
			}
		}
		slices.Sort(ids)
		ordered := append([]string{}, ids...)
		if s.cleanupCursor != "" {
			split := 0
			for split < len(ids) && ids[split] <= s.cleanupCursor {
				split++
			}
			ordered = append(append([]string{}, ids[split:]...), ids[:split]...)
		}
		for _, id := range ordered {
			if len(candidates) >= budget {
				break
			}
			tx := st.OwnerLogins[id]
			if !ownerSecretRefValid(tx) {
				continue
			}
			if !st.Now.Before(tx.ExpiresAt) {
				if tx.Status == "pending" {
					tx.Status = "cancelled"
				}
				if tx.Status == "exchanging" {
					tx.Status = "failed"
				}
				st.OwnerLogins[id] = tx
			}
			candidates = append(candidates, tx)
		}
		return nil
	})
	if err != nil {
		return ErrPersistence
	}
	for _, candidate := range candidates {
		if ctx.Err() != nil {
			return ErrPersistence
		}
		s.cleanupCursor = candidate.ID
		if e := s.hideSecret(ctx, candidate.SecretRef); e != nil {
			cleanupErr = e
			continue
		}
		err = s.repo.Transact(ctx, func(st *domain.State) error {
			tx, ok := st.OwnerLogins[candidate.ID]
			if !ok {
				return nil
			}
			if !ownerSecretRefValid(tx) || tx.SecretRef != candidate.SecretRef {
				return ErrCallback
			}
			if tx.Status == "pending" || tx.Status == "exchanging" {
				return nil
			}
			if tx.IssuedSessionID != "" {
				session, exists := st.Sessions[tx.IssuedSessionID]
				if exists && st.Now.Before(session.ExpiresAt) {
					return nil
				}
			}
			delete(st.OwnerLogins, tx.ID)
			return nil
		})
		if err != nil {
			cleanupErr = ErrPersistence
		}
	}
	return cleanupErr
}
