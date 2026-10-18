// Package oauth establishes owner-bound Google connections. It never authenticates
// a Toolbox owner; callers must supply the existing first-party owner session.
package oauth

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/ufaruq/toolbox/internal/domain"
	"github.com/ufaruq/toolbox/internal/security"
	"github.com/ufaruq/toolbox/internal/tokens"
)

const TransactionLifetime = 10 * time.Minute

var (
	ErrCallback      = errors.New("INVALID_OAUTH_CALLBACK")
	ErrProvider      = errors.New("OAUTH_PROVIDER_FAILED")
	ErrIdentity      = errors.New("INVALID_PROVIDER_IDENTITY")
	ErrScope         = errors.New("OAUTH_SCOPE_MISMATCH")
	ErrPersistence   = errors.New("OAUTH_PERSISTENCE_FAILED")
	ErrReauth        = errors.New("CONNECTION_REAUTH_REQUIRED")
	ErrConfiguration = errors.New("INVALID_OAUTH_CONFIGURATION")
)

// ExchangeResult contains provider credentials and, on success, a verified identity.
// Implementations must verify signature, issuer, audience, expiry, and nonce before
// returning success. A rejected response may retain known credentials with an error
// exclusively for cleanup; callers must never activate that result. Never serialize
// this value into an API response or logs.
type ExchangeResult struct {
	Subject, ClientID, AccessToken, RefreshToken string
	Expiry                                       time.Time
	Scopes                                       []string
}

type Provider interface {
	ClientID() string
	AuthorizationURL(state, nonce, challenge string) (string, error)
	Exchange(ctx context.Context, code, verifier, nonceHash string) (ExchangeResult, error)
}

type SecretStore interface {
	tokens.SecretStore
	tokens.JSONStore
}

type Service struct {
	repo     domain.Repository
	secrets  SecretStore
	provider Provider
}

type StartResult struct {
	AuthorizationURL string    `json:"authorization_url"`
	ConnectionID     string    `json:"connection_id"`
	ExpiresAt        time.Time `json:"expires_at"`
}

type transactionSecret struct {
	Verifier      string    `json:"verifier"`
	TransactionID string    `json:"transaction_id"`
	ConnectionID  string    `json:"connection_id"`
	ExpiresAt     time.Time `json:"expires_at"`
}

func NewService(repo domain.Repository, secrets SecretStore, provider Provider) (*Service, error) {
	if repo == nil || secrets == nil || provider == nil || provider.ClientID() == "" {
		return nil, ErrConfiguration
	}
	return &Service{repo: repo, secrets: secrets, provider: provider}, nil
}

func liveSession(st *domain.State, ownerID, sessionID string) bool {
	u, ok := st.Users[ownerID]
	session, exists := st.Sessions[sessionID]
	return ok && u.Status == "active" && exists && session.UserID == ownerID && st.Now.Before(session.ExpiresAt)
}

// Start allocates a fresh connection and a one-use transaction. A reconnect always
// gets a new connection ID; old grants are never transferred or reactivated.
func (s *Service) Start(ctx context.Context, ownerID, sessionID string) (StartResult, error) {
	var result StartResult
	if ownerID == "" || sessionID == "" {
		return result, domain.ErrDenied
	}
	id, connectionID := security.ID(), security.ID()
	state, nonce, verifier := id+"."+security.Random(), security.Random(), security.Random()
	var expiry time.Time
	if err := s.repo.Transact(ctx, func(st *domain.State) error {
		if !liveSession(st, ownerID, sessionID) {
			return domain.ErrDenied
		}
		expiry = st.Now.Add(TransactionLifetime)
		return nil
	}); err != nil {
		return result, err
	}
	authorizationURL, err := s.provider.AuthorizationURL(state, nonce, challengeFor(verifier))
	if err != nil {
		return result, err
	}
	secretRef := transactionPath(id)
	secret := transactionSecret{Verifier: verifier, TransactionID: id, ConnectionID: connectionID, ExpiresAt: expiry}
	if _, err = s.secrets.PutJSON(ctx, secretRef, secret, 0); err != nil {
		return result, ErrPersistence
	}
	err = s.repo.Transact(ctx, func(st *domain.State) error {
		if !liveSession(st, ownerID, sessionID) || !st.Now.Before(expiry) {
			return domain.ErrDenied
		}
		if _, exists := st.OAuth[id]; exists {
			return ErrCallback
		}
		if _, exists := st.Connections[connectionID]; exists {
			return ErrCallback
		}
		st.OAuth[id] = domain.OAuthTransaction{ID: id, OwnerID: ownerID, SessionID: sessionID, StateHash: security.Hash(state), NonceHash: security.Hash(nonce), SecretRef: secretRef, ConnectionID: connectionID, ExpiresAt: expiry}
		st.Connections[connectionID] = domain.Connection{ID: connectionID, OwnerID: ownerID, Provider: "google_drive", ClientID: s.provider.ClientID(), Status: "pending", Epoch: 1}
		st.Audits = append(st.Audits, domain.Audit{ID: security.ID(), At: st.Now, ActorType: "user", ActorID: ownerID, SubjectID: ownerID, Action: "connection.oauth.start", ConnectionID: connectionID, Outcome: "pending"})
		return nil
	})
	// A database commit can be uncertain. Do not destroy the verifier on this error;
	// an expired orphan can be removed by the secret-retention cleanup procedure.
	if err != nil {
		return result, err
	}
	return StartResult{AuthorizationURL: authorizationURL, ConnectionID: connectionID, ExpiresAt: expiry}, nil
}

// Complete atomically consumes the transaction before any token-endpoint call.
// Exchange failures and invalid identities require a new Start, never a replay.
func (s *Service) Complete(ctx context.Context, ownerID, sessionID, state, code string) (result domain.Connection, resultErr error) {
	var none domain.Connection
	id, _, err := security.CredentialParts(state)
	if err != nil || len(code) == 0 || len(code) > 4096 || strings.ContainsAny(code, "\r\n\x00") {
		return none, ErrCallback
	}
	var tx domain.OAuthTransaction
	err = s.repo.Transact(ctx, func(st *domain.State) error {
		candidate, ok := st.OAuth[id]
		if !ok || candidate.Consumed || candidate.OwnerID != ownerID || candidate.SessionID != sessionID || !liveSession(st, ownerID, sessionID) || !st.Now.Before(candidate.ExpiresAt) || !security.Equal(candidate.StateHash, security.Hash(state)) {
			return ErrCallback
		}
		connection, ok := st.Connections[candidate.ConnectionID]
		if !ok || connection.OwnerID != ownerID || connection.Status != "pending" || connection.Epoch != 1 || connection.ClientID != s.provider.ClientID() {
			return ErrCallback
		}
		candidate.Consumed = true
		st.OAuth[id] = candidate
		tx = candidate
		return nil
	})
	if err != nil {
		return none, err
	}
	if tx.SecretRef != transactionPath(tx.ID) {
		return none, ErrCallback
	}
	var secret transactionSecret
	if _, err = s.secrets.GetJSON(ctx, tx.SecretRef, &secret); err != nil {
		return none, ErrPersistence
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		_ = s.secrets.DeleteJSON(cleanupCtx, tx.SecretRef)
	}()
	if secret.TransactionID != tx.ID || secret.ConnectionID != tx.ConnectionID || !secret.ExpiresAt.Equal(tx.ExpiresAt) || !validVerifier(secret.Verifier) {
		return none, ErrCallback
	}
	// Fence the non-idempotent exchange at the stable credential path before it
	// can issue credentials. Disconnect cleanup must see an unresolved operation
	// rather than mistake an absent bundle for completed provider cleanup.
	intent, intentVersion, err := s.prepareExchange(ctx, tx, ownerID, sessionID)
	if err != nil {
		return none, err
	}
	exchanged, exchangeErr := s.provider.Exchange(ctx, code, secret.Verifier, tx.NonceHash)
	if exchangeErr != nil && !errors.Is(exchangeErr, tokens.ErrInvalidGrant) && exchanged.AccessToken == "" && exchanged.RefreshToken == "" {
		// An unknown provider outcome cannot be declared cleaned or retried.
		return none, exchangeErr
	}

	// Known credentials and definitive invalid_grant rejections resolve the
	// intent even after cancellation, session loss or disconnect. Persist them
	// with a bounded detached context; a rejected exchange can never activate.
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	bundle := intent
	bundle.Subject, bundle.Generation = exchanged.Subject, 1
	bundle.AccessToken, bundle.RefreshToken, bundle.Expiry = exchanged.AccessToken, exchanged.RefreshToken, exchanged.Expiry
	bundle.Scopes = append([]string(nil), exchanged.Scopes...)
	bundle.State = tokens.StateActive
	unlock, err := s.repo.LockConnection(cleanupCtx, tx.ConnectionID)
	if err != nil {
		// The exchange is resolved even when the database lock cannot be
		// reacquired. CAS only our original intent into cleanup; another
		// worker's generation must never be replaced or activated here.
		// Lock acquisition may have exhausted cleanupCtx's deadline.
		persistCtx, persistCancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer persistCancel()
		_, _ = s.persistExchangeBundle(persistCtx, cleanupExchangeBundle(bundle), intentVersion)
		return none, ErrPersistence
	}
	var version int64
	persisted := false
	defer func() {
		lockErr := unlock()
		if persisted && bundle.State == tokens.StateActive && (resultErr != nil || lockErr != nil) {
			// An uncertain DB activation or lost advisory session must not leave
			// dispatchable credentials. Resolve only our exact response version.
			cleanup := cleanupExchangeBundle(bundle)
			if _, cleanupErr := s.persistExchangeBundle(cleanupCtx, cleanup, version); cleanupErr != nil {
				resultErr = ErrPersistence
			}
			_ = s.repo.Transact(cleanupCtx, func(st *domain.State) error {
				c, ok := st.Connections[tx.ConnectionID]
				if ok && c.Status == "active" && c.Epoch == bundle.Epoch && c.Subject == bundle.Subject && c.ClientID == bundle.ClientID {
					c.Status = "needs_reauth"
					st.Connections[c.ID] = c
				}
				return nil
			})
		}
		if lockErr != nil {
			result, resultErr = none, ErrPersistence
		}
	}()

	var current domain.Connection
	resultErr = exchangeErr
	if resultErr == nil && (!validSubject(exchanged.Subject) || exchanged.ClientID != s.provider.ClientID() || exchanged.AccessToken == "") {
		resultErr = ErrIdentity
	}
	if resultErr == nil && !exactScopes(exchanged.Scopes) {
		resultErr = ErrScope
	}
	if resultErr == nil {
		resultErr = ctx.Err()
	}
	if resultErr == nil {
		resultErr = s.repo.Transact(cleanupCtx, func(st *domain.State) error {
			c, ok := st.Connections[tx.ConnectionID]
			if !ok || c.OwnerID != ownerID || c.Status != "pending" || c.Epoch != intent.Epoch || c.ClientID != intent.ClientID || !liveSession(st, ownerID, sessionID) {
				return domain.ErrDenied
			}
			if !st.Now.Before(exchanged.Expiry) {
				return ErrIdentity
			}
			current = c
			return nil
		})
	}
	if resultErr == nil && exchanged.RefreshToken == "" {
		resultErr = ErrReauth
	}
	if resultErr != nil {
		bundle = cleanupExchangeBundle(bundle)
	}
	version, err = s.persistExchangeBundle(cleanupCtx, bundle, intentVersion)
	if err != nil {
		return none, ErrPersistence
	}
	persisted = true
	if resultErr != nil {
		if !errors.Is(resultErr, ErrReauth) {
			return none, resultErr
		}
		// An access-only response remains available for revocation, but cannot
		// establish a durable offline connection or dispatch an access lease.
		err = s.repo.Transact(cleanupCtx, func(st *domain.State) error {
			c, ok := st.Connections[tx.ConnectionID]
			if !ok || c.OwnerID != ownerID || c.Status != "pending" || c.Epoch != intent.Epoch || c.ClientID != intent.ClientID || !liveSession(st, ownerID, sessionID) {
				return domain.ErrDenied
			}
			c.Subject, c.Status, c.Scopes = exchanged.Subject, "needs_reauth", append([]string(nil), exchanged.Scopes...)
			st.Connections[c.ID] = c
			current = c
			st.Audits = append(st.Audits, domain.Audit{ID: security.ID(), At: st.Now, ActorType: "user", ActorID: ownerID, SubjectID: ownerID, Action: "connection.oauth.complete", ConnectionID: c.ID, Outcome: "needs_reauth"})
			return nil
		})
		if err != nil {
			return none, err
		}
		return current, ErrReauth
	}
	err = s.repo.Transact(cleanupCtx, func(st *domain.State) error {
		c, ok := st.Connections[tx.ConnectionID]
		if !ok || c.OwnerID != ownerID || c.Status != "pending" || c.Epoch != bundle.Epoch || c.ClientID != bundle.ClientID || !liveSession(st, ownerID, sessionID) || ctx.Err() != nil || !st.Now.Before(bundle.Expiry) {
			return domain.ErrDenied
		}
		c.Subject, c.SecretVersion, c.Scopes, c.Status = bundle.Subject, version, append([]string(nil), bundle.Scopes...), "active"
		st.Connections[c.ID] = c
		current = c
		st.Audits = append(st.Audits, domain.Audit{ID: security.ID(), At: st.Now, ActorType: "user", ActorID: ownerID, SubjectID: ownerID, Action: "connection.oauth.complete", ConnectionID: c.ID, Outcome: "active"})
		return nil
	})
	if err != nil {
		return none, err
	}
	return current, nil
}

// prepareExchange serializes creation of the durable intent with disconnect
// cleanup, then releases the lock before the provider request. A lost session
// cannot dispatch a request whose fence was not durably confirmed.
func (s *Service) prepareExchange(ctx context.Context, tx domain.OAuthTransaction, ownerID, sessionID string) (intent tokens.Bundle, version int64, resultErr error) {
	unlock, err := s.repo.LockConnection(ctx, tx.ConnectionID)
	if err != nil {
		return intent, 0, ErrPersistence
	}
	defer func() {
		if unlock() != nil {
			resultErr = ErrPersistence
		}
	}()
	err = s.repo.Transact(ctx, func(st *domain.State) error {
		c, ok := st.Connections[tx.ConnectionID]
		if !ok || c.OwnerID != ownerID || c.Status != "pending" || c.Epoch != 1 || c.ClientID != s.provider.ClientID() || !liveSession(st, ownerID, sessionID) {
			return domain.ErrDenied
		}
		intent = tokens.Bundle{ConnectionID: c.ID, ClientID: c.ClientID, Epoch: c.Epoch, OperationID: security.ID(), State: tokens.StateRefreshing}
		return nil
	})
	if err != nil {
		return intent, 0, err
	}
	version, err = s.persistExchangeBundle(ctx, intent, 0)
	return intent, version, err
}

func cleanupExchangeBundle(bundle tokens.Bundle) tokens.Bundle {
	bundle.State = tokens.StateCleanup
	if bundle.RefreshToken != "" {
		bundle.AccessToken = ""
	}
	bundle.Expiry = time.Time{}
	return bundle
}

func (s *Service) persistExchangeBundle(ctx context.Context, bundle tokens.Bundle, cas int64) (int64, error) {
	version, err := s.secrets.Put(ctx, tokens.Path(bundle.ConnectionID), bundle, cas)
	if err == nil {
		return version, nil
	}
	// Reconcile only this exact operation at a strictly newer CAS generation.
	observed, observedVersion, readErr := s.secrets.Get(ctx, tokens.Path(bundle.ConnectionID))
	if readErr != nil || observedVersion <= cas || !sameInitialBundle(observed, bundle) {
		return 0, ErrPersistence
	}
	return observedVersion, nil
}

func transactionPath(id string) string { return "oauth-transactions/" + id }
func sameInitialBundle(a, b tokens.Bundle) bool {
	return a.ConnectionID == b.ConnectionID && a.Subject == b.Subject && a.ClientID == b.ClientID && a.Epoch == b.Epoch && a.Generation == b.Generation && a.OperationID == b.OperationID && a.AccessToken == b.AccessToken && a.RefreshToken == b.RefreshToken && a.Expiry.Equal(b.Expiry) && a.State == b.State && slices.Equal(a.Scopes, b.Scopes)
}
func exactScopes(scopes []string) bool {
	return len(scopes) == 2 && domain.HasScope(scopes, domain.DriveScope) && domain.HasScope(scopes, "openid")
}
func validSubject(subject string) bool {
	if len(subject) == 0 || len(subject) > 255 {
		return false
	}
	for i := 0; i < len(subject); i++ {
		if subject[i] < 33 || subject[i] > 126 {
			return false
		}
	}
	return true
}
