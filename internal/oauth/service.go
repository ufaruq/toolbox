// Package oauth establishes owner-bound Google connections. It never authenticates
// a Toolbox owner; callers must supply the existing first-party owner session.
package oauth

import (
	"context"
	"errors"
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

// ExchangeResult contains a verified provider identity. Implementations must verify
// the signature and issuer, audience, expiry, and expected nonce before returning.
// Do not serialize this value into an API response or logs.
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
	exchanged, err := s.provider.Exchange(ctx, code, secret.Verifier, tx.NonceHash)
	if err != nil {
		return none, err
	}
	if !validSubject(exchanged.Subject) || exchanged.ClientID != s.provider.ClientID() || exchanged.AccessToken == "" {
		return none, ErrIdentity
	}
	if !exactScopes(exchanged.Scopes) {
		return none, ErrScope
	}

	// Serialize persistence with refresh/disconnect cleanup, and recheck lifecycle
	// both before the secret write and during activation. No DB transaction spans
	// network I/O; the bounded session advisory lock intentionally spans the write.
	unlock, err := s.repo.LockConnection(ctx, tx.ConnectionID)
	if err != nil {
		return none, ErrPersistence
	}
	defer func() {
		if unlock() != nil {
			result = domain.Connection{}
			resultErr = ErrPersistence
		}
	}()
	var current domain.Connection
	err = s.repo.Transact(ctx, func(st *domain.State) error {
		c, ok := st.Connections[tx.ConnectionID]
		if !ok || c.OwnerID != ownerID || c.Status != "pending" || c.Epoch != 1 || !liveSession(st, ownerID, sessionID) {
			return domain.ErrDenied
		}
		if !st.Now.Before(exchanged.Expiry) {
			return ErrIdentity
		}
		current = c
		return nil
	})
	if err != nil {
		return none, err
	}
	if exchanged.RefreshToken == "" {
		// An access token alone cannot establish a durable offline connection.
		err = s.repo.Transact(ctx, func(st *domain.State) error {
			c, ok := st.Connections[tx.ConnectionID]
			if !ok || c.OwnerID != ownerID || c.Status != "pending" || c.Epoch != current.Epoch {
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
	bundle := tokens.Bundle{ConnectionID: current.ID, Subject: exchanged.Subject, ClientID: s.provider.ClientID(), Epoch: current.Epoch, Generation: 1, OperationID: security.ID(), AccessToken: exchanged.AccessToken, RefreshToken: exchanged.RefreshToken, Expiry: exchanged.Expiry, Scopes: append([]string(nil), exchanged.Scopes...), State: "active"}
	version, err := s.secrets.Put(ctx, tokens.Path(current.ID), bundle, 0)
	if err != nil {
		// A timeout may hide a committed CAS. Accept only this exact operation and
		// complete bundle from the authoritative stable path, never a stale pointer.
		observed, observedVersion, readErr := s.secrets.Get(ctx, tokens.Path(current.ID))
		if readErr != nil || !sameInitialBundle(observed, bundle) {
			return none, ErrPersistence
		}
		version = observedVersion
	}
	err = s.repo.Transact(ctx, func(st *domain.State) error {
		c, ok := st.Connections[tx.ConnectionID]
		if !ok || c.OwnerID != ownerID || c.Status != "pending" || c.Epoch != bundle.Epoch || !liveSession(st, ownerID, sessionID) || !st.Now.Before(bundle.Expiry) {
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

func transactionPath(id string) string { return "oauth-transactions/" + id }
func sameInitialBundle(a, b tokens.Bundle) bool {
	return a.ConnectionID == b.ConnectionID && a.Subject == b.Subject && a.ClientID == b.ClientID && a.Epoch == b.Epoch && a.Generation == b.Generation && a.OperationID == b.OperationID && a.AccessToken == b.AccessToken && a.RefreshToken == b.RefreshToken && a.Expiry.Equal(b.Expiry) && a.State == "active" && exactScopes(a.Scopes)
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
