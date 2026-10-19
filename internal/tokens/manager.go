package tokens

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ufaruq/toolbox/internal/domain"
)

const StateActive = "active"
const StateRefreshing = "refreshing"
const StateTombstoned = "tombstoned"

// StateCleanup contains a resolved provider response that must never be used
// for dispatch. Its original epoch and operation bind it to the refresh intent.
const StateCleanup = "cleanup"

type RefreshResult struct {
	AccessToken, RefreshToken string
	Expiry                    time.Time
	Scopes                    []string
}

// Provider must use fixed OAuth endpoints, bounded requests and no refresh
// retries: a timeout may already have rotated the refresh token at the provider.
// Refresh must return known credentials from a successful response even when
// validation rejects it. A non-nil error makes that result cleanup-only; it can
// never authorize an access lease. An unknown response returns an empty result.
type Provider interface {
	Refresh(context.Context, string) (RefreshResult, error)
	Revoke(context.Context, string) error
}

type Manager struct {
	Repository domain.Repository
	Secrets    SecretStore
	Provider   Provider
	Now        func() time.Time
	mu         sync.Mutex
	gates      map[string]*gate
}
type gate struct {
	ch   chan struct{}
	refs int
}

func (m *Manager) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now().UTC()
}

// localLock coalesces work without sharing a caller's authorization decision or
// retaining access tokens. Waiters still acquire the cross-replica DB lock and
// reread the authoritative secret generation.
func (m *Manager) localLock(ctx context.Context, id string) (func(), error) {
	m.mu.Lock()
	if m.gates == nil {
		m.gates = map[string]*gate{}
	}
	g := m.gates[id]
	if g == nil {
		g = &gate{ch: make(chan struct{}, 1)}
		m.gates[id] = g
	}
	g.refs++
	m.mu.Unlock()
	releaseRef := func() {
		m.mu.Lock()
		g.refs--
		if g.refs == 0 {
			delete(m.gates, id)
		}
		m.mu.Unlock()
	}
	select {
	case g.ch <- struct{}{}:
		return func() { <-g.ch; releaseRef() }, nil
	case <-ctx.Done():
		releaseRef()
		return nil, ctx.Err()
	}
}

// Lease carries the immutable provider credential generation used by a dispatch.
// It is internal credential material and must never be serialized to an agent.
type Lease struct {
	Token      string
	Generation int64
}

func (m *Manager) Access(ctx context.Context, id string, authorize func(context.Context) error) (string, error) {
	lease, err := m.AccessLease(ctx, id, authorize)
	return lease.Token, err
}
func (m *Manager) AccessLease(ctx context.Context, id string, authorize func(context.Context) error) (Lease, error) {
	return m.accessLease(ctx, id, authorize, false, 0)
}

// ForceRefreshAfter is reserved for one trusted provider-401 recovery. A queued
// caller reuses a newer valid generation instead of rotating it a second time.
func (m *Manager) ForceRefreshAfter(ctx context.Context, id string, rejectedGeneration int64, authorize func(context.Context) error) (Lease, error) {
	if rejectedGeneration < 1 {
		return Lease{}, domain.ErrDenied
	}
	return m.accessLease(ctx, id, authorize, true, rejectedGeneration)
}

// ForceRefresh is a compatibility helper. Production 401 recovery should use
// ForceRefreshAfter so concurrent responses from the same generation coalesce.
func (m *Manager) ForceRefresh(ctx context.Context, id string, authorize func(context.Context) error) (string, error) {
	lease, err := m.accessLease(ctx, id, authorize, true, -1)
	return lease.Token, err
}
func (m *Manager) accessLease(ctx context.Context, id string, authorize func(context.Context) error, force bool, rejectedGeneration int64) (lease Lease, err error) {
	if m.Repository == nil || m.Secrets == nil || authorize == nil || !validPath(id) || strings.Contains(id, "/") {
		return Lease{}, domain.ErrDenied
	}
	if err = authorize(ctx); err != nil {
		return Lease{}, err
	}
	release, e := m.localLock(ctx, id)
	if e != nil {
		return Lease{}, ErrUnavailable
	}
	defer release()
	unlock, e := m.Repository.LockConnection(ctx, id)
	if e != nil {
		return Lease{}, ErrUnavailable
	}
	defer func() {
		if unlock() != nil {
			lease = Lease{}
			err = ErrUnavailable
		}
	}()
	if e = authorize(ctx); e != nil {
		return Lease{}, e
	}
	conn, e := m.connection(ctx, id)
	if e != nil {
		return Lease{}, e
	}
	bundle, version, e := m.Secrets.Get(ctx, Path(id))
	if e != nil {
		return Lease{}, ErrUnavailable
	}
	if !matches(bundle, conn) {
		m.markReauth(ctx, conn)
		return Lease{}, ErrReauth
	}
	if (!force || rejectedGeneration > 0 && bundle.Generation > rejectedGeneration) && bundle.AccessToken != "" && bundle.Expiry.After(m.now().Add(time.Minute)) {
		if e = m.repairVersion(ctx, conn, version); e != nil {
			return Lease{}, e
		}
		if e = authorize(ctx); e != nil {
			return Lease{}, e
		}
		if _, e = m.sameConnection(ctx, conn); e != nil {
			return Lease{}, e
		}
		return Lease{Token: bundle.AccessToken, Generation: bundle.Generation}, nil
	}
	if m.Provider == nil || bundle.RefreshToken == "" {
		m.markReauth(ctx, conn)
		return Lease{}, ErrReauth
	}
	// Recheck immediately before the refresh request as well as before secret read.
	if e = authorize(ctx); e != nil {
		return Lease{}, e
	}
	if _, e = m.sameConnection(ctx, conn); e != nil {
		return Lease{}, e
	}
	op, e := operationID()
	if e != nil {
		return Lease{}, ErrUnavailable
	}
	// Persist an intent before the non-idempotent provider operation. A crash
	// leaves a durable fence: another worker must not replay a possibly rotated
	// refresh token. This deliberately favors reconnect over unsafe recovery.
	intent := bundle
	intent.State = StateRefreshing
	intent.OperationID = op
	intentVersion, intentErr := m.Secrets.Put(ctx, Path(id), intent, version)
	if intentErr != nil {
		recovered, recoveredVersion, readErr := m.Secrets.Get(ctx, Path(id))
		if readErr != nil || recovered.State != StateRefreshing || recovered.OperationID != op || recovered.ConnectionID != id || recovered.Epoch != conn.Epoch || recoveredVersion <= version {
			return Lease{}, ErrUnavailable
		}
		intentVersion = recoveredVersion
	}
	version = intentVersion
	if e = authorize(ctx); e == nil {
		_, e = m.sameConnection(ctx, conn)
	}
	if e != nil {
		// No provider request was made. Restore the known old generation only at
		// this intent's CAS version. A failed rollback remains safely fenced.
		restoreCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		_, restoreErr := m.Secrets.Put(restoreCtx, Path(id), bundle, version)
		cancel()
		if restoreErr != nil {
			m.markReauth(ctx, conn)
		}
		return Lease{}, e
	}
	result, refreshErr := m.Provider.Refresh(ctx, bundle.RefreshToken)
	authorizationAfterRefresh := authorize(ctx)
	if refreshErr != nil && !errors.Is(refreshErr, ErrInvalidGrant) && result.AccessToken == "" && result.RefreshToken == "" {
		m.markReauth(ctx, conn)
		return Lease{}, ErrReauth
	}
	// Preserve known rotated credentials even when activation is denied. A
	// definitive invalid_grant also resolves the intent, retaining the old
	// credential for cleanup rather than assuming its revocation retired every
	// generation. Unknown empty responses must keep their uncertainty fence.
	liveCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	_, activationErr := m.sameConnection(liveCtx, conn)
	next := bundle
	next.Scopes = append([]string(nil), bundle.Scopes...)
	next.AccessToken = result.AccessToken
	next.Expiry = result.Expiry
	next.Generation++
	next.OperationID = op
	if result.RefreshToken != "" {
		next.RefreshToken = result.RefreshToken
	} else if refreshErr != nil && result.AccessToken != "" {
		// A rejected response can have an absent or malformed refresh credential.
		// Revoke its known new access token rather than claiming cleanup solely
		// from an old refresh token that the provider may already have rotated.
		next.RefreshToken = ""
	}
	if len(result.Scopes) > 0 {
		next.Scopes = append([]string(nil), result.Scopes...)
	}
	validResponse := refreshErr == nil && result.AccessToken != "" && result.Expiry.After(m.now()) && validRefreshScopes(next.Scopes, bundle.Scopes, conn.Scopes)
	if activationErr != nil || !validResponse {
		next.State = StateCleanup
		// Prefer the known refresh credential for cleanup. Otherwise retain the
		// known access token only in this non-dispatchable state for revocation.
		if next.RefreshToken != "" {
			next.AccessToken = ""
		}
		next.Expiry = time.Time{}
	}
	newVersion, putErr := m.Secrets.Put(liveCtx, Path(id), next, version)
	if putErr != nil {
		// A timeout can conceal a successful KV commit. Only this exact operation is
		// a proven durable success. A different winner cannot prove which rotated
		// provider credential remains valid, so do not overwrite or refresh again.
		recovered, recoveredVersion, readErr := m.Secrets.Get(liveCtx, Path(id))
		if readErr != nil || recovered.ConnectionID != next.ConnectionID || recovered.Subject != next.Subject || recovered.ClientID != next.ClientID || recovered.Epoch != next.Epoch || recovered.State != next.State || recovered.OperationID != op || recovered.Generation != next.Generation || recovered.AccessToken != next.AccessToken || recovered.RefreshToken != next.RefreshToken || !recovered.Expiry.Equal(next.Expiry) || !slices.Equal(recovered.Scopes, next.Scopes) || recoveredVersion <= version {
			m.markReauth(ctx, conn)
			return Lease{}, ErrReauth
		}
		next = recovered
		newVersion = recoveredVersion
	}
	if next.State == StateCleanup {
		m.markReauth(liveCtx, conn)
		if activationErr != nil {
			return Lease{}, activationErr
		}
		return Lease{}, ErrReauth
	}
	if e = m.repairVersion(ctx, conn, newVersion); e != nil {
		return Lease{}, e
	}
	if authorizationAfterRefresh != nil {
		return Lease{}, authorizationAfterRefresh
	}
	if e = authorize(ctx); e != nil {
		return Lease{}, e
	}
	if _, e = m.sameConnection(ctx, conn); e != nil {
		return Lease{}, e
	}
	return Lease{Token: next.AccessToken, Generation: next.Generation}, nil
}

func validRefreshScopes(scopes, storedScopes, connectionScopes []string) bool {
	// Email identity is opt-in on both stored records. Its exact contract must
	// survive refresh, including when the provider omits scopes in its response.
	if domain.HasScope(storedScopes, "email") || domain.HasScope(connectionScopes, "email") {
		return emailIdentityScopes(storedScopes) && emailIdentityScopes(connectionScopes) && emailIdentityScopes(scopes)
	}
	// Legacy credentials can omit openid. Retain that compatibility without
	// allowing refresh to introduce email or broader Drive authority.
	return len(scopes) == 1 && scopes[0] == domain.DriveScope || len(scopes) == 2 && domain.HasScope(scopes, domain.DriveScope) && domain.HasScope(scopes, "openid")
}

func emailIdentityScopes(scopes []string) bool {
	return len(scopes) == 3 && domain.HasScope(scopes, "openid") && domain.HasScope(scopes, "email") && domain.HasScope(scopes, domain.DriveScope)
}

func matches(b Bundle, c domain.Connection) bool {
	if (domain.HasScope(b.Scopes, "email") || domain.HasScope(c.Scopes, "email")) && !validRefreshScopes(b.Scopes, b.Scopes, c.Scopes) {
		return false
	}
	return b.ConnectionID == c.ID && b.Subject == c.Subject && b.ClientID == c.ClientID && b.Epoch == c.Epoch && b.Epoch > 0 && b.Generation > 0 && b.OperationID != "" && b.State == StateActive && domain.HasScope(b.Scopes, domain.DriveScope)
}
func (m *Manager) connection(ctx context.Context, id string) (domain.Connection, error) {
	var c domain.Connection
	e := m.Repository.Transact(ctx, func(s *domain.State) error {
		var ok bool
		c, ok = s.Connections[id]
		if !ok || c.Status != "active" || c.Provider != "google_drive" || c.Subject == "" || c.ClientID == "" || !domain.HasScope(c.Scopes, domain.DriveScope) {
			return domain.ErrDenied
		}
		return nil
	})
	return c, e
}
func (m *Manager) sameConnection(ctx context.Context, want domain.Connection) (domain.Connection, error) {
	c, e := m.connection(ctx, want.ID)
	if e != nil {
		return c, e
	}
	if c.Epoch != want.Epoch || c.Subject != want.Subject || c.ClientID != want.ClientID {
		return c, domain.ErrDenied
	}
	return c, nil
}
func (m *Manager) repairVersion(ctx context.Context, want domain.Connection, version int64) error {
	return m.Repository.Transact(ctx, func(s *domain.State) error {
		c, ok := s.Connections[want.ID]
		if !ok || c.Status != "active" || c.Epoch != want.Epoch || c.Subject != want.Subject || c.ClientID != want.ClientID {
			return domain.ErrDenied
		}
		c.SecretVersion = version
		s.Connections[c.ID] = c
		return nil
	})
}
func (m *Manager) markReauth(ctx context.Context, want domain.Connection) {
	// The request may have timed out after a provider-side rotation. Use a short
	// detached context to durably block the connection. A DB failure still fails
	// this invocation closed and must be surfaced by operational dependency alerts.
	c, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	_ = m.Repository.Transact(c, func(s *domain.State) error {
		v, ok := s.Connections[want.ID]
		if ok && v.Status == "active" && v.Epoch == want.Epoch {
			v.Status = "needs_reauth"
			s.Connections[v.ID] = v
		}
		return nil
	})
}
func operationID() (string, error) {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		return "", e
	}
	return hex.EncodeToString(b[:]), nil
}

// Tombstone is an idempotent cleanup step after the DB has already disabled the
// connection and advanced its epoch. Retained KV versions need a separately
// permissioned destroy job. A revoke failure leaves the tombstoned credential
// available only to this cleanup path for retry.
func (m *Manager) Tombstone(ctx context.Context, id string, epoch int64) (err error) {
	if m.Repository == nil || m.Secrets == nil {
		return ErrUnavailable
	}
	release, e := m.localLock(ctx, id)
	if e != nil {
		return ErrUnavailable
	}
	defer release()
	unlock, e := m.Repository.LockConnection(ctx, id)
	if e != nil {
		return ErrUnavailable
	}
	defer func() {
		if unlock() != nil {
			err = ErrUnavailable
		}
	}()
	e = m.Repository.Transact(ctx, func(s *domain.State) error {
		c, ok := s.Connections[id]
		if !ok || c.Status == "active" || c.Epoch != epoch {
			return domain.ErrDenied
		}
		return nil
	})
	if e != nil {
		return e
	}
	b, v, e := m.Secrets.Get(ctx, Path(id))
	if e == ErrNotFound {
		return nil
	}
	if e != nil {
		return ErrUnavailable
	}
	if b.ConnectionID != id || b.Epoch > epoch {
		return domain.ErrDenied
	}
	// An in-flight/uncertain refresh may still return a rotated credential.
	// Do not overwrite its intent or claim that revoking the old token completes
	// cleanup. A late known response can still resolve this exact CAS version.
	if b.State == StateRefreshing {
		return ErrRefreshUncertain
	}
	if b.State != StateTombstoned || b.Epoch != epoch {
		b.State = StateTombstoned
		b.Epoch = epoch
		b.Generation++
		b.OperationID, e = operationID()
		if e != nil {
			return ErrUnavailable
		}
		v, e = m.Secrets.Put(ctx, Path(id), b, v)
		if e != nil {
			return ErrUnavailable
		}
	}
	token := b.RefreshToken
	if token == "" {
		token = b.AccessToken
	}
	if token == "" {
		return nil
	}
	if m.Provider == nil || m.Provider.Revoke(ctx, token) != nil {
		return ErrUnavailable
	}
	b.AccessToken = ""
	b.RefreshToken = ""
	b.Expiry = time.Time{}
	b.Generation++
	b.OperationID, e = operationID()
	if e != nil {
		return ErrUnavailable
	}
	_, e = m.Secrets.Put(ctx, Path(id), b, v)
	if e != nil {
		return ErrUnavailable
	}
	return nil
}
