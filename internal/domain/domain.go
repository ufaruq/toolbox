// Package domain defines persisted, non-secret Toolbox state.
package domain

import (
	"context"
	"errors"
	"time"
)

const Tool = "google_drive.read_document.v1"
const Action = "google_drive.document.read"
const DriveScope = "https://www.googleapis.com/auth/drive.file"
const MaxBytes = 1 << 20

var ErrDenied = errors.New("NOT_AUTHORIZED")

type User struct{ ID, Issuer, Subject, Status string }
type Agent struct{ ID, OwnerID, Name, Status string }
type Credential struct {
	ID, AgentID, Hash, Status string
	ExpiresAt                 time.Time
}
type Session struct {
	ID, UserID, CSRFHash string
	ExpiresAt            time.Time
}

// CallerProfile binds an approved Okta identity and client to one owner agent.
type CallerProfile struct {
	ID, OwnerID, AgentID, Issuer, UserID, ClientID, Label, Status string
	Tools                                                         []string
	ApprovedAt, ExpiresAt                                         time.Time
}

type Connection struct {
	ID, OwnerID, Provider, Subject, ClientID, Status string
	Epoch, SecretVersion                             int64
	Scopes                                           []string
}
type Resource struct {
	ConnectionID, FileID, MIME, Name string
	VerifiedAt                       time.Time
}
type Request struct {
	ID, AgentID, FileID, Tool, Digest, Status, GrantID string
	Version                                            int
	DurationSeconds                                    int64
	RequestedExpiry                                    time.Time
	ExpiresAt                                          time.Time
}
type Grant struct {
	ID, OwnerID, AgentID, ConnectionID, Tool, Action, FileID string
	Epoch                                                    int64
	Version                                                  int
	NotBefore, ExpiresAt                                     time.Time
	RevokedAt                                                *time.Time
}
type OAuthTransaction struct {
	ID, OwnerID, SessionID, StateHash, NonceHash, SecretRef, ConnectionID string
	ExpiresAt                                                             time.Time
	Consumed                                                              bool
}

// OwnerLoginTransaction binds a one-use OIDC login to its originating browser.
// IssuedSessionID preserves the revocation relationship through response delivery.
// The PKCE verifier belongs in the secret store referenced by SecretRef.
type OwnerLoginTransaction struct {
	ID, StateHash, BrowserHash, NonceHash, SecretRef string
	Issuer, ClientID, RedirectURI                    string
	PreviousSessionID, IssuedSessionID, Status       string
	ExpiresAt                                        time.Time
}
type Audit struct {
	AgentID, CallerProfileID, ClientID                                                              string
	ID                                                                                              string
	At                                                                                              time.Time
	ActorType, ActorID, SubjectID, Action, GrantID, ConnectionID, ResourceID, Outcome, InvocationID string
	Bytes                                                                                           int
}
type Cleanup struct {
	ID, ConnectionID, OwnerID, Status string
	Epoch                             int64
}

// State is a transaction snapshot. Never retain its maps or pointers after Transact.
// Provider tokens, OAuth codes and PKCE verifiers never belong in this structure.
type State struct {
	CallerProfiles map[string]CallerProfile
	Now            time.Time
	Users          map[string]User
	Agents         map[string]Agent
	Credentials    map[string]Credential
	Sessions       map[string]Session
	Connections    map[string]Connection
	Resources      map[string]Resource
	Requests       map[string]Request
	Grants         map[string]Grant
	OAuth          map[string]OAuthTransaction
	OwnerLogins    map[string]OwnerLoginTransaction
	Audits         []Audit
	Cleanup        map[string]Cleanup
}

func NewState() *State {
	return &State{CallerProfiles: map[string]CallerProfile{}, Users: map[string]User{}, Agents: map[string]Agent{}, Credentials: map[string]Credential{}, Sessions: map[string]Session{}, Connections: map[string]Connection{}, Resources: map[string]Resource{}, Requests: map[string]Request{}, Grants: map[string]Grant{}, OAuth: map[string]OAuthTransaction{}, OwnerLogins: map[string]OwnerLoginTransaction{}, Cleanup: map[string]Cleanup{}}
}
func ResourceKey(connectionID, fileID string) string { return connectionID + ":" + fileID }
func HasScope(scopes []string, scope string) bool {
	for _, v := range scopes {
		if v == scope {
			return true
		}
	}
	return false
}

// Repository provides a serializable primary-database snapshot and database time.
// Callbacks must be short, perform no network I/O, and never re-enter Transact.
// LockConnection obtains a bounded, dedicated-session lock across replicas.
type Repository interface {
	Transact(context.Context, func(*State) error) error
	LockConnection(context.Context, string) (func() error, error)
	Ping(context.Context) error
}
