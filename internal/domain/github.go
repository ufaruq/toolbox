package domain

import "time"

const GitHubTool = "github.operation.v1"

// GitHubScope is independently reviewed authorization, not installation access.
type GitHubScope struct {
	Actions, Branches, BaseBranches, Paths []string
	PullRequests                           []int64
	ExpectedHead                           string
	AllowUnconditionalWrites               bool
}

// GitHubConnection binds one installed repository to one Toolbox owner. Secrets
// and provider tokens never belong in these persisted records.
type GitHubConnection struct {
	ID, OwnerID, RepositoryOwner, RepositoryName, Status string
	InstallationID, RepositoryID, Epoch                  int64
}
type GitHubRequest struct {
	ID, OwnerID, AgentID, ConnectionID, Status, Digest, GrantID string
	RepositoryID, Epoch                                         int64
	Scope                                                       GitHubScope
	ExpiresAt, ReviewExpiresAt                                  time.Time
}
type GitHubGrant struct {
	ID, OwnerID, AgentID, ConnectionID string
	RepositoryID, Epoch                int64
	Scope                              GitHubScope
	NotBefore, ExpiresAt               time.Time
	RevokedAt                          *time.Time
}
