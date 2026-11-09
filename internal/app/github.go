package app

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/ufaruq/toolbox/internal/domain"
	"github.com/ufaruq/toolbox/internal/githubruntime"
	"github.com/ufaruq/toolbox/internal/server"
)

// GitHub adapts the isolated runtime to the application's authorized provider
// boundary. It never creates grants or accepts an agent-selected installation.
type GitHub struct{ Runtime *githubruntime.Runtime }

func (g *GitHub) Repositories(ctx context.Context, owner string) ([]server.GitHubRepository, error) {
	repos, e := g.Runtime.Repositories(ctx, owner)
	if e != nil {
		return nil, e
	}
	out := make([]server.GitHubRepository, 0, len(repos))
	for _, r := range repos {
		out = append(out, server.GitHubRepository{InstallationID: r.InstallationID, RepositoryID: r.RepositoryID, Owner: r.Owner, Name: r.Name})
	}
	return out, nil
}
func (g *GitHub) Execute(ctx context.Context, c domain.GitHubConnection, grant domain.GitHubGrant, action string, args json.RawMessage, check func(context.Context) error) (any, error) {
	result, e := g.Runtime.Execute(ctx, c.InstallationID, server.GitHubPolicyGrant(grant, c), action, args, check)
	if errors.Is(e, githubruntime.ErrOutcomeUnknown) {
		return nil, server.ErrGitHubOutcomeUnknown
	}
	if errors.Is(e, githubruntime.ErrDenied) {
		return nil, domain.ErrDenied
	}
	return result, e
}
