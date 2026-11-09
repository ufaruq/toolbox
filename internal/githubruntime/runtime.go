// Package githubruntime executes reviewed GitHub operations in disposable MCP gateways.
package githubruntime

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/ufaruq/toolbox/internal/githubapp"
	githubpolicy "github.com/ufaruq/toolbox/internal/servicepolicy/github"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var ErrUnavailable = errors.New("GITHUB_RUNTIME_UNAVAILABLE")
var ErrOutcomeUnknown = errors.New("GITHUB_RUNTIME_WRITE_OUTCOME_UNKNOWN")
var ErrDenied = errors.New("GITHUB_RUNTIME_DENIED")

type Config struct {
	AppID          string
	PrivateKey     []byte
	OwnerID        string
	InstallationID int64
	StateDirectory string
}
type Repository struct {
	InstallationID, RepositoryID int64
	Owner, Name                  string
}
type Runtime struct {
	config Config
	issuer appIssuer
	launch launcher
}
type launcher func(context.Context, string, string) (session, error)
type session interface {
	Call(context.Context, githubpolicy.Call, func(context.Context) error) (json.RawMessage, error)
	Close() error
}

func New(c Config) (*Runtime, error) {
	if c.OwnerID == "" || c.InstallationID <= 0 || c.StateDirectory == "" {
		return nil, ErrDenied
	}
	if validateStateDirectory(c.StateDirectory) != nil {
		return nil, ErrDenied
	}
	issuer, e := githubapp.New(c.AppID, c.PrivateKey)
	if e != nil {
		return nil, ErrDenied
	}
	c.PrivateKey = nil
	return &Runtime{config: c, issuer: issuer, launch: dockerLauncher(c.StateDirectory)}, nil
}
func (r *Runtime) Repositories(ctx context.Context, ownerID string) ([]Repository, error) {
	if ownerID != r.config.OwnerID {
		return nil, ErrDenied
	}
	repos, e := r.issuer.Repositories(ctx, r.config.InstallationID)
	if e != nil {
		return nil, ErrUnavailable
	}
	out := make([]Repository, 0, len(repos))
	for _, repo := range repos {
		out = append(out, Repository{r.config.InstallationID, repo.ID, repo.Owner.Login, repo.Name})
	}
	return out, nil
}
func (r *Runtime) Close() error { return nil }
func (r *Runtime) Execute(ctx context.Context, installationID int64, g githubpolicy.Grant, action string, args json.RawMessage, check func(context.Context) error) (result json.RawMessage, resultErr error) {
	dispatched := false
	cleanupFailure := func(e error) {
		if e != nil {
			result = nil
			resultErr = ErrUnavailable
			if dispatched && action != "files.read" && action != "prs.read" && action != "issues.read" {
				resultErr = ErrOutcomeUnknown
			}
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if validateStateDirectory(r.config.StateDirectory) != nil {
		return nil, ErrDenied
	}
	if check == nil || installationID != r.config.InstallationID || g.OwnerID != r.config.OwnerID || githubpolicy.ValidateGrant(g) != nil {
		return nil, ErrDenied
	}
	call, e := githubpolicy.Build(g, action, args, time.Now())
	if e != nil {
		return nil, ErrDenied
	}
	if check(ctx) != nil {
		return nil, ErrDenied
	}
	permissions, e := githubpolicy.Permissions(action)
	if e != nil {
		return nil, ErrDenied
	}
	// Preflight has a separate read credential so mutation credentials retain the
	// exact policy permission set, including merge's contents-only permission.
	prePermissions := map[string]string{"metadata": "read"}
	if action == "files.read" || action == "files.update" || action == "files.write" {
		prePermissions["contents"] = "read"
	}
	if strings.HasPrefix(action, "prs.") {
		prePermissions["pull_requests"] = "read"
	}
	pre, e := r.issuer.Issue(ctx, installationID, g.RepositoryID, prePermissions)
	if e != nil {
		return nil, ErrUnavailable
	}
	defer func() { cleanupFailure(r.revoke(ctx, pre.Token)) }()
	call, e = r.preflight(ctx, pre.Token, g, action, call)
	if e != nil {
		return nil, ErrDenied
	}
	if check(ctx) != nil {
		return nil, ErrDenied
	}
	credential, e := r.issuer.Issue(ctx, installationID, g.RepositoryID, permissions)
	if e != nil {
		return nil, ErrUnavailable
	}
	defer func() { cleanupFailure(r.revoke(ctx, credential.Token)) }()
	s, e := r.launch(ctx, credential.Token, call.Tool)
	if e != nil {
		return nil, ErrUnavailable
	}
	defer func() { cleanupFailure(s.Close()) }()
	if check(ctx) != nil || r.identity(ctx, pre.Token, g) != nil {
		return nil, ErrDenied
	}
	if check(ctx) != nil {
		return nil, ErrDenied
	}
	finalCheck := func(ctx context.Context) error {
		if e := check(ctx); e != nil {
			return e
		}
		dispatched = true
		return nil
	}
	raw, e := s.Call(ctx, call, finalCheck)
	failure := func(err error) error {
		if dispatched && action != "files.read" && action != "prs.read" && action != "issues.read" {
			return ErrOutcomeUnknown
		}
		return err
	}
	if e != nil {
		return nil, failure(ErrUnavailable)
	}
	if check(ctx) != nil || ctx.Err() != nil || r.identity(ctx, pre.Token, g) != nil {
		return nil, failure(ErrDenied)
	}
	out, e := githubpolicy.ProjectResultForRepository(action, raw, g.Owner, g.Repository)
	if e != nil || strings.Contains(string(out), credential.Token) || strings.Contains(string(out), pre.Token) {
		return nil, failure(ErrUnavailable)
	}
	if check(ctx) != nil || ctx.Err() != nil {
		return nil, failure(ErrDenied)
	}
	return out, nil
}
func (r *Runtime) revoke(ctx context.Context, token string) error {
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	return r.issuer.Revoke(cleanup, token)
}
func (r *Runtime) identity(ctx context.Context, token string, g githubpolicy.Grant) error {
	var repo githubapp.Repository
	if r.issuer.GetRepositoryMetadata(ctx, token, g.Owner, g.Repository, "", &repo) != nil || repo.ID != g.RepositoryID || repo.Name != g.Repository || repo.Owner.Login != g.Owner {
		return ErrDenied
	}
	return nil
}
func (r *Runtime) preflight(ctx context.Context, token string, g githubpolicy.Grant, action string, call githubpolicy.Call) (githubpolicy.Call, error) {
	if r.identity(ctx, token, g) != nil {
		return call, ErrDenied
	}
	var args map[string]json.RawMessage
	json.Unmarshal(call.Arguments, &args)
	if _, ok := args["pullNumber"]; ok {
		var n int64
		json.Unmarshal(args["pullNumber"], &n)
		var pr struct {
			Head, Base struct {
				Ref, SHA string
				Repo     struct{ ID int64 }
			}
		}
		if r.issuer.GetRepositoryMetadata(ctx, token, g.Owner, g.Repository, "/pulls/"+string(args["pullNumber"]), &pr) != nil || pr.Head.Repo.ID != g.RepositoryID || pr.Base.Repo.ID != g.RepositoryID || githubpolicy.ValidatePullRequest(g, n, pr.Head.Ref, pr.Base.Ref, pr.Head.SHA) != nil {
			return call, ErrDenied
		}
	}
	if action != "files.read" && action != "files.update" && action != "files.write" {
		return call, nil
	}
	var branch, path string
	json.Unmarshal(args["branch"], &branch)
	if action == "files.read" {
		json.Unmarshal(args["ref"], &branch)
		branch = strings.TrimPrefix(branch, "refs/heads/")
	}
	json.Unmarshal(args["path"], &path)
	var ref struct {
		Ref    string
		Object struct {
			SHA  string
			Type string
		}
	}
	if r.issuer.GetRepositoryMetadata(ctx, token, g.Owner, g.Repository, "/git/ref/heads/"+url.PathEscape(branch), &ref) != nil || !metadataSHA.MatchString(ref.Object.SHA) || ref.Object.Type != "commit" || ref.Ref != "refs/heads/"+branch {
		return call, ErrDenied
	}
	var commit struct{ Tree struct{ SHA string } }
	if r.issuer.GetRepositoryMetadata(ctx, token, g.Owner, g.Repository, "/git/commits/"+ref.Object.SHA, &commit) != nil || !metadataSHA.MatchString(commit.Tree.SHA) {
		return call, ErrDenied
	}
	if action == "files.write" {
		var files []struct{ Path string }
		if json.Unmarshal(args["files"], &files) != nil || len(files) == 0 {
			return call, ErrDenied
		}
		cache := map[string]gitTree{}
		for _, file := range files {
			if r.checkWritePath(ctx, token, g, commit.Tree.SHA, file.Path, cache) != nil {
				return call, ErrDenied
			}
		}
		return call, nil
	}
	tree := commit.Tree.SHA
	parts := strings.Split(path, "/")
	for index, part := range parts {
		var result struct {
			Truncated bool
			Tree      []struct{ Path, Mode, Type, SHA string }
		}
		if r.issuer.GetRepositoryMetadata(ctx, token, g.Owner, g.Repository, "/git/trees/"+tree, &result) != nil || result.Truncated {
			return call, ErrDenied
		}
		found := false
		for _, entry := range result.Tree {
			if entry.Path != part {
				continue
			}
			found = true
			if index < len(parts)-1 {
				if entry.Mode != "040000" || entry.Type != "tree" {
					return call, ErrDenied
				}
				if !metadataSHA.MatchString(entry.SHA) {
					return call, ErrDenied
				}
				tree = entry.SHA
			} else {
				if (entry.Mode != "100644" && entry.Mode != "100755") || entry.Type != "blob" {
					return call, ErrDenied
				}
				if action == "files.update" {
					var expected string
					json.Unmarshal(args["sha"], &expected)
					if entry.SHA != expected {
						return call, ErrDenied
					}
				}
			}
		}
		if !found {
			return call, ErrDenied
		}
	}
	if action == "files.read" {
		return githubpolicy.PinRead(call, ref.Object.SHA)
	}
	return call, nil
}

type appIssuer interface {
	Issue(context.Context, int64, int64, map[string]string) (githubapp.Credential, error)
	Revoke(context.Context, string) error
	Repositories(context.Context, int64) ([]githubapp.Repository, error)
	GetRepositoryMetadata(context.Context, string, string, string, string, any) error
}

var metadataSHA = regexp.MustCompile(`^[0-9a-f]{40}$`)

type gitTree struct {
	Truncated bool
	Tree      []struct{ Path, Mode, Type, SHA string }
}

func (r *Runtime) checkWritePath(ctx context.Context, token string, g githubpolicy.Grant, tree, path string, cache map[string]gitTree) error {
	parts := strings.Split(path, "/")
	for index, part := range parts {
		result, ok := cache[tree]
		if !ok {
			if r.issuer.GetRepositoryMetadata(ctx, token, g.Owner, g.Repository, "/git/trees/"+tree, &result) != nil || result.Truncated {
				return ErrDenied
			}
			cache[tree] = result
		}
		found := false
		for _, entry := range result.Tree {
			if entry.Path != part {
				continue
			}
			found = true
			if index == len(parts)-1 {
				if entry.Type != "blob" || (entry.Mode != "100644" && entry.Mode != "100755") {
					return ErrDenied
				}
			} else {
				if entry.Type != "tree" || entry.Mode != "040000" || !metadataSHA.MatchString(entry.SHA) {
					return ErrDenied
				}
				tree = entry.SHA
			}
			break
		}
		if !found {
			return nil
		}
	}
	return nil
}
