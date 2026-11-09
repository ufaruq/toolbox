// Package github constructs reviewed calls from trusted application grants.
// Call construction alone is not authorization: the application must verify the
// authenticated principal, current connection epoch and repository identity.
package github

import (
	"encoding/json"
	"errors"
	"path"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ufaruq/toolbox/internal/strict"
)

var ErrDenied = errors.New("GITHUB_OPERATION_NOT_AUTHORIZED")
var locator = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$`)

type Grant struct {
	OwnerID, AgentID, ConnectionID string
	RepositoryID, Epoch            int64
	Owner, Repository              string
	Actions, Branches, Paths       []string
	BaseBranches                   []string
	PullRequests                   []int64
	ExpectedHead                   string
	AllowUnconditionalWrites       bool
	ExpiresAt                      time.Time
	Revoked                        bool
}
type Call struct {
	Tool      string
	Arguments json.RawMessage
}

func contains(values []string, v string) bool {
	for _, x := range values {
		if x == v {
			return true
		}
	}
	return false
}
func branch(v string) bool {
	if !utf8.ValidString(v) || v == "" || len(v) > 200 || v == "@" || strings.HasPrefix(v, "refs/") || strings.HasPrefix(v, "/") || strings.HasSuffix(v, "/") || strings.Contains(v, "..") || strings.Contains(v, "@{") || strings.ContainsAny(v, " ~^:?*[\\") {
		return false
	}
	for _, c := range v {
		if c < 33 || c == 127 {
			return false
		}
	}
	for _, p := range strings.Split(v, "/") {
		if p == "" || strings.HasPrefix(p, ".") || strings.HasSuffix(p, ".") || strings.HasSuffix(p, ".lock") {
			return false
		}
	}
	return true
}
func allowedPath(g Grant, v string) bool {
	if v == "" || len(v) > 1024 || !utf8.ValidString(v) || strings.HasPrefix(v, "/") || strings.Contains(v, "\\") || strings.Contains(v, "%") || path.Clean(v) != v {
		return false
	}
	for _, r := range v {
		if r < 32 || r == 127 {
			return false
		}
	}
	for _, part := range strings.Split(v, "/") {
		if part == "." || part == ".." || strings.EqualFold(part, ".git") {
			return false
		}
	}
	// Workflow changes need a separately reviewed capability.
	if strings.EqualFold(v, ".github/workflows") || strings.HasPrefix(strings.ToLower(v), ".github/workflows/") {
		return false
	}
	for _, p := range g.Paths {
		if p == v || strings.HasSuffix(p, "/") && strings.HasPrefix(v, p) {
			return true
		}
	}
	return false
}

// allowedTreeWrite requires authority over every subtree the blob entry could
// replace and every ancestor blob which Git tree construction could replace.
// Preflight cannot safely substitute for this authority: upstream reads a newer
// head internally and offers no caller head precondition.
func allowedTreeWrite(g Grant, v string) bool {
	if !allowedPath(g, v) || strings.EqualFold(v, ".github") {
		return false
	}
	covered := false
	for _, prefix := range g.Paths {
		if strings.HasSuffix(prefix, "/") && strings.HasPrefix(v, prefix) && len(v) > len(prefix) {
			covered = true
			break
		}
	}
	if !covered {
		return false
	}
	for ancestor := path.Dir(v); ancestor != "."; ancestor = path.Dir(ancestor) {
		if !allowedPath(g, ancestor) {
			return false
		}
	}
	return true
}

func build(tool string, args map[string]any) (Call, error) {
	b, e := json.Marshal(args)
	if e != nil || len(b) > 16<<10 {
		return Call{}, ErrDenied
	}
	return Call{Tool: tool, Arguments: b}, nil
}

// Build constructs fixed upstream calls. Live identity, repository and PR checks
// remain mandatory at dispatch; see ValidatePullRequest and the operation contract.
func Build(g Grant, action string, raw json.RawMessage, now time.Time) (Call, error) {
	if g.OwnerID == "" || g.AgentID == "" || g.ConnectionID == "" || g.RepositoryID <= 0 || g.Epoch <= 0 || !locator.MatchString(g.Owner) || !locator.MatchString(g.Repository) || g.Revoked || !now.Before(g.ExpiresAt) || !contains(g.Actions, action) || len(raw) > 16<<10 || !utf8.Valid(raw) {
		return Call{}, ErrDenied
	}
	args := map[string]any{"owner": g.Owner, "repo": g.Repository}
	switch action {
	case "files.read":
		var in struct {
			Branch string `json:"branch"`
			Path   string `json:"path"`
		}
		if strict.Decode(raw, &in) != nil || !branch(in.Branch) || !contains(g.Branches, in.Branch) || !allowedPath(g, in.Path) {
			return Call{}, ErrDenied
		}
		args["ref"] = "refs/heads/" + in.Branch
		args["path"] = in.Path
		return build("get_file_contents", args)
	case "files.write":
		if !g.AllowUnconditionalWrites {
			return Call{}, ErrDenied
		}
		type file struct {
			Path    string  `json:"path"`
			Content *string `json:"content"`
		}
		var in struct {
			Branch  string `json:"branch"`
			Message string `json:"message"`
			Files   []file `json:"files"`
		}
		if strict.Decode(raw, &in) != nil || !branch(in.Branch) || !contains(g.Branches, in.Branch) || strings.TrimSpace(in.Message) == "" || len(in.Message) > 1024 || len(in.Files) == 0 || len(in.Files) > 20 {
			return Call{}, ErrDenied
		}
		seen := map[string]bool{}
		for _, f := range in.Files {
			if !allowedTreeWrite(g, f.Path) || seen[f.Path] || f.Content == nil || !utf8.ValidString(*f.Content) || strings.ContainsRune(*f.Content, 0) {
				return Call{}, ErrDenied
			}
			for existing := range seen {
				if strings.HasPrefix(existing, f.Path+"/") || strings.HasPrefix(f.Path, existing+"/") {
					return Call{}, ErrDenied
				}
			}
			seen[f.Path] = true
		}
		args["branch"] = in.Branch
		args["message"] = in.Message
		args["files"] = in.Files
		return build("push_files", args)
	default:
		return buildOperation(g, action, raw, args)
	}
}
