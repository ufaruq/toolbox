package github

import (
	"encoding/json"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/ufaruq/toolbox/internal/strict"
)

var shaPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

// Permissions returns the minimum installation-token permissions for one action.
// Token issuance must also restrict repository_ids to the trusted RepositoryID.
func Permissions(action string) (map[string]string, error) {
	p := map[string]string{"metadata": "read"}
	switch action {
	case "files.read":
		p["contents"] = "read"
	case "files.write", "files.update", "branches.create", "prs.merge":
		p["contents"] = "write"
	case "prs.read":
		p["pull_requests"] = "read"
	case "prs.create", "prs.update", "prs.review":
		p["pull_requests"] = "write"
	case "issues.read":
		p["issues"] = "read"
	default:
		return nil, ErrDenied
	}
	return p, nil
}

// ValidateGrant validates restrictions independently of expiry and principal binding.
func ValidateGrant(g Grant) error {
	if len(g.Actions) == 0 || len(g.Actions) > 10 || len(g.Branches) > 50 || len(g.BaseBranches) > 50 || len(g.Paths) > 100 || len(g.PullRequests) > 100 {
		return ErrDenied
	}
	for _, a := range g.Actions {
		if _, e := Permissions(a); e != nil {
			return e
		}
		switch a {
		case "files.read", "files.write", "files.update":
			if len(g.Branches) == 0 || len(g.Paths) == 0 {
				return ErrDenied
			}
		case "branches.create", "prs.create":
			if len(g.Branches) == 0 || len(g.BaseBranches) == 0 {
				return ErrDenied
			}
		case "prs.read", "prs.update", "prs.review", "prs.merge":
			if len(g.PullRequests) == 0 || len(g.Branches) == 0 || len(g.BaseBranches) == 0 {
				return ErrDenied
			}
		}
		if a == "files.write" && !g.AllowUnconditionalWrites {
			return ErrDenied
		}
		if (a == "prs.merge" || a == "prs.review") && !shaPattern.MatchString(g.ExpectedHead) {
			return ErrDenied
		}
	}
	for _, bs := range [][]string{g.Branches, g.BaseBranches} {
		for _, b := range bs {
			if !branch(b) {
				return ErrDenied
			}
		}
	}
	for _, p := range g.Paths {
		v := strings.TrimSuffix(p, "/")
		if !allowedPath(Grant{Paths: []string{v}}, v) {
			return ErrDenied
		}
	}
	for _, n := range g.PullRequests {
		if n <= 0 {
			return ErrDenied
		}
	}
	if g.ExpectedHead != "" && !shaPattern.MatchString(g.ExpectedHead) {
		return ErrDenied
	}
	return nil
}
func allowedPR(g Grant, n int64) bool {
	for _, v := range g.PullRequests {
		if n > 0 && n == v {
			return true
		}
	}
	return false
}

// ValidatePullRequest consumes trusted, freshly fetched same-repository PR
// metadata, never caller assertions. The dispatcher must also verify both PR
// head/base repository IDs equal g.RepositoryID; fork PRs are unsupported.
func ValidatePullRequest(g Grant, number int64, head, base, headSHA string) error {
	if !allowedPR(g, number) || !branch(head) || !branch(base) || !contains(g.Branches, head) || !contains(g.BaseBranches, base) || !shaPattern.MatchString(headSHA) {
		return ErrDenied
	}
	if g.ExpectedHead != "" && headSHA != g.ExpectedHead {
		return ErrDenied
	}
	return nil
}
func textOK(v string, max int, required bool) bool {
	return utf8.ValidString(v) && !strings.ContainsRune(v, 0) && len(v) <= max && (!required || strings.TrimSpace(v) != "")
}
func buildOperation(g Grant, action string, raw json.RawMessage, args map[string]any) (Call, error) {
	switch action {
	case "files.update":
		var in struct {
			Branch  string `json:"branch"`
			Path    string `json:"path"`
			Content string `json:"content"`
			Message string `json:"message"`
			SHA     string `json:"sha"`
		}
		if strict.Decode(raw, &in) != nil || !branch(in.Branch) || !contains(g.Branches, in.Branch) || !allowedPath(g, in.Path) || !shaPattern.MatchString(in.SHA) || !textOK(in.Message, 1024, true) || !textOK(in.Content, 16<<10, true) {
			return Call{}, ErrDenied
		}
		args["branch"] = in.Branch
		args["path"] = in.Path
		args["content"] = in.Content
		args["message"] = in.Message
		args["sha"] = in.SHA
		args["allow_symlink_write"] = false
		return build("create_or_update_file", args)
	case "branches.create":
		var in struct {
			Branch string `json:"branch"`
			From   string `json:"from_branch"`
		}
		if strict.Decode(raw, &in) != nil || !branch(in.Branch) || !contains(g.Branches, in.Branch) || !branch(in.From) || !contains(g.BaseBranches, in.From) || in.Branch == in.From {
			return Call{}, ErrDenied
		}
		args["branch"] = in.Branch
		args["from_branch"] = in.From
		return build("create_branch", args)
	case "prs.create":
		var in struct {
			Head  string `json:"head"`
			Base  string `json:"base"`
			Title string `json:"title"`
			Body  string `json:"body"`
			Draft bool   `json:"draft"`
		}
		if strict.Decode(raw, &in) != nil || !branch(in.Head) || !contains(g.Branches, in.Head) || !branch(in.Base) || !contains(g.BaseBranches, in.Base) || in.Head == in.Base || !textOK(in.Title, 256, true) || !textOK(in.Body, 8192, false) {
			return Call{}, ErrDenied
		}
		args["head"] = in.Head
		args["base"] = in.Base
		args["title"] = in.Title
		args["body"] = in.Body
		args["draft"] = in.Draft
		args["maintainer_can_modify"] = false
		return build("create_pull_request", args)
	case "prs.read":
		var in struct {
			Number int64 `json:"pull_number"`
		}
		if strict.Decode(raw, &in) != nil || !allowedPR(g, in.Number) {
			return Call{}, ErrDenied
		}
		args["pullNumber"] = in.Number
		args["method"] = "get"
		return build("pull_request_read", args)
	case "prs.update":
		var in struct {
			Number int64   `json:"pull_number"`
			Title  *string `json:"title"`
			Body   *string `json:"body"`
			State  *string `json:"state"`
			Base   *string `json:"base"`
			Draft  *bool   `json:"draft"`
		}
		if strict.Decode(raw, &in) != nil || !allowedPR(g, in.Number) {
			return Call{}, ErrDenied
		}
		args["pullNumber"] = in.Number
		if in.Title != nil {
			if !textOK(*in.Title, 256, true) {
				return Call{}, ErrDenied
			}
			args["title"] = *in.Title
		}
		if in.Body != nil {
			if !textOK(*in.Body, 8192, false) {
				return Call{}, ErrDenied
			}
			args["body"] = *in.Body
		}
		if in.State != nil {
			if *in.State != "open" && *in.State != "closed" {
				return Call{}, ErrDenied
			}
			args["state"] = *in.State
		}
		if in.Base != nil {
			if !branch(*in.Base) || !contains(g.BaseBranches, *in.Base) {
				return Call{}, ErrDenied
			}
			args["base"] = *in.Base
		}
		if in.Draft != nil {
			args["draft"] = *in.Draft
		}
		if len(args) == 3 {
			return Call{}, ErrDenied
		}
		return build("update_pull_request", args)
	case "prs.review":
		var in struct {
			Number int64  `json:"pull_number"`
			Event  string `json:"event"`
			Commit string `json:"commit_id"`
			Body   string `json:"body"`
		}
		if strict.Decode(raw, &in) != nil || !allowedPR(g, in.Number) || !shaPattern.MatchString(g.ExpectedHead) || in.Commit != g.ExpectedHead || !contains([]string{"APPROVE", "REQUEST_CHANGES", "COMMENT"}, in.Event) || !textOK(in.Body, 8192, true) {
			return Call{}, ErrDenied
		}
		args["pullNumber"] = in.Number
		args["method"] = "create"
		args["event"] = in.Event
		args["commitID"] = g.ExpectedHead
		args["body"] = in.Body
		return build("pull_request_review_write", args)
	case "prs.merge":
		var in struct {
			Number int64  `json:"pull_number"`
			Head   string `json:"expected_head"`
			Method string `json:"merge_method"`
		}
		if strict.Decode(raw, &in) != nil || !allowedPR(g, in.Number) || !shaPattern.MatchString(g.ExpectedHead) || in.Head != g.ExpectedHead {
			return Call{}, ErrDenied
		}
		if in.Method == "" {
			in.Method = "merge"
		}
		if !contains([]string{"merge", "squash", "rebase"}, in.Method) {
			return Call{}, ErrDenied
		}
		args["pullNumber"] = in.Number
		args["expectedHeadSha"] = g.ExpectedHead
		args["merge_method"] = in.Method
		return build("merge_pull_request", args)
	case "issues.read":
		var in struct {
			Number int64 `json:"issue_number"`
		}
		if strict.Decode(raw, &in) != nil || in.Number <= 0 {
			return Call{}, ErrDenied
		}
		args["issue_number"] = in.Number
		args["method"] = "get"
		return build("issue_read", args)
	default:
		return Call{}, ErrDenied
	}
}

// PinRead pins a constructed file-read call to the trusted SHA resolved from the
// exact granted branch at dispatch, preventing upstream default/tag fallbacks.
func PinRead(call Call, commit string) (Call, error) {
	if call.Tool != "get_file_contents" || !shaPattern.MatchString(commit) {
		return Call{}, ErrDenied
	}
	var args struct {
		Owner string `json:"owner"`
		Repo  string `json:"repo"`
		Ref   string `json:"ref"`
		Path  string `json:"path"`
	}
	if strict.Decode(call.Arguments, &args) != nil || !locator.MatchString(args.Owner) || !locator.MatchString(args.Repo) || !strings.HasPrefix(args.Ref, "refs/heads/") {
		return Call{}, ErrDenied
	}
	return build(call.Tool, map[string]any{"owner": args.Owner, "repo": args.Repo, "path": args.Path, "ref": args.Ref, "sha": commit})
}
