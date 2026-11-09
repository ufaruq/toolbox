package server

// githubOperationSchema describes discovery; servicepolicy/github remains the
// authority for byte limits, valid refs/paths, grant scope and live dispatch.
func githubOperationSchema() map[string]any {
	text := func(max int, required bool) map[string]any {
		s := map[string]any{"type": "string", "maxLength": max, "pattern": "^[^\u0000]*$", "description": "UTF-8 text; limits are also enforced in bytes at dispatch."}
		if required {
			s["minLength"] = 1
			s["pattern"] = "^[^\u0000]*[^\\s\u0000][^\u0000]*$"
		}
		return s
	}
	branch := map[string]any{"type": "string", "minLength": 1, "maxLength": 200, "description": "Exact granted branch name, not refs/heads/. Git ref validation and the 200-byte bound apply at dispatch."}
	path := map[string]any{"type": "string", "minLength": 1, "maxLength": 1024, "description": "Exact granted repository-relative path. Traversal, .git and .github/workflows are forbidden; path policy and 1024-byte limit apply at dispatch."}
	sha := map[string]any{"type": "string", "pattern": "^[0-9a-f]{40}$"}
	number := map[string]any{"type": "integer", "minimum": 1, "maximum": int64(9223372036854775807)}
	boolean := map[string]any{"type": "boolean"}
	enum := func(values ...string) map[string]any { return map[string]any{"type": "string", "enum": values} }
	content := text(16<<10, false)
	content["minLength"] = 1
	variants := []any{}
	add := func(action string, properties map[string]any, required ...string) map[string]any {
		args := objectSchema(properties, required...)
		variants = append(variants, objectSchema(map[string]any{"grant_id": idSchema(), "action": map[string]any{"type": "string", "const": action}, "arguments": args}, "grant_id", "action", "arguments"))
		return args
	}
	add("files.read", map[string]any{"branch": branch, "path": path}, "branch", "path")
	add("files.update", map[string]any{"branch": branch, "path": path, "content": content, "message": text(1024, true), "sha": sha}, "branch", "path", "content", "message", "sha")
	add("files.write", map[string]any{"branch": branch, "message": text(1024, true), "files": map[string]any{"type": "array", "minItems": 1, "maxItems": 20, "items": objectSchema(map[string]any{"path": path, "content": text(16<<10, false)}, "path", "content"), "description": "Distinct paths without ancestor collisions; grant must permit unconditional tree writes and every ancestor. Total serialized arguments are limited to 16 KiB."}}, "branch", "message", "files")
	add("branches.create", map[string]any{"branch": branch, "from_branch": branch}, "branch", "from_branch")
	add("prs.read", map[string]any{"pull_number": number}, "pull_number")
	add("prs.create", map[string]any{"head": branch, "base": branch, "title": text(256, true), "body": text(8192, false), "draft": boolean}, "head", "base", "title")
	update := add("prs.update", map[string]any{"pull_number": number, "title": text(256, true), "body": text(8192, false), "state": enum("open", "closed"), "base": branch, "draft": boolean}, "pull_number")
	update["minProperties"] = 2
	add("prs.review", map[string]any{"pull_number": number, "event": enum("APPROVE", "REQUEST_CHANGES", "COMMENT"), "commit_id": sha, "body": text(8192, true)}, "pull_number", "event", "commit_id", "body")
	add("prs.merge", map[string]any{"pull_number": number, "expected_head": sha, "merge_method": enum("", "merge", "squash", "rebase")}, "pull_number", "expected_head")
	add("issues.read", map[string]any{"issue_number": number}, "issue_number")
	return map[string]any{"type": "object", "oneOf": variants, "description": "Action-specific closed inputs. Total arguments and the constructed provider call must each fit 16 KiB. PR operations require trusted same-repository head/base checks; review and merge require the approved head SHA. Authorization is checked again at dispatch."}
}
