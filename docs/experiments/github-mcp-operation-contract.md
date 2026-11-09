# GitHub MCP operation contract

This experiment constructs fixed calls against GitHub MCP source revision
`b98d115bbb080e9555466a96656ec4df605aea21`. Policy construction is implemented in
`internal/servicepolicy/github`; it does not by itself establish runtime or live
GitHub acceptance. No local Git checkout or agent provider credential is needed.

The application must authenticate owner, agent and MCP caller separately, check
live grant expiry/revocation and connection epoch at dispatch, and resolve the
trusted owner/repository locator back to the approved numeric repository ID.
Installation-token issuance must restrict `repository_ids` to that ID even when
the App installation includes other repositories. `Permissions(action)` returns
only metadata read and the action-specific contents, pull_requests or issues
permission; account connection is never repository authorization.

## Inputs and restrictions

All inputs use strict JSON: duplicate, unknown and case-aliased keys, nulls and
trailing values are rejected. Inputs and constructed arguments are at most 16
KiB. Branches and paths must match explicit grant lists; paths ending in `/`
grant descendants. Ref syntax, path traversal, encoded paths, `.git` and workflow
paths are denied. There are no implicit branch defaults, arbitrary tool names,
methods, argument passthrough, workflow/admin/delete/force-push capabilities.
`ValidateGrant` validates restriction syntax before persistence; dispatch still
checks live authorization separately.

| Action | Input fields | Fixed upstream tool |
| --- | --- | --- |
| `files.read` | `branch`, `path` | `get_file_contents` with trusted `ref` |
| `files.write` | `branch`, `message`, `files` (`path`, `content`) | `push_files`, at most 20 unique files |
| `files.update` | `branch`, `path`, `message`, `content`, `sha` | `create_or_update_file`, required exact blob SHA, symlink writes false |
| `branches.create` | `branch`, `from_branch` | `create_branch`, source must be in `BaseBranches` |
| `prs.read` | `pull_number` | `pull_request_read`, method `get` |
| `prs.create` | `head`, `base`, `title`, optional `body`, `draft` | `create_pull_request`, maintainer edits false |
| `prs.update` | `pull_number`, optional `title`, `body`, `state`, `base`, `draft` | `update_pull_request`, at least one update |
| `prs.review` | `pull_number`, `commit_id`, `event`, `body` | `pull_request_review_write`, method `create`, explicit submitted event |
| `prs.merge` | `pull_number`, `expected_head`, optional `merge_method` | `merge_pull_request`, required approved `expectedHeadSha` |
| `issues.read` | `issue_number` | `issue_read`, method `get` |

Existing PR operations require an explicit `PullRequests` number list. Creation
requires an explicit allowed head and base. Before existing PR operations, fetch
trusted current PR metadata, verify both head/base repository IDs equal the
approved repository ID, then call `ValidatePullRequest` with number, head branch,
base branch and head SHA. Fork PRs are unsupported. This preflight checks grant
branch restrictions and `ExpectedHead` when supplied; caller-provided branch
names are not evidence of the current PR target. Retargeting and external changes
can race a preflight; GitHub's merge endpoint atomically checks head SHA, but does
not atomically assert the approved base branch. Exact base-at-merge semantics
remain unsupported. Do not claim the preflight closes that race.

Merge and review require a grant `ExpectedHead` of 40 lowercase hex characters.
The caller must provide that same SHA. Merge forwards the approved SHA to the
provider's atomic expected-head check and exposes no protection bypass. Review
pins the reviewed commit; a new head does not silently receive the old approval.
Thread resolution and pending-review methods are unsupported: upstream thread
methods ignore the repository and PR arguments. File update requires a nonempty
text content because the pinned upstream single-file tool rejects empty content;
use explicitly approved multi-file writes for empty files. The SHA is a blob
precondition, not a branch-head precondition. Plain text is sent unchanged; the
upstream tool performs REST base64 encoding.

## Multi-file write boundary

`files.write` requires `AllowUnconditionalWrites=true`, explicitly reviewed by
the owner. `push_files` reads the current head, constructs a commit with that
parent, and updates the ref with `Force=false`. A concurrent divergent change
after that internal head read rejects as non-fast-forward. There is **no caller
expected-head input**, so a stale agent baseline can overwrite file content when
the branch changed before the tool's internal read. This is not compare-and-set.
No automatic mutation retry or fabricated CAS is provided.

The upstream tool may create a missing branch from the default branch and may
initialize an empty repository, including a default-branch change. Dispatch must
preflight that the repository is nonempty and the exact target branch exists.
Those checks reduce accidental side effects but cannot eliminate concurrent
external branch deletion or repository-administration races. Deployments needing
atomic existing-branch-only or agent-baseline semantics must disable this
capability until an upstream primitive provides them.

## Bounded results

`ProjectResult(action, raw)` accepts the serialized MCP `CallToolResult` envelope
at most 256 KiB and emits at most 64 KiB of selected fields. It rejects provider
errors, links, binary resources, directory reads and unavailable file content.
Before dispatching a file read, resolve the exact approved branch to its current
commit SHA and call `PinRead(call, commitSHA)`. This is mandatory: the pinned
upstream resolver can fall back from missing `main` to the default branch, even
with a fully qualified ref. The upstream suffix-match fallback emits only text
and is rejected by projection. File reads return only text and blob SHA; no download links or resource URIs are
forwarded or fetched. Other operations retain outcome identifiers, branch refs,
PR state and bounded text, discarding arbitrary nested objects and metadata.
Treat all projected provider text as untrusted data. Rejection of an oversized
mutation result does not prove that the mutation failed: do not retry it. The
application should correlate projected results with the trusted request scope.

Sources: pinned upstream [repository tools](https://github.com/github/github-mcp-server/blob/b98d115bbb080e9555466a96656ec4df605aea21/pkg/github/repositories.go),
[PR tools](https://github.com/github/github-mcp-server/blob/b98d115bbb080e9555466a96656ec4df605aea21/pkg/github/pullrequests.go),
and [issue tools](https://github.com/github/github-mcp-server/blob/b98d115bbb080e9555466a96656ec4df605aea21/pkg/github/issues.go).
