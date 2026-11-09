# GitHub repository access

[Overview](../README.md) · [MCP identity setup](mcp-setup.md) · [App registration](../github-app/README.md)

The GitHub connector separates App installation access, owner connections, caller
approval and repository grants. Keep the repositories selected in GitHub; an
installation's access is a ceiling, not permission for an agent to use them.

## Owner and agent flow

1. The operator binds a verified GitHub App installation to a specific existing
   Toolbox owner ID. This local connector does not trust installation IDs from
   browser callbacks and does not implement public self-service App onboarding.
2. The owner opens `/github`, selects a repository returned by that trusted
   installation and connects it. A connection records the immutable repository
   ID, installation ID, locator and generation. Reconnecting creates a new
   connection; old grants cannot transfer to it.
3. In Workspace's **Agent clients**, enable **Allow scoped GitHub operations**
   for the intended MCP caller. This permits requests, not repository operations.
4. The agent lists connections, requests a scope, and supplies the approval URL
   to the owner. The owner reviews agent, repository ID, actions, branches, paths,
   PR numbers, approved head SHA and expiry. An approval is valid for only the
   exact reviewed request; changes require a new request.
5. The agent polls for its grant and invokes an approved operation. Authentication,
   owner/agent binding, grant lifetime and connection generation are checked
   before execution and again before releasing results. Disable, revoke and
   disconnect invalidate grants. They cannot undo completed GitHub writes.

Review requests expire after 15 minutes. Grants last at most seven days and cannot
outlive their caller profile. No GitHub token or App private key is returned to
agents, the browser, grants, ordinary state tables or audits.

## Inbound tools

Only callers explicitly approved for `github.operation.v1` see these tools:

| Tool | Purpose |
| --- | --- |
| `toolbox_list_github_connections` | List this owner's active repository connections. |
| `toolbox_request_github_access` | Request an exact connection, scope and duration. |
| `toolbox_get_github_request` | Poll this caller's request and obtain the grant ID. |
| `github_operation_v1` | Invoke a fixed supported action with a grant ID. |

Example access request:

```json
{
  "connection_id": "<connection-id>",
  "duration_seconds": 3600,
  "scope": {
    "actions": ["files.read"],
    "branches": ["main"],
    "paths": ["README.md", "docs/"]
  }
}
```

Example operation:

```json
{
  "grant_id": "<approved-grant-id>",
  "action": "files.read",
  "arguments": {"branch": "main", "path": "README.md"}
}
```

Scopes additionally accept `base_branches`, `pull_requests`, `expected_head`, and
`allow_unconditional_writes`. Actions and their exact argument schemas are in the
[reviewed operation contract](experiments/github-mcp-operation-contract.md).
Toolbox constructs upstream tools and arguments; callers cannot supply provider
URLs, installation IDs, owner/repository locators or arbitrary MCP methods.

Paths ending in `/` authorize descendants; other paths authorize exact entries.
Multi-file writes require subtree and ancestor authority, for example both `src`
and `src/`, plus explicit acknowledgement of unconditional writes. A permitted
path can replace a directory and its descendants, so exact-file-only grants
cannot authorize `push_files`. Workflow modifications are excluded.

PR permissions apply to the PR, including its full diff; file-operation path
limits do not limit PR contents. Fork PRs are excluded. Review/merge require an
explicit approved head revision. Merge is a distinct action; approving creation
or review does not approve merging.

## HTTP owner lifecycle

Owner endpoints require the normal Toolbox session. POST requests require exact
Origin, JSON content type and CSRF header. `GET /v1/github/state` returns only the
owner's connections, requests and grants. The UI uses:

- `GET /v1/github/repositories`, `POST /v1/github/connections` (`repository_id`).
- `POST /v1/github/connections/{id}/disconnect` with an empty object.
- `POST /v1/github/requests/{id}/review` with an empty object.
- `POST /v1/github/requests/{id}/approve` or `/deny` with the reviewed `digest`.
- `POST /v1/github/grants/{id}/revoke` with an empty object.

Legacy authenticated agents can use `POST /v1/github/requests`,
`GET /v1/github/requests/{id}` and `POST /v1/github/invoke` with the same request
bodies as MCP. These endpoints do not accept owner cookies as agent identity.
Stored records returned by the state/review endpoints retain domain field names;
agent request fields use the snake_case API schema above.

## Limits and acceptance

GitHub installation tokens still permit some public repository reads outside
selected repositories. Toolbox policy and dispatch checks remain necessary.
The [live token evidence](experiments/github-app-live-acceptance.md) records that
negative probe rather than claiming token scope alone proves isolation.

Upstream `push_files` has no caller baseline compare-and-swap, and upstream merge
cannot atomically assert the approved base branch. Metadata preflight cannot
remove every concurrent rename, transfer or retarget race. The operation
contract records these limits. No write is automatically retried: a timeout or
rejected response after dispatch may mean the write succeeded. Inspect state
before deciding to retry.

`make github-check` runs credential/policy and application authorization tests.
`make github-browser-check` exercises the owner page in real Chromium against a
synthetic provider. The full `make test-all` enables that browser test together
with storage, Google, Keycloak and gateway acceptance. Synthetic results are not
live GitHub acceptance; record real-provider evidence separately.
