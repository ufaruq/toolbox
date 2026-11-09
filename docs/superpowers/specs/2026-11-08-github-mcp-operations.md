# GitHub operations through Toolbox MCP

Status: expanded user-requested scope; implementation and live acceptance pending.
Supersedes the issue-read-only scope of PR #9 for the new connector. Preserve the
existing Docker Gateway route and the existing Google connector.

## Intended user experience

The App installation may include multiple repositories selected by the owner.
Keep that selection: the user explicitly chose application-level authorization.
Installation access is only a ceiling, never an agent grant. An owner connects
a GitHub App installation and selects a repository for each Toolbox grant. The owner
approves an identified agent for explicit actions and an expiry. The agent uses
Toolbox MCP to read files, propose file changes, create a task branch, commit one
or multiple files, and open/manage pull requests. It receives no GitHub token,
SSH key, local Git credentials, gateway bearer, or direct gateway endpoint.
No local clone or shell is required for these GitHub API operations. This does
not provide a build/test execution environment or arbitrary Git transport.

## Architecture and credentials

Agent -> Toolbox authentication and live grant checks -> reviewed GitHub policy
adapter -> existing shared MCP client -> isolated Docker MCP Gateway -> pinned
GitHub MCP server -> GitHub APIs.

Use GitHub App installation tokens issued for exactly one immutable repository
ID and an explicit permission subset. GitHub documents a one-hour lifetime;
Toolbox grants can expire sooner and must be checked independently. Never grant
access merely because the provider token remains valid. GitHub authentication,
installation verification and token issuance/revocation are internal control
plane API calls; provider operations go through MCP. There is no direct GitHub
operation fallback.

A protected App private key remains a long-lived service secret. It must never
enter agent requests, persisted non-secret state, logs or downstream MCP tools.
The downstream credential context receives only short-lived installation tokens.
Renewal creates a new isolated context; retire expired contexts, invalidate old
bindings and bound cleanup. No PAT or SSH deploy key is required from agents.
Do not claim the existing static-secret pilot already supports rotation.

GitHub App permissions are an upper bound, not Toolbox authorization. Verify
that the installation belongs to the connecting account; knowing an installation
ID or public repository name does not establish ownership. Resolve trusted
provider identity separately from Toolbox owner sign-in.

## Reviewed capabilities

| Capability | MCP mapping / constraint |
| --- | --- |
| Read files, directories, commits, branches, PRs and issues | Reviewed tools from the pinned inventory; bounded content and pagination. |
| Create task branch | `create_branch`; approved repository, source revision and task branch namespace. |
| Update one file | `create_or_update_file`; approved branch/path, expected file revision where supported. |
| Commit multiple files | `push_files`; approved branch and paths, bounded file count/bytes; investigate atomic expected-head support before enablement. |
| Create/update/close/reopen PR | Exact reviewed PR tool/method; validate base/head repository and branch and explicit permitted fields. |
| Review/comment on PR | Separate action permission; validate target PR; returned/user-provided content remains untrusted. |
| Merge PR | Separate explicit approval bound to reviewed head SHA; no branch-protection bypass. |

Do not automatically expose every upstream tool. Repository deletion, permission
administration, secrets management, workflow modification, force-push and other
destructive capabilities require separately reviewed policies. Missing upstream
concurrency or scope enforcement blocks the affected operation; never silently
replace it with a weaker check. Tool names above must be verified against the
pinned image before runtime enablement.

## Persistence and authorization

Add explicit GitHub repository/resource kinds; never encode repository identity
as a Google FileID. Bind grants and approval digests to owner, agent, connection,
connection generation, immutable repository ID, actions, branch/path restrictions,
expiry, and any operation-specific approval (including expected revision).
Use additive migrations and preserve legacy Google grant/token semantics.

Construct MCP arguments from trusted grants and validated structured inputs.
Agents cannot supply MCP server URLs, arbitrary tools, raw JSON passthrough,
credential references or installation IDs as authority. Recheck authorization
before dispatch and before result release. Record started/terminal audit events
without tokens or raw file contents. Writes may finish upstream if revocation
races dispatch; report this limitation, never promise retroactive rollback.
Timeout after dispatch is an uncertain outcome, not a reason to retry a write.

## Acceptance gates

- Verify installation-token repository restrictions against real GitHub,
  including public repositories; PATs include public read access and are not
  sufficient proof of this boundary.
- Verify the pinned server tools, argument schemas and actual write concurrency
  semantics. Reject stale head/file revisions without losing concurrent work.
- Controlled tests cover two owners, cross-repository/branch/path attempts,
  rename/transfer/locator reuse, revocation, expiry, reconnect, token rotation,
  shutdown/cleanup, timeout-after-write, secret redaction and audit failures.
- Browser and inbound MCP acceptance cover connect -> request -> owner review ->
  approved call -> revoke. Include unchanged Google acceptance and rollback with
  GitHub disabled.
- Live reads use `ufaruq/toolbox`. Live writes use a dedicated task branch and
  explicitly authorized test PR/files. Never rename/transfer the real repository
  for testing; use fixtures or disposable repositories for destructive cases.

## References

- [Existing gateway pilot](../../mcp-gateway-pilot.md)
- [Existing feasibility evidence](../../experiments/mcp-github-feasibility.md)
- [GitHub installation tokens](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app)
- [Official GitHub MCP server](https://github.com/github/github-mcp-server)
