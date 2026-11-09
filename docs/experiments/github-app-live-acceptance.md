# GitHub App credential acceptance

Recorded 2026-11-08 during the expanded GitHub MCP connector setup.
These are live GitHub credential checks, not MCP connector acceptance.

## Verified

- App: The AI Toolbox (`the-ai-toolbox`), ID `5667548`, owned by `ufaruq`.
- Installation: `180004509`, active, selected-repository installation.
- Repository: `ufaruq/toolbox`, immutable ID `1423893369`.
- App permissions: contents/issues/pull_requests write; actions/checks/metadata read.
- Issued a short-lived installation token with explicit repository ID and only
  contents/issues/metadata read permissions. Verified returned permissions and
  lifetime. The installation repository listing contained only `ufaruq/toolbox`.
- Authenticated README read from `ufaruq/toolbox` returned HTTP 200.
- Test token was revoked immediately afterward; revocation returned HTTP 204.
- No repository writes were performed. No token or private key is recorded here.

## Failed isolation assumption

With the same token, `GET /repos/octocat/Hello-World/contents/README` also returned
HTTP 200, despite that public repository not being selected. The response content
was discarded and not printed or retained. Installation repository selection is
therefore not sufficient proof of exclusive public-repository read access.
This does not demonstrate access to an unselected private repository or write
access to an unselected repository. Those are separate properties.

The existing MCP server's locator-based reads cannot be declared safe against
old-locator reuse solely on the basis of token repository scope. A trusted
preflight identity lookup alone has a resolution/dispatch race. The original
PR #9 requires identity enforcement through upstream dispatch, not merely
rejection of returned data. That gate remains open and connector enablement
remains blocked until an acceptable route is proven.

## Remaining acceptance

- Actual installed App token through the pinned Docker Gateway/GitHub MCP server.
- Immutable resource enforcement at dispatch for each read/write capability.
- Trusted owner-to-installation onboarding, persisted grants and review UI.
- Token renewal, isolated downstream credential replacement and cleanup.
- File/branch/multi-file commit/PR policies and concurrency semantics.
- Browser and inbound MCP end-to-end authorization/revocation tests.

The App is registered and installed. The full Toolbox connector is not yet
implemented or enabled. See the [expanded design](../superpowers/specs/2026-11-08-github-mcp-operations.md).
