# GitHub MCP operations implementation plan

**Goal:** Expose scoped GitHub repository operations to agents through Toolbox,
without giving agents GitHub credentials or requiring a local Git checkout.

**Spec:** [Expanded connector design](../specs/2026-11-08-github-mcp-operations.md).
**Architecture:** Reuse `internal/mcpclient` and the pinned Docker Gateway topology.
Add installation-token management, explicit GitHub policies and resource-aware
application authorization. Keep the existing Drive execution path unchanged.
**Execution:** Implement inline, using failing regression tests before behavior
changes, and review the complete branch independently before publishing.

## Global constraints

- No arbitrary MCP passthrough, direct provider-operation fallback or PAT fallback.
- Installation tokens contain exactly one approved immutable repository ID and
  explicit permissions; the App key never enters a downstream credential context.
- Reuse 20-second invocation deadlines and 1 MiB result limits. Bound files,
  batches and strings before dispatch. No automatic retry after any write dispatch.
- Add migrations after current main; preserve existing Drive resources and tokens.
- Keep runtime disabled until configured and each capability's acceptance passes.
- Run `make test-all` before pushing; separate synthetic evidence from live proof.

## 1. Register App and verify the pinned upstream contract

Files: `github-app/`, `docs/experiments/mcp-github-feasibility.md`, operator-only
probe assets in ignored `work/` (outside tracked source).

- [x] Prepare non-secret registration settings and `make github-app-setup`.
- [x] Register the App and install it on the owner-selected repositories, including `ufaruq/toolbox`.
- [x] Record App/installation IDs and securely provision its signing key.
- [ ] Inventory actual pinned tool schemas for file read/update, `push_files`,
  branch creation, PR read/create/update/review/merge and issue operations.
- [ ] Prove installation-token authentication, explicit permission narrowing,
  expiry and denial outside the selected repository, including a public target.
- [ ] Verify actual `push_files` concurrent-head behavior. If expected-head writes
  are unsupported, block that capability until a reviewed safe approach exists;
  an unprotected preflight SHA comparison is not sufficient.
- [ ] Record capability-by-capability go/no-go evidence. Do not claim a successful
  issue read validates file writes, PR merges or repository-identity races.

## 2. Short-lived installation credential service

Files: new `internal/githubapp/{issuer.go,issuer_test.go,lifecycle.go,lifecycle_test.go}`;
configuration additions in `cmd/toolbox` only when runtime wiring is ready.

Interface: `Issue(ctx, installationID, repositoryID, permissions) (Credential, error)`.
`Credential` contains secret token, provider expiry and verified scope; never add
it to `domain.State`. Installation IDs are resolved from trusted owner connections.

- [ ] Failing tests for signed App JWT validity, exact repository/permission
  request, missing/broader response scope, expired/overlong lifetime, oversized
  response, redirect, cancellation, duplicate response fields and redacted errors.
- [ ] Implement bounded HTTPS issuance with no redirects and validated response.
- [ ] Test rotation with fresh downstream contexts, failed renewal, concurrent
  calls, expiry, disconnect and cleanup; never reuse another owner's context.
- [ ] Verify using `make test TEST_PACKAGES=./internal/githubapp`.

## 3. Capability-specific GitHub policy

Files: new `internal/servicepolicy/github/{policy.go,policy_test.go}` with focused
files for read, file-write, branch and PR mappings as needed.

Interface: a typed approved operation contains immutable repository identity,
connection generation, permitted actions, branch/path rules and expected revision.
A policy-built call contains a pinned tool plus exact constructed arguments.
Result validation produces bounded typed data, not raw credential-bearing output.

- [ ] Failing tests for each accepted mapping and unknown field/tool/method,
  repository/branch/path escape, traversal, invalid ref, batch limits, stale SHA,
  cross-repository PR, workflow files, secret echo and malformed results.
- [ ] Implement only capabilities accepted by the upstream contract gate.
- [ ] Test that denied inputs make zero gateway requests and reads never obtain
  a write-capable credential context.
- [ ] Verify using `make test TEST_PACKAGES=./internal/servicepolicy/github`.

## 4. Persisted GitHub connections, requests and grants

Files: `internal/domain`, `internal/store`, `internal/security`, a new numbered
SQL migration and memory/PostgreSQL upgrade tests.

- [ ] Define explicit repository resource kinds and immutable IDs; keep old
  document ID semantics. Include actions, branch/path restrictions, revision
  approval and generation in request digests, grants and token validation.
- [ ] Write failing memory and real PostgreSQL tests for cross-kind/owner/agent
  denial, immutable scope, expiry, reconnect and unchanged legacy Drive grants.
- [ ] Implement additive schema and snapshot validation, including SQL invariants.
- [ ] Verify focused tests and actual migration/constraint tests via `make test-all`.

## 5. Trusted onboarding and owner approval

Files: focused GitHub handlers under `internal/server`, owner UI assets,
`internal/app` wiring and browser tests.

- [ ] Bind a verified installation to the authenticated owner; reject spoofed
  installation callback IDs, other-owner installations and stale login state.
- [ ] Show provider account, repository, agent, actions, branch/path limits,
  expiry and exact mutation/merge revision in trusted review UI.
- [ ] Write failing browser/API tests for stale review, CSRF, cross-owner access,
  permissions changes and disconnect/reconnect before implementing handlers.
- [ ] Keep provider secrets out of browser JSON, audits and ordinary DB state.

## 6. Inbound MCP operations and opt-in runtime

Files: `internal/server/mcp.go`, focused GitHub operation handlers,
`cmd/toolbox`, `.env.example`, integration/browser acceptance and setup docs.

- [ ] Add typed inbound operations; callers cannot choose upstream tools or URLs.
- [ ] Test live authorization before dispatch and final release; persist started
  and terminal audit events, including uncertain write outcomes and audit failure.
- [ ] Enforce explicit merge approval and preserve GitHub branch protections.
- [ ] Test cancellation, no retry after dispatch, rotation, disconnect and rollback
  with GitHub disabled; rerun the existing Google regression suites.
- [ ] Document real startup and credential rotation using Make targets.

## 7. Live acceptance and review

- [ ] Read from `ufaruq/toolbox` with a narrow installation token through the real
  pinned gateway/server. Verify public cross-repository denial separately.
- [ ] Use only an explicitly approved test branch/files/PR for live writes; verify
  a multi-file commit, PR lifecycle, concurrent-update denial and cleanup.
- [ ] Do not rename/transfer the user's repository for testing. Use controlled
  fixtures or separately authorized disposable repositories for those gates.
- [ ] Review the complete diff for security and regressions. Fix substantive
  findings, update affected guides, and run `make test-all`, `make vuln-check`,
  `make semgrep-check` and `make docs-check` before push.
- [ ] Report tested commit and remaining live gates accurately. Verify GitHub PR
  mergeability after push; do not infer it from push success.

## Execution evidence

App registration, installation, narrowed token issuance and revocation passed.
The public cross-repository read negative probe returned HTTP 200: the exclusive
read-scope assumption failed. See [live evidence](../../experiments/github-app-live-acceptance.md).
Do not check off the repository-isolation gate or enable the runtime on this basis.

User clarification: retain all currently selected installation repositories.
Each Toolbox grant and token request must still name exactly one repository.
Never remove installation repositories as an implicit security fix.
