# GitHub authorization acceptance — 8 November 2026

Revision: `e78e50acd418cbccbd43663a3cd2d593801a5c95`.

This checkpoint validates the owner/application boundary before the real runtime
adapter is integrated. It is not a release or live GitHub write claim.

- `make check`: formatting, vet, build and ordinary race tests passed. Opt-in
  integration suites were separately run below.
- `make github-browser-check`: real Chromium and Toolbox HTTP UI, synthetic
  provider; connection, approval link, exact scope review, approval, allowed read,
  revoke and denied reuse passed. Agent HTML-like names rendered as text; narrow
  viewport did not overflow. A rejected query-string approval route was reproduced
  and replaced with `/github/approve/{request-id}` before this revision.
- `make test TEST_PACKAGES=./internal/store TEST_RUN=TestGitHub` with the dedicated
  disposable PostgreSQL DSN: memory and PostgreSQL invariants passed, including
  raw SQL null fields, future epoch and approval scope mismatch rejection.
- `make test-all`: 1,140 tests/subtests passed with **no skips**. Included real
  Keycloak and Docker Gateway with controlled providers, OIDC/Workspace/GitHub
  browsers, PostgreSQL/OpenBao, race tests, build and standalone fixture/review-race
  browser checks. Local evidence: `/private/tmp/toolbox-test-evidence.6Bn9Rf`.

The policy review fixed directory-replacement scope expansion in multi-file
writes and acceptance of whitespace-only single-file updates. The subsequent
owner/auth/storage/UI review found no concrete isolation bypass but requested
machine-readable action argument schemas for MCP clients; that fix remains a
separate follow-up at this checkpoint.

The registered App's token issuance/revocation evidence is recorded in
[GitHub App live acceptance](github-app-live-acceptance.md). It does not establish
live MCP operations, all mutation behavior, or an atomic repository-name binding.

## Runtime integration checkpoint

After `31d4ff3`, focused credential, policy, store, server and MCP schema tests
passed. The MCP discovery follow-up publishes action-specific closed schemas.

Using the installed App and the real pinned Docker MCP gateway, the explicit
operator check read `main:README.md` and rejected an unrelated public repository
locator. The write check created a dedicated `toolbox-acceptance/` branch, committed
two synthetic files, read them back, and performed a conditional single-file
update. Draft PR [#36](https://github.com/ufaruq/toolbox/pull/36) was created, but
the command failed while interpreting its returned PR number. Before any retry,
the existing PR was identified, read and closed through the same MCP runtime.
No merge occurred. The create-result handling is being corrected separately; this
checkpoint is not a full successful write-command claim.

These operator checks do not exercise a live browser owner approval. Synthetic
browser tests exercise that application authorization flow independently.
