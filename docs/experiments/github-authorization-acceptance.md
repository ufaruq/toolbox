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

## Corrected live command — `8737f8a`

`make github-live-write-check` passed on the integrated runtime fix. It verified
installation discovery, `README.md` read, public locator mismatch denial, a new
dedicated branch, a two-file commit with **both** readbacks, conditional update
and readback, and draft PR [#39](https://github.com/ufaruq/toolbox/pull/39) creation,
read, closure and closed-state readback. Nothing was merged. The earlier stale
command also created [#38](https://github.com/ufaruq/toolbox/pull/38); that draft was
closed through the GitHub connector after identifying its branch, without retrying
the same mutation. Synthetic acceptance branches are retained for inspection.

The final branch security review identified that GitHub's Issues endpoint also
returns PRs. That action requires an explicit preflight classification guard so
issue-only grants cannot bypass PR-specific scope checks. The fix and final gate
are recorded in the subsequent checkpoint.

## Final review and acceptance

On `8737f8a`, `make test-all` passed 1,187 tests/subtests with no skips, plus the
standalone browser fixtures and review-race checks. This includes the corrected
Linux Docker gateway test. Evidence: `/private/tmp/toolbox-test-evidence.onujdx`.
A prior run during integration compiled a changing working tree and failed; it
is not counted as a passing revision.

The final review's issue/PR finding was fixed in `6e7649a`: issue reads require
trusted issue metadata matching the requested number and repository, and reject
any PR marker before issuing the operation token or dispatching MCP. Regressions
cover ordinary issues, PR/fork markers, missing or mismatched metadata and provider
failures. The four focused credential/runtime/policy/MCP packages passed with the
race detector. The installed pre-push gate must still validate the exact final
committed snapshot; its result is reported on the implementation PR.

`make vuln-check` found no reachable Go vulnerabilities; it reported one advisory
in a required module outside the imported/called code. `make semgrep-check` found
zero findings in its configured rules. These scans do not establish absence of
application vulnerabilities. Real PR review/merge and live owner-browser approval
through to MCP remain untested; review/merge were not exercised against main.
