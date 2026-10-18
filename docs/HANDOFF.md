# Implementation handoff

Deployment preparation now includes a persistent Docker/PostgreSQL stack, production-default KMS/local verification wrappers, key rotation, role separation, cleanup/retention, encrypted backup/restore and Make/Terraform tooling. See [deployment instructions](deployment-docker.md) and [recovery](recovery-docker.md). Production OIDC/live Google gates remain unfinished; cloud provisioning and live KMS are not locally verified.


**Current update:** the six comments on `3738412` and the additional initial-exchange rejection finding on `f6e9c7c` are fixed, with regression tests. The combined local run passed 301 Go tests/subtests without skips with real PostgreSQL/OpenBao, the Chromium fixture E2E, four delayed-review browser cases, and API smoke checks. CI runs the storage integration and both browser scripts; check it independently on the final pushed commit. See [comment links and current verification](implementation-status.md) and [browser runner](../tests/browser/README.md). GitHub API access remains blocked, so threads have not been replied to or marked resolved. Production human OIDC and live Google integration remain outstanding; no merge or deployment has occurred. The checkpoint details below describe earlier work.

## Where the work is

Branch: `feat/user-delegated-drive-mvp`, PR [#2](https://github.com/ufaruq/toolbox/pull/2), based on existing main. The user marked it ready for review; preserve that status. Design PR #1 has merged. History is incremental, with no squash or force update.

- `e361c3be25ddae940e67381151e3c22ba0ce93de`: identity/delegation/strict JSON foundations.
- `ad0da682fcd6b7776e7b19e39f851328babf0705`: full local WIP preserved, including the deliberately failing regression.
- This documentation commit supplies a runnable entry point and continuation checklist.

## What is implemented

The service distinguishes owner browser sessions, independently authenticated agent credentials, user-owned Google connections, and explicit immutable grants. An agent requests an exact document read, receives an approval URL, and polls/mints a short-lived delegation token after owner approval. Connection alone gives no agent authority. Approval records the connection epoch; issuance, dispatch/retries and final buffered return check current grant/credential/connection state. Writes and unrecognized inputs fail closed. Audit records actor and human subject without provider tokens or document contents.

Adapters include PostgreSQL relational constraints and atomic audit, OpenBao KV-v2 compare-and-set, bound one-use OAuth/PKCE transactions, a fixed Google identity/token adapter, fixed Drive metadata plus plain-text export, and refresh coordination with durable intent and generation-aware 401 recovery. Synthetic fixtures allow local development without real credentials.

## Historical lifecycle regression (fixed)

File: `internal/tokens/review_test.go`.
Test: `TestReviewDisconnectDuringRotationRevokesNewCredential`.

A refresh succeeds with a new token after a concurrent disconnect changes the connection epoch/status. `internal/tokens/manager.go` returns at the live-state check before preserving the new token. Cleanup therefore sees the old token in the durable refreshing intent. If that old token is invalid, provider revocation may be treated as terminal, even though the new token was not revoked.

Required behavior:

1. Retain a known successful refresh response durably as a cleanup-only generation, bound by CAS to the original intent, operation ID and identity. Never reactivate the disconnected connection or release credentials to the caller.
2. Revoke the returned current credential during cleanup, retaining encrypted cleanup material if revocation fails.
3. Do not report cleanup complete for an unresolved `refreshing` intent. Its provider-side outcome may be unknown or still in flight.
4. Preserve CAS/epoch fencing, and cover concurrent cleanup, failure/retry, late responses and lost-lock cases. Revocation cannot undo already dispatched provider work.
5. Rerun the regression, token race suite, complete API suite and real PostgreSQL suite before calling the fix verified.

Also review successful refresh responses with changed/missing required scopes: known rotated credentials should not be silently discarded before cleanup simply because connection activation is denied.

## Verification ledger

### Passed before the new regression

- Focused JWT/credential and strict-JSON tests.
- OAuth protocol/identity/callback/PKCE fixture and persistence-failure race tests.
- Fixed Drive method/host/path/query, restricted metadata, size, redirects and retry tests.
- Token concurrency, durable intent, CAS reconciliation, generation-aware 401, isolation and revocation tests.
- Full `go test -race ./...`, including actual PostgreSQL **17.11** and API acceptance.
- API allowed read; denied write/unknown fields/other document/other agent; expired/revoked grant; credential revocation; epoch mismatch; final content discarded after mid-fetch revocation; approval replay and CSRF checks; audit hygiene.
- Independent review found no high-confidence owner/agent authorization bypass in the reviewed wiring.

### Failed / incomplete

- The new rotation/disconnect cleanup regression fails. This is intentionally committed as evidence.
- Interactive cloud-browser navigation to both loopback/localhost was blocked with `ERR_BLOCKED_BY_CLIENT`. No visible browser flow was verified.
- Final aggregate checks after later provider-error mapping/readiness edits were not completed; do not reuse earlier results as proof for the final checkpoint.
- A polling attempt for the final local command returned an automatic approval-review capacity error. Its outcome is unverified; the work was preserved rather than retried via another execution route.

### Not run or not implemented

- Production human OIDC: **not implemented**. The current owner login is an explicitly local fixture. Add configurable trusted OIDC login and server-side sessions before production.
- Real Google app/account consent, actual S256 negative tests, exact-scope ID-token issuance, Picker selection/browser exposure, multi-tab fidelity and restricted/resource-key/shared-drive scenarios: **not validated**. See the Google setup document.
- Real deployed OpenBao workload policy, retained-version destruction/recovery and complete Compose stack: **not validated**.
- Automated browser E2E suite and associated CI artifacts: **not completed**.
- Production deployment, hosted identity, durable signing/pepper rotation, distributed rate limits, scoped SQL queries, audit retention/reconciliation and operational recovery: **not completed**.

## Product flow to preserve

The agent supplies requested actions, exact documents and duration. Toolbox gives it a trusted approval link. The user signs into Toolbox through the chosen configurable OIDC provider, reviews agent + connection/account + documents/actions + expiry, and approves. Subsequent calls are checked automatically against live approved rights. New rights or more time require a new reviewed grant. Keep user login, agent authentication and Google OAuth separate.

## Suggested continuation order

1. Fix the cleanup regression and verify it, without weakening tests.
2. Implement configurable owner OIDC and secure session lifecycle with a test IdP; keep the mock fixture explicitly isolated.
3. Finish browser E2E against a permitted local browser/test environment; include interrupted/repeated review and negative paths.
4. Complete local Postgres/OpenBao integration and CI jobs; verify checks on the exact new commit.
5. Run the explicitly authorized Google spike and close the documented production decisions.

Keep this draft unmerged and undeployed until those gates are reviewed. No live credentials or account provisioning are part of this checkpoint.
