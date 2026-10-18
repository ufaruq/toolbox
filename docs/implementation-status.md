# Review fixes and current local verification

All three findings from the review of `5d2dd4a` are addressed:

- Initial OAuth exchange now records a durable, operation-bound intent before contacting the provider. Disconnect cleanup stays pending while issuance is unresolved. Late responses, cancelled callers, expired sessions and rejected identity/scope results preserve known credentials for cleanup without activating access.
- Google token parsing returns safely parsed credentials alongside validation errors. Both exchange and refresh paths persist those results as cleanup-only. Broader or explicitly empty scopes remain rejected; an omitted refresh scope inherits the stored grant. When no usable new refresh credential exists, cleanup retains the known new access credential rather than relying on an older refresh credential.
- The PostgreSQL backend-loss test identifies its exact database/advisory-lock key, waits for that backend to terminate and proves an unrelated same-application session survives. It no longer depends on a special application name to execute.

## Verification for these fixes

- Passed: formatting, `go vet ./...`, `go build ./...`, and full `go test -race -count=1 ./...`: **221 tests/subtests passed, zero failures or skips**, with actual fresh PostgreSQL 17.11 and OpenBao 2.4.1.
- Passed: targeted backend-loss regression three times, plus focused OAuth/token race tests. Regressions cover initial exchange/disconnect, cancelled or expired owner sessions, exact CAS binding, uncertain writes, rejected/malformed token responses, revocation failure/retry, and known access-only cleanup.
- Passed: rebuilt fixture service with actual PostgreSQL/OpenBao, exercising login, synthetic OAuth, review/approval, exact-document read, other-document denial, revocation and disconnect through the API.
- Passed: automated headless Chromium browser E2E twice consecutively on that service. The actual UI flow covers trusted approval navigation, interrupted review/reload, repeated approval rejection, successful A read, denied B read, revocation, request denial, disconnect, audit evidence/redaction and JavaScript error checks. See `tests/browser/README.md`.
- Independent review of the full PR and final lifecycle changes found no further high-confidence actionable defect. The CI workflow now runs the real-store and browser checks instead of silently skipping integration settings.
- GitHub CI status must be checked on the final pushed commit; local results are not a CI result.

The project remains a draft. **Production human OIDC is unimplemented, and live Google consent/PKCE/Picker/Drive validation remains unrun.** Production secret retention, workload policies, operational recovery and deployment validation remain release gates. No live accounts/apps were provisioned; nothing was merged or deployed.

The earlier checkpoint records below are historical and superseded by this section.

---

# Previous continuation: refresh/disconnect cleanup fixed locally

The original WIP checkpoint below is retained as historical evidence. Its known refresh/disconnect regression is now fixed; the project remains draft and is not ready to merge or deploy.

- Successful refresh responses are CAS-bound to the original intent, identity, epoch and operation. Responses rejected for disconnected state, scope loss, missing access token or expired access are retained as a cleanup-only generation. They cannot authorize dispatch or reactivate a connection.
- Bounded detached persistence preserves a known result after caller cancellation. Exact-response reconciliation handles a committed write whose response was lost. A failed/uncertain write remains fenced.
- Cleanup never overwrites an unresolved refreshing intent or reports it complete. Late responses after lost session locks can resolve their original CAS intent. Failed provider revocation retains the rotated refresh credential for retry.
- PostgreSQL API acceptance now uses a fresh schema per run. Repeated runs previously could select stale connections whose ephemeral fixture secrets were gone.

## Previous local verification

Using checksum-verified Go 1.27.2, PostgreSQL 17.11 and OpenBao 2.4.1:

- Passed: formatting, `go vet ./...`, `go build ./...`, and `go test -race -count=1 ./...`: 185 tests/subtests passed, zero failures or skips with both integration settings enabled.
- Passed: the original failing regression, rejected-rotation/retry/cancellation/write-outcome tests, late response after simulated session lock loss, actual OpenBao KV-v2 CAS and rotated-token cleanup, full API acceptance and PostgreSQL repository/session-loss tests.
- Passed: PostgreSQL full API acceptance twice consecutively, demonstrating repeatability after isolation correction.
- Passed: running fixture executable backed by actual PostgreSQL and OpenBao: readiness, fixture login/OAuth, trusted review/approval, allowed exact-document read, denied other document, grant revocation and disconnect. Provider data and identities were synthetic.
- Failed then fixed: the documented refresh/disconnect regression; repeat-run PostgreSQL API fixture isolation. No remaining failures in the selected local checks.
- Not implemented: production human OIDC sign-in. The executable remains explicitly fixture-only.
- Unrun: automated browser E2E, live Google consent/PKCE/Picker/Drive scenarios, production OpenBao policy/retention and deployment validation. No live account/app or secrets were provisioned. Local adapter tests do not close these release gates.
- GitHub CI for new continuation commits must be checked separately; local checks are not a CI result.

---

# WORK IN PROGRESS: NOT READY TO MERGE OR DEPLOY

This checkpoint preserves the implementation for review. It deliberately includes a known failing regression and is not a completed MVP or a final passing test result.

## Checkpoint 2: preserved implementation

The working tree includes the Go fixture service and approval UI, separate agent authentication, durable approval grants and scoped tokens, exact-document read dispatch, Postgres storage, OpenBao KV-v2 adapter, OAuth lifecycle, and synthetic-provider acceptance tests. Production human OIDC is not implemented; the executable explicitly requires `TOOLBOX_MODE=fixture`. No live Google account or app was provisioned.

### Known failing regression

`internal/tokens/review_test.go: TestReviewDisconnectDuringRotationRevokesNewCredential` fails. When disconnect changes connection state during a successful refresh, the manager currently drops the returned rotated token. Cleanup can revoke only the old token and may incorrectly report completion. Toolbox execution remains blocked, but provider-side cleanup is incomplete. Preserve the returned generation as CAS-bound cleanup-only state, never reactivate the connection, and keep unresolved refresh intents pending before considering this fixed.

### Verification evidence and limits

- Earlier full Go race tests and the API acceptance flow passed with actual PostgreSQL 17.11 and synthetic Google/OIDC/secrets.
- Covered allowed read, denied writes/unknown inputs, other documents/agents, expiry, revocation, credential revocation, epoch changes, and final buffered-content discard after revocation.
- The new failing review regression was added after that passing run. Later provider-error mapping and readiness edits have not received final aggregate verification.
- Interactive cloud-browser testing was attempted, but localhost navigation returned `ERR_BLOCKED_BY_CLIENT`. No browser end-to-end pass is claimed, and no Playwright deliverable was completed.
- Local execution then hit an automatic approval reviewer capacity limit. Execution was paused rather than bypassed; this connector-only commit preserves the WIP under the existing publication authorization.
- This exact checkpoint has not been certified by CI. A failing check from the intentional regression is expected until fixed.

### Remaining work

Fix and reverify rotation/disconnect cleanup; implement configurable human OIDC login; finish browser E2E tests and supporting CI; complete README/development guidance; run final formatting, vet, race, actual Postgres/OpenBao integration and build checks; inspect CI for the exact final commit. Real Google scopes/PKCE/Picker/account/restricted-download validation remains a separate release gate.

No merge, deployment, live credential creation or app provisioning is authorized by this checkpoint.

---

# Implementation status

This separate implementation PR follows [design PR #1](https://github.com/ufaruq/toolbox/pull/1) at commit `0851595a4238359b25e8426b45878f6e5fb5a0ee`. The design has not been merged or modified by this implementation.

## Increment 1: identity and authorization primitives

- Separate agent credential format with 256-bit random secrets and keyed hashes.
- Five-minute Ed25519 delegation JWTs with fixed issuer, audience, algorithm, token type, agent, owner, grant, resource and output constraints.
- Strict JSON parsing rejects duplicate keys, unknown arguments, case aliases and trailing data.
- Shared non-secret domain model and transactional repository contract.

Checked locally: focused security and strict JSON tests pass with official checksum-verified Go 1.27.2. Integration, provider, browser and production validation are not claimed at this checkpoint.

## Release gates

Production human OIDC provider/hosting remain unselected. Real Google client/Picker configuration, positive and negative PKCE enforcement, restricted downloads and document fidelity require a separately authorized test project and account. Fixture tests are not live Google validation. No deployment, merge, live credential generation or OAuth application provisioning is included.
