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
