# Implementation and verification status

This page records evidence, not the task backlog. See the [roadmap](ROADMAP.md) for remaining work and the [handoff](HANDOFF.md) for continuation. Earlier results are preserved in the [historical ledger](history/implementation-checkpoints.md).

## Recorded application checkpoint

Source: [`621fc2599bdae96661c001999fa0cc311a0e09af`](https://github.com/ufaruq/toolbox/commit/621fc2599bdae96661c001999fa0cc311a0e09af), [implementation PR #2](https://github.com/ufaruq/toolbox/pull/2), now merged into `main` at `6279f3aab67465aadf5b1ee07f50ed8a99d4bcb4`. [Hosted CI succeeded for this application head](https://github.com/ufaruq/toolbox/actions/runs/39105338114).

Documentation-only follow-ups do not extend the recorded application or live-provider coverage. Check CI independently for each later revision.

| Check | Result at the recorded checkpoint | Scope and limits |
| --- | --- | --- |
| Formatting, `go vet ./...`, `go build ./...` | Passed | Final committed application revision. |
| `go test -race -count=1 ./...` | Passed: 301 tests/subtests, no failures or skips | Actual PostgreSQL 17.11 and OpenBao 2.4.1 enabled; synthetic provider inputs. |
| Chromium fixture browser E2E | Passed | Actual approval UI, allowed exact-document read, denials, revocation, disconnect and audit; simulated identity and Google. |
| Delayed-review browser regressions | Passed: four cases | Request/connection changes, including away-and-back; stale response cannot enable approval. |
| API smoke checks | Passed | Rebuilt fixture service with PostgreSQL/OpenBao; login, synthetic OAuth, approval, read, denial, revocation and disconnect. |
| Independent review of the comment fixes | No further actionable findings | Reviewed lifecycle/CAS, token expiry, UI and invocation audit changes. |
| Hosted CI | Passed | Storage integration/race suite, build and both fixture browser scripts. |

There were no remaining failures in these final recorded checks. Earlier deliberate failing regressions and interrupted runs are historical evidence, not current failures.

## Review findings addressed

| Comment | Implemented correction |
| --- | --- |
| [Post-exchange lock failure](https://github.com/ufaruq/toolbox/pull/2#discussion_r4305865495) | CAS-bound cleanup preserves known issued credentials using a fresh detached deadline after lock failure. |
| [Definitive invalid grant on refresh](https://github.com/ufaruq/toolbox/pull/2#discussion_r4305865499) | Known rejection resolves to cleanup-only state; unknown outcomes stay fenced. |
| [Definitive rejection of initial exchange](https://github.com/ufaruq/toolbox/pull/2#discussion_r4306002633) | Empty `ErrInvalidGrant` resolves the exact intent into cleanup-only state so disconnect can finish; unknown responses remain fenced. |
| [Stale review response](https://github.com/ufaruq/toolbox/pull/2#discussion_r4305873611) | Pending reviews bind request, connection and invalidation generation. |
| [Fractional expiry](https://github.com/ufaruq/toolbox/pull/2#discussion_r4305873620) | Token issuance requires a future serialized JWT expiry second. |
| [Missing denial audits](https://github.com/ufaruq/toolbox/pull/2#discussion_r4305873628) | Denials commit under authenticated ownership without untrusted resource identifiers. |
| [Cancelled terminal audits](https://github.com/ufaruq/toolbox/pull/2#discussion_r4305873635) | Bounded detached failure audits cover cancellation, slot timeout and final-gate failure; write failures fail closed. |

Regression tests accompanied each fix. This records code changes, not GitHub thread resolution.

## Blocked and unrun

- **Blocked in the working environment:** GitHub API access. Inline replies and thread resolution were not performed; no account-wide quota conclusion is inferred from that network restriction.
- **Not implemented:** production owner OIDC, real Picker UI and non-fixture runtime wiring. Real Google library adapters exist; the current executable still uses fixture providers.
- **Unrun:** live Google consent, PKCE enforcement, exact-scope/ID-token issuance, Picker, Drive acceptance and real owner sign-in. Local mocks and fixtures do not close these gates.
- **Unrun or incomplete:** hosted deployment, durable key/pepper lifecycle, production workload/store policies, secret-history/orphan cleanup, operational audit reconciliation, backup/restore and recovery validation.
- **Future scope:** external agent client/MCP integration and additional tools/providers. Current agent access is a custom HTTP API; supported tool behavior is one approved native document read as plain text.

The roadmap maps these gaps to M1–M4 and F1–F2. PR #2 is merged. No production readiness, deployment or live credential provisioning is claimed by this evidence.

## Browser artifacts

The [runner instructions](../tests/browser/README.md) explain both scripts and artifact handling. CI uploads its own masked screenshots, metadata and service logs as `browser-e2e`. The [committed gallery](e2e-evidence/README.md) records capture source `5e34ca93624ba963f97c1b4fa86ffbaf0ebb2bc9`; it is historical illustration, not a capture of every later change. Only a successful full runner flow writes passing result metadata.
