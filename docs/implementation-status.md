# Implementation and verification status

This page records evidence, not the task backlog. See the [roadmap](ROADMAP.md) for remaining work and the [handoff](HANDOFF.md) for continuation. Earlier results are preserved in the [historical ledger](history/implementation-checkpoints.md).

## Local Okta owner sign-in

PR #5 adds a loopback-only real Okta owner mode. Its [verification record](okta-verification.md) covers automated identity/session/browser checks and one-user live sign-in, application restart, logout and repeat login. A second live Okta user and public production acceptance remain open; Google/MCP runtime evidence is recorded in the current status section below. The checkpoint below is historical PR #2 evidence, not the current local Okta coverage.

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

## Current local runtime and deployment preparation

PRs #10 and #7 are merged. The executable supports real loopback Okta owner login,
Google OAuth/Picker and exact-document reads, plus an Okta-authenticated MCP client.
One real account completed the PKCE/scope checks, owner-approved Google read and
Codex MCP read; a different document was denied. Live revocation, disabled-client,
disconnect and second-client checks remain open. Synthetic automated tests cover
those paths. Eight-hour access tokens do not by themselves force fresh interactive
Okta authentication; that sign-in policy still needs verification.

PR #4 preserves those local modes while adding persistent container signing/pepper
keys, encrypted SQL credentials, restricted roles, bounded cleanup, conservative
retention, encrypted backups, recovery fencing, monitoring and an optional GCP VM
Terraform adapter. See [deployment verification](deployment-verification.md) for
revision-specific evidence. The container profile uses synthetic providers; hosted
production serving remains blocked pending real identity/provider wiring and public
HTTPS acceptance. Actual GCP provisioning, KMS/IAM, off-host backup delivery and
external alerts are unrun.

Earlier PR #2 limitations above are historical, not the current application feature
list. The full-state SQL adapter and additional tools/policies remain future work.

## Browser artifacts

The [runner instructions](../tests/browser/README.md) explain both scripts and artifact handling. CI uploads its own masked screenshots, metadata and service logs as `browser-e2e`. The [committed gallery](e2e-evidence/README.md) records capture source `5e34ca93624ba963f97c1b4fa86ffbaf0ebb2bc9`; it is historical illustration, not a capture of every later change. Only a successful full runner flow writes passing result metadata.
