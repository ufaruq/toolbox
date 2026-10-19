# Toolbox roadmap

This is the current index of remaining work. It supersedes the pending-work lists in the [historical checkpoint ledger](history/implementation-checkpoints.md). Technical requirements live in the linked references; verification results live in [implementation status](implementation-status.md).

The application baseline is [PR #2](https://github.com/ufaruq/toolbox/pull/2) at `621fc2599bdae96661c001999fa0cc311a0e09af`. PR #2 has merged into `main` at `6279f3aab67465aadf5b1ee07f50ed8a99d4bcb4`; this documentation follow-up now targets `main`. A completed item below describes implemented behavior at that revision, not a production deployment. Unchecked items need implementation, validation or an explicit recorded decision.

## Completed baseline

- [x] Go service, trusted owner approval UI and custom HTTP agent API for one tool: reading an approved native Google document as plain text.
- [x] Separate owner sessions, agent credentials, provider connections and exact-document grants; short-lived delegation tokens, live authorization checks, expiry, revocation and disconnect.
- [x] PostgreSQL and OpenBao adapters, audit records, OAuth/PKCE transaction handling, Google OAuth/Drive library adapters, refresh coordination and credential cleanup. The executable wires simulated identity and Google providers only.
- [x] Regressions for the refresh/disconnect lifecycle, all six comments on `3738412`, and the later definitive initial-exchange rejection on `f6e9c7c`, including stale UI review responses, JWT expiry rounding and missing invocation audits.
- [x] Fixture API, race, real PostgreSQL/OpenBao and Chromium checks, with CI and masked screenshot artifacts. See the [evidence and its limits](implementation-status.md); production OIDC and live Google have not passed.

## Milestones and dependencies

| ID | Deliverable | Depends on | Completion gate |
| --- | --- | --- | --- |
| [M1](#m1-real-owner-sign-in) | Real owner sign-in | Select a trusted OIDC provider | Real login/session lifecycle and negative identity tests pass. |
| [M2](#m2-live-google-document-flow) | Live Google document flow | Dedicated test configuration; M1 for the complete human flow | Real consent, Picker, approval, read and denial checks pass with sanitized evidence. |
| [M3](#m3-controlled-pilot-deployment) | Controlled pilot deployment | M1 and M2 | Production configuration, secret lifecycle, recovery and hosted browser acceptance pass. |
| [M4](#m4-larger-workloads) | Larger workloads | Preserve M1–M3 guarantees | Scoped storage and distributed controls meet a recorded workload target. |
| [F1](#f1-agent-client-integrations) | Agent client integrations | Choose an initial client; use the existing HTTP authorization boundary | Client integration tests pass; MCP is an option to evaluate. |
| [F2](#f2-more-tools-and-providers) | More tools and providers | A separately reviewed tool contract | Each new action has explicit permissions, limits and acceptance tests. |

M1 and the isolated Google configuration/protocol spike in M2 can progress independently. The full live user flow needs both. F1 and F2 are future product work, not prerequisites for the initial HTTP-based pilot. M4 gates broader workloads; it does not imply the current adapter is ready for unrestricted production traffic.

## M1: Real owner sign-in

References: [Okta setup](okta-setup.md), [identity boundary](google-setup.md#1-keep-owner-identity-separate), `internal/server`, `internal/domain`, and `cmd/toolbox/main.go`.

The local Okta owner-only mode and automated protocol/session/browser tests are implemented in PR #5. Live Okta acceptance is still pending; the checklist below distinguishes implementation from that remaining gate.

- [ ] Record the selected OIDC provider, trusted issuer, client/audience, callback origins and stable issuer/subject mapping. Toolbox login and the connected Google account must remain independent.
- [x] Implement the OIDC authorization callback and session integration, validating signatures, issuer, audience, nonce, state and lifetime before establishing a first-party owner session.
- [x] Complete secure session creation, expiry and logout/revocation with CSRF and same-origin checks. Keep agent authentication independent of browser sessions.
- [x] Add an explicitly configured non-fixture startup path that fails closed for missing identity settings and never exposes fixture login/authorization routes. Keep the local fixture mode available for development.
- [ ] Verify valid sign-in and sign-out, expired/replayed transactions and sessions, wrong issuer/audience/nonce, invalid signatures, cross-owner access and CSRF. Exercise the flow with a test IdP in the browser, then record acceptance against the chosen provider.

**Done when:** a real user can establish and end an authenticated Toolbox session, a second user cannot access the first user's state, and automated negative identity/session tests pass. The hosted flow is verified again in M3.

## M2: Live Google document flow

References: [Google setup and release gates](google-setup.md), `internal/oauth`, `internal/connectors/gdrive`, `internal/app/integration.go` and the approval UI in `internal/server/web`.

- [ ] Configure a dedicated Google test project, OAuth web client, exact callbacks, test users and Picker project/API settings. Inject credentials through the server's secret mechanism; record only non-secret configuration identifiers.
- [ ] Complete the [real PKCE enforcement spike](google-setup.md#3-mandatory-pkce-enforcement-spike): independent fresh-code positive, missing-verifier and wrong-verifier cases, followed by another positive case. Keep `PKCEValidated` false until the gate passes.
- [ ] Verify ID-token issuance and exact granted scopes for the intended `openid` plus `drive.file` request. If the minimal request fails, record and review the identity/scope decision before changing it; do not silently broaden scopes.
- [ ] Wire the existing real Google OAuth, refresh/revocation and Drive metadata/export adapters into the non-fixture runtime. Preserve the fixed endpoints, bounded requests, generation coordination and exact-document dispatch checks.
- [ ] Implement trusted owner document selection with Google Picker and bind selection to the reviewed connection/account. Review the required access-token exposure to the owner browser, its expiry and in-memory handling; provider refresh tokens must never reach the browser or agent. `drive.file` itself is not read-only.
- [ ] Run the full human/agent browser flow with a synthetic document in the real test account: consent, selection, request, review, approval, permitted read, other-document denial, grant revocation and disconnect. Verify provider credentials are absent from agent responses, logs and artifacts.
- [ ] Complete live checks for cross-account consent, re-consent/missing refresh tokens, revoked provider access, restricted downloads, resource keys/shared drives and multi-tab document fidelity. Record observed limitations and resolve any that prevent the supported document-read contract.
- [ ] Record the project's consent-screen/test-user/token-lifetime requirements and any publishing or verification needed for the intended pilot users.

**Done when:** the configured live flow and its negative cases pass with sanitized results tied to the actual project/client configuration. Fixture and mocked HTTP passes do not close these items. A failed PKCE or scope/identity spike can require a design change rather than a configuration adjustment.

## M3: Controlled pilot deployment

References: [storage permissions and limits](storage.md), [Google persistence/failure behavior](google-setup.md#5-persistence-and-failure-behavior), the [merged design](https://github.com/ufaruq/toolbox/pull/1), and `cmd/toolbox/main.go`.

- [ ] Select the hosting topology, operational owner and workload identity. Document responsibility for incidents, credential access, revocation and deletion requests, and the bounded pilot workload. Confirm grant/credential lifetimes, output limits and retention defaults rather than treating proposed design values as approved settings.
- [ ] Implement and document a non-fixture deployment with HTTPS, exact callback/origin configuration, private store access, verified database/OpenBao TLS, reviewed egress/proxy policy and no fixture routes or dev credentials.
- [ ] Persist signing keys and the agent-credential pepper across restarts. Specify and test key/pepper rotation and recovery, including what happens to existing credentials and short-lived delegation tokens.
- [ ] Configure least-privilege database and OpenBao workload roles, separate migration/retention privileges and production secret-store authentication. The Compose dev stack and its `fixture-only` values remain development fixtures.
- [ ] Implement expiry/orphan cleanup for OAuth secrets and destruction of retained secret versions under the reviewed retention policy. Preserve unresolved operations and credentials still needed for retryable revocation; current-version deletion alone is not erasure.
- [ ] Document and test recovery for crashes, store outages, unknown provider outcomes, lost locks, failed revocation and committed writes with lost acknowledgments. Reconcile started-but-unfinished invocation audits without inventing successful delivery, silently replaying a non-idempotent operation or claiming cross-system exactly-once behavior.
- [ ] Define audit retention and incident investigation procedures. Add sanitized operational logs, cleanup/backlog and dependency health monitoring, readiness checks and alerts for failures requiring intervention.
- [ ] Document agent onboarding through the existing HTTP API: independent credentials, approval links, polling/token issuance, invocation and credential rotation/revocation. Verify the guide with a pilot agent without requiring an MCP adapter.
- [ ] Configure and verify per-user, per-agent and per-connection limits and bounded export/refresh concurrency. Keep the pilot on one replica with explicit workload bounds until distributed rate limiting and multi-replica verification in M4 are complete.
- [ ] Exercise backup and restore, migrations, restart/upgrade and credential-revocation procedures on the selected topology; record an operational runbook and recovery evidence.
- [ ] Run hosted browser and API acceptance using real owner identity and the live Google test configuration, including logout, denial, revocation, disconnect, restart behavior and recovery. Keep fixture and live results separate in the verification record.

**Done when:** a controlled hosted pilot satisfies M1/M2, survives the documented restart/failure cases, uses durable secrets and restricted store roles, and has an operational owner with tested recovery procedures. This roadmap is not evidence that any deployment has occurred.

## M4: Larger workloads

References: [snapshot adapter limits](storage.md#supported-slice), repository transactions and authorization acceptance tests.

- [ ] Record expected tenant/agent counts, request concurrency, data/audit growth and latency/availability targets before selecting capacity changes.
- [ ] Replace full-state snapshots and the database-wide application transaction lock with scoped, indexed queries and explicit transactional methods. Preserve owner/resource constraints, immutable grants, atomic audit writes and current primary-state authorization checks.
- [ ] Add distributed rate limits and resource bounds across replicas. Verify that adding replicas does not permit refresh replay, bypass revocation or weaken exact-document rights.
- [ ] Implement scalable audit retention/pruning under the M3 policy with separately controlled privileges; test that retention preserves required investigation and ownership guarantees.
- [ ] Run load, growth, contention and multi-replica failure tests against the recorded workload targets, alongside the authorization/refresh regression suites.

**Done when:** measured capacity meets the agreed workload and the existing security/cleanup properties hold under concurrency and failures.

## F1: Agent client integrations

- [ ] Choose a real agent client and document onboarding, independent agent credential handling, approval-link presentation, polling/token issuance and error handling using the existing HTTP API.
- [ ] Evaluate whether that client needs an MCP adapter, an SDK/example or direct HTTP support; record the transport and authentication contract before implementation.
- [ ] Test the chosen client through request, owner approval, bounded execution, expiry and revocation, including other-agent/document denial. Never hand provider credentials to the agent or widen a grant through the transport.

**Done when:** the selected client completes the existing permission flow and its denial cases. The fixture agent console is not evidence of this integration; MCP is not currently implemented or selected.

## F2: More tools and providers

- [ ] Select each next provider/action and define its manifest, explicit rights, resource selection, limits and fixed execution plan in a separate proposal.
- [ ] Implement its adapter, owner review copy and provider-specific acceptance tests. Writes, broader document rights or longer access require new reviewed permissions; existing read grants cannot acquire them implicitly.

**Done when:** each added tool has its own working user flow and positive/negative provider acceptance evidence. No additional provider or write action is committed by this roadmap.

## Keeping the documentation current

| Document | Responsibility |
| --- | --- |
| [README](../README.md) | What runs today and how to start it. |
| [This roadmap](ROADMAP.md) | Single current backlog, dependencies and completion criteria. |
| [Handoff](HANDOFF.md) | Entry point for the next session and pointers to the next milestone. |
| [Implementation status](implementation-status.md) | Revision-specific passed, failed, blocked and unrun checks. |
| [Google setup](google-setup.md) | Provider configuration, protocol constraints and live acceptance procedure. |
| [Storage](storage.md) | Current persistence guarantees, permissions and operating limits. |
| [Browser runner](../tests/browser/README.md) | Repeatable fixture browser commands and artifact handling. |
| [Evidence gallery](e2e-evidence/README.md) | Historical masked screenshots with their actual capture metadata. |
| [Historical ledger](history/implementation-checkpoints.md) | Preserved earlier checkpoints, never the current task list. |

The [design artifacts merged through PR #1](https://github.com/ufaruq/toolbox/tree/main/docs/design) describe the intended architecture and their own design-review evidence. Their generated Markdown/PDF/SVGs are not application completion reports and are not regenerated for status-only changes.

Each follow-up PR should identify its roadmap item, update its completion evidence and the handoff, and leave unchecked requirements visibly pending. A live check needs a source revision, environment/configuration identifiers, actual result and limitations. Never include secrets or treat a fixture result as a live-provider pass.
