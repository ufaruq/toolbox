# Dynamic Client Onboarding Implementation Plan

> **For agentic workers:** Use superpowers:subagent-driven-development to implement this plan task-by-task. One writer in this worktree at a time; independent reviews are read-only.

**Status:** Implemented and verified at `21452fa`; see [verification](../../dynamic-client-onboarding-verification.md).

**Goal:** Dynamically registered Keycloak clients become owner-scoped Pending requests, then gain only explicitly dashboard-approved permissions.

**Architecture:** Retain the approved CallerProfile invariant and add a separate candidate table. Separate fully verified token identity from client admission; only owner-session mutations can promote a candidate. Opt-in Keycloak realm policies support anonymous OIDC registration without adding an OAuth server to Toolbox.

**Tech Stack:** Existing Go, PostgreSQL, Keycloak 26.8.2, embedded JavaScript UI, existing Docker/browser acceptance runner.

**Spec:** `docs/superpowers/specs/2026-11-08-dynamic-client-onboarding-design.md` (approved by user).

## Global Constraints

- Each owner manages callers for their own account; central administration is outside this change.
- An MCP credential cannot approve itself or increase its permissions.
- Preserve exact issuer/audience/signature/user/client validation, owner session/Origin/CSRF checks, and final revocation checks.
- No active Agent or grant is created for a pending candidate. Keep the existing approved CallerProfile schema invariant.
- Registration is opt-in and Keycloak-only. Static mode and direct Okta retain their current behavior.
- Reject reserved administrative/owner-login client IDs and client-credentials tokens, including on the candidate verification path.
- Add migrations; never rewrite applied migrations. No live provider configuration changes or hook bypasses.
- Run focused tests first and the full `scripts/test-all` gate before pushing. Report unavailable/skipped prerequisites honestly.

## Review Focus

- Repeated requests and concurrent dashboard decisions must not duplicate candidates or reactivate rejection/revocation (Tasks 1–2).
- An MCP bearer token plus a claimed owner ID must never become a management session (Task 2).
- Disabling onboarding must deny previously dynamically admitted callers unless separately statically configured (Tasks 1–2).
- Registration-token updates must be as restricted as initial registration; malicious protocol mappers cannot forge identity (Task 3).
- A stale dashboard response after sign-out/owner switch must not disclose candidates or apply an approval (Task 2 browser checks).

### Task 1: Candidate persistence and verified onboarding identity

**Files:** `internal/domain/domain.go`, new `internal/domain/caller_candidate.go`, `internal/store/validate.go`, `internal/store/postgres.go`, next additive `internal/store/migrations/*_caller_candidates.sql`, new `internal/store/caller_candidate_test.go`, `internal/identity/access.go`, `internal/identity/okta.go`, `internal/identity/keycloak.go`, `internal/identity/keycloak_test.go` (or focused sibling tests).

**Interfaces:**
- `domain.CallerCandidate`: string fields `ID, OwnerID, Issuer, UserID, ClientID, Status`; times `FirstSeenAt, DecidedAt`. Statuses `pending`, `rejected`, `approved`. State contains `CallerCandidates map[string]CallerCandidate`, initialized in `NewState`.
- `identity.AccessConfig.DynamicClientOnboarding bool`; `(*identity.Service).DynamicClientOnboarding() bool`; `(*identity.Service).VerifyOnboardingAccess(context.Context, string) (identity.Claims, error)`.
- `VerifyAccess` remains the static-allowlist path. `VerifyOnboardingAccess` only works when explicitly enabled for Keycloak, validates all token claims/signatures, and permits an eligible unknown client identity without authorizing it. Both reject reserved client identities. The server in Task 2 explicitly chooses the appropriate verification path.

- [ ] Write failing tests for candidate roundtrip, unique issuer/user/client tuple, owner/identity binding (including existing identity aliases), immutable identity/first-seen fields, decision timestamps/status, and duplicate concurrent identity rejection. Include PostgreSQL tests using existing opt-in fixtures and direct SQL invariant probes.
- [ ] Implement candidate persistence with additive migration and memory/PostgreSQL parity. Pending has zero DecidedAt; decisions have DecidedAt >= FirstSeenAt. Approved candidates must match an approved-profile identity binding (profile can later be disabled/expired); no candidate can rebind an identity or existing agent. Rejected→pending is permitted for explicit later human review; approved never returns to pending. Enforce constraints in store/SQL consistent with existing patterns.
- [ ] Write failing signed-token tests: static unknown denied; onboarding opt-in unknown accepted as identity only; disabled mode/Okta reject onboarding configuration/path; wrong signature/issuer/audience/scope/type/expiry and missing user/session rejected; reserved IDs/owner IDs/service-account tokens rejected. Preserve static client behavior.
- [ ] Implement the explicit candidate verification API, factoring common Keycloak verification rather than duplicating checks. Reject invalid provider/option combinations at construction.
- [ ] Run `go test -race ./internal/domain ./internal/store ./internal/identity`, report any opt-in skips, self-review and commit. Full database validation is repeated with real fixtures in final acceptance.

### Task 2: Owner dashboard admission and pending MCP flow

**Files:** `cmd/toolbox/mcp.go`, `cmd/toolbox/mcp_test.go`, `internal/server/agent_auth.go`, `internal/server/mcp.go`, `internal/server/callers.go`, new `internal/server/caller_candidates.go` and tests, `internal/server/web/workspace.js` and `workspace.html`, existing browser acceptance helpers/tests where appropriate.

**Consumes:** Task 1 candidate and verifier interfaces. Optional server identity extension `{DynamicClientOnboarding() bool; VerifyOnboardingAccess(context.Context,string)(identity.Claims,error)}` keeps existing static test identities compatible.

**Produces:** runtime setting `TOOLBOX_MCP_DYNAMIC_CLIENT_ONBOARDING=true|false` (default false, strict validation, Keycloak-only); `GET /v1/callers` adds owner-scoped `pending_callers` (including rejected entries to allow explicit reopen); `POST /v1/callers/pending/{id}/approve`, `/reject`, `/reopen` owner-only mutations. Approval accepts only `label, tools, duration_seconds`; identities derive from the stored candidate. Existing active profile controls remain authoritative.

- [ ] Write failing tests showing a fully verified unknown user's client produces exactly one Pending row, no Agent/CallerProfile/grant, and MCP 403 `CALLER_PENDING_APPROVAL`. An unknown/unlinked/disabled owner cannot enqueue. Invalid token cannot enqueue. Existing static-approved calls work unchanged.
- [ ] Implement onboarding resolution: verify first; within a transaction look for existing profile before candidate creation; active approved dynamic candidates permit profile resolution only when onboarding is on. Disabled/expired/rejected clients stay denied and never reset on reconnect. Store mutations must commit when returning the intentional pending denial (do not return an error that rolls back the candidate).
- [ ] Bound candidates to 64 total per owner and 4096 globally (including retained decisions), and new candidate attempts to 10/minute per verified owner. Idempotent retries must not append audit entries or bypass decisions. Return 429 for capacity/rate limits and 503 on repository failure, not a misleading invalid-token response. Do not store raw tokens. A fixed dashboard URL can accompany pending denial; no client-controlled redirects.
- [ ] Write and implement owner-only decisions with existing session, CSRF, Origin, and owner-scope checks. Atomic approval creates Agent/CallerProfile and marks candidate approved using verified stored binding; tools/duration use existing validation. Reject/reopen do not create agents. Double approval is deterministic and cannot duplicate; stale reject after approval cannot disable an approved profile implicitly.
- [ ] Extend existing panel with Pending/Rejected rows and explicit configure/approve, reject, reopen controls. Reuse tool/duration inputs, show exact verified client ID/issuer/first-seen, use textContent, and preserve uiEpoch guards. Show no default broad permission or vendor-verified label. Keep configured-client approval, rename, update, disable/enable workflows.
- [ ] Regression tests cover foreign owners, MCP bearer-only management, missing/incorrect CSRF and Origin, client-supplied identities, approve/reject races, repeated retries, quotas, disabled onboarding rollback, revocation/expiry, no document access without grant, and stale UI/owner switching. Add a browser scenario for Pending→approve/reject/reopen to the existing runner-enabled suite rather than an unexecuted standalone test.
- [ ] Run `go test -race ./internal/server ./cmd/toolbox ./internal/app`; run available focused browser scenario, recording prerequisites/skips; self-review and commit.

### Task 3: Restricted Keycloak dynamic registration and real acceptance

**Files:** `internal/keycloakrealm/realm.go`, focused registration renderer/tests, `cmd/toolbox/keycloak.go` and tests, `internal/app/keycloak_e2e_test.go` and focused test helpers, `tests/runner`/Makefile only if needed to ensure new scenarios run in the full gate.

**Interfaces:** add `DynamicClientRegistration bool` and `DynamicRegistrationTrustedHosts []string` to realm Config; CLI `TOOLBOX_KEYCLOAK_DYNAMIC_CLIENT_REGISTRATION=true|false`, `TOOLBOX_KEYCLOAK_DYNAMIC_REGISTRATION_TRUSTED_HOSTS` JSON string array. Existing default realm output stays restricted. Runtime onboarding flag from Task 2 is independently required.

- [ ] Research pinned 26.8.2 native registration policies and client policies in official upstream source, then write failing renderer/config tests for explicit opt-in, required bounded trusted hosts, forbidden wildcards/unsafe host patterns, PKCE S256, minimal scopes, restricted flows, zero mapper privileges, full-scope disabled, consent required, and registration quota. No auth secrets in error output.
- [ ] Implement compatible native realm policy composition for anonymous OIDC registration and registration-token updates. Require explicit trusted hosts/callback-host admission and exact submitted callbacks (HTTPS except loopback HTTP); no wildcard redirects. Limit registrations to 128 realm clients. Allow only required basic/mcp scope behavior, use operator-controlled audience mapper, and prevent requester-controlled identity/privileged mappers. Do not add a registration proxy or broader Keycloak service-account role. If native policies cannot enforce a requirement, report the exact gap before weakening it.
- [ ] Extend real disposable Keycloak acceptance: discover registration endpoint, register unknown public code client, reject absent/wrong PKCE, obtain valid user token, verify Pending/no tool execution, log into owner UI separately, approve then exercise exact-document grant/read/revoke. Test a second owner/client denial and update attempts that add wildcard redirect, service-account flow, dangerous mapper, or loosen PKCE. Test static/off-mode behavior.
- [ ] Native policies must reject insecure creation AND updates. Keep existing service-account/ID-token denial tests. Record exact pinned-image behavior; no live realm edits.
- [ ] Run renderer/CLI focused tests and `make keycloak-check` with isolated fixtures. Self-review and commit.

### Task 4: Documentation, complete acceptance, and whole-branch review

**Files:** `docs/keycloak-setup.md`, `docs/mcp-setup.md`, `docs/architecture/README.md`, `docs/security/README.md`, design status and implementation verification note; implementation/test files only for observed failures.

- [ ] Document opt-in registration policies and runtime flag, dashboard pending flow, owner-first prerequisite, rejection/reopen, rate/capacity limits, approved-client disable/expiry, and safe static-mode rollback. Distinguish app registration from owner approval and document grants; distinguish local tested compatibility from untested hosted clients.
- [ ] Run `make docs-check`, formatting, and focused regression tests for amended files.
- [ ] Run full `make test-all`, including real PostgreSQL/OpenBao, browser, Keycloak and MCP tests. Investigate failures and fix causes without loosening gates. Record exact revision/results and any live-provider limitations.
- [ ] Independent whole-branch review of candidate isolation, admission bypasses, mutable DCR metadata, token confusion, SQL parity, and test coverage. Address substantive findings, rerun affected verification, commit the completed work. Push/open a PR only if authorized and the required exact-commit pre-push gate passes; the earlier one-time hook bypass does not apply here.
