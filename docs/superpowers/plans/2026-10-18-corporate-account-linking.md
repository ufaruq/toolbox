# Corporate account linking implementation plan

> **For agentic workers:** Use the TDD and verification skills for each task.

**Goal:** Opt in to linking only the corporate Google Workspace account explicitly permitted for an authenticated Toolbox owner.

**Architecture:** Keep owner authentication and Google connection identity separate. A server-injected `TrustedOwnerIdentityResolver` maps the already authenticated owner ID to its permitted mailbox and Workspace hosted domain. `NewCorporateService` evaluates verified Google claims at OAuth completion before activation; default `NewService` and the fixture keep their existing behavior. No broker, service, user columns, or email account keys are introduced.

**Tech stack:** Go, existing OAuth service, Google RS256 verifier, existing transactional repository and cleanup credential store.

## Constraints and review focus

- Provider identity remains the existing Google issuer/provider plus stable `sub`; mailbox claims authorize a link, never replace account identity.
- Resolver input is the owner ID bound to the consumed OAuth transaction. Request bodies, query parameters, `login_hint`, and consent hints never configure policy.
- Workspace enforcement needs signed `email`, boolean true `email_verified`, and `hd`. Exact mailbox and hosted-domain matches are both required. No alias, dot, plus-address, or local-part case folding.
- Google email identity scope is explicit opt-in (`GoogleConfig.IdentityScopes`), with an exact `openid email drive.file` grant contract. Minimal scopes remain unchanged by default.
- Rejected known credentials use the existing cleanup-only persistence path. No active connection, access lease, callback retry, or automatic account-wide revocation follows a policy denial.
- Runtime wiring remains a library integration gate: the fixture command supplies neither real owner OIDC nor the trusted resolver. Mocked tests are not Google acceptance.
- Test resolver absence/failure/invalid data; same-domain colleague; personal account; missing/malformed/unverified signed claims; spoofed hints; stale, wrong-owner and wrong-session callbacks; owner/session loss while exchanging; cleanup retention and revocation.

## Task 1: Explicit Google identity contract

- [x] Add tests that fail when email identity mode is unavailable or does not enforce its exact scopes and signed claim types.
- [x] Run those tests and inspect their missing-feature failures.
- [x] Add `IdentityScopes`, copied `ExpectedScopes`, and verified identity extraction after existing signature/issuer/audience/nonce/time checks.
- [x] Run OAuth tests; keep default and fixture scope tests unchanged.

## Task 2: Trusted corporate link policy

- [x] Add service tests using signed Google responses and a server-injected owner resolver. Assert exact allowed account, all denial classes, stable-sub persistence, transaction/session binding, and cleanup-only credentials.
- [x] Watch failures before implementing `CorporateIdentity`, `TrustedOwnerIdentityResolver`, `NewCorporateService`, and completion enforcement.
- [x] Run the policy and complete OAuth suites.

## Task 3: Refresh continuity and integration documentation

- [x] Test then implement preservation of the stored email scope contract in the token manager; reject default-to-email escalation and corporate scope drops.
- [x] Document resolver trust and actual fixture/runtime limitations, explicit scope consent, deployment and real-provider gates.
- [x] Run gofmt, vet, full race tests, and build with the pinned toolchain. Review the whole diff and commit the isolated branch. (Final verification evidence is recorded in the branch completion report.)
