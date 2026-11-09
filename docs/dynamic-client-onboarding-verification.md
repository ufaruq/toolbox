# Dynamic client onboarding verification

Observed 8 November 2026 (local time), against implementation revision
`21452fa01768725d5f615b1204e4f2a8ecbbd745`. The branch started at `715d7bf`.
This record is separate from the current [setup guide](keycloak-setup.md#optional-dynamic-client-registration)
and [owner workflow](mcp-setup.md#owner-approval-for-new-keycloak-clients).

## Complete acceptance

`TOOLBOX_E2E_REVISION=21452fa01768725d5f615b1204e4f2a8ecbbd745 make test-all`
passed using the repository's isolated Docker runner. Its result checker reported
**1179 tests/subtests passed, no skips, all five opt-in acceptance suites ran**.
The gate also passed formatting, vet, documentation links, builds, and both
standalone browser scripts. Local evidence was retained at
`/private/tmp/toolbox-test-evidence.lfh1kf`; it is not a hosted CI result.

Coverage includes real PostgreSQL and OpenBao, the digest-pinned Keycloak 26.8.2
server with controlled HTTPS upstreams, the real MCP gateway fixture, owner and
Workspace browser flows, and all ordinary Go tests with the race detector.

The new assertions verify:

- Candidate storage and SQL constraints, including approved-candidate
  delete/recreate attempts and immutable profile/agent binding.
- Fully signed token validation before queue creation; unknown/inactive owners,
  invalid tokens, reserved clients and service-account tokens cannot onboard.
- Idempotent pending requests, candidate capacity/rate limits, reject/reopen,
  concurrent decisions, and independent owner/client permission boundaries.
- Owner-cookie, Origin and CSRF authorization; no MCP bearer self-approval or
  client-supplied identity rebinding.
- Pending/rejected/approved UI and a delayed list response arriving after logout.
- Real registration discovery, setup-gate denial with and without submitted
  scopes, the documented administrator setup, preserved builtin client scopes,
  safe registration and registration-token updates, and rollback of denied writes.
- Wildcard/untrusted callbacks, remote sector URLs, confidential clients,
  privileged scopes, device/CIBA/token-exchange settings and protocol mapper
  injection are denied. PKCE downgrade is normalized to S256; missing/plain
  challenges are denied. The sequential realm quota reaches128 and then denies.
- Real user login → pending → separate owner approval → document grant → read →
  revoke; another owner and pairwise subjects cannot inherit approval.

## Independent review and fixes

A fresh whole-branch review of `715d7bf..a0b9097` identified two substantive issues.
Both were reproduced with failing regressions, fixed in `21452fa`, and included
in the passing full gate:

1. A delayed decision body could outlive the owner session. Approve/reject/reopen
   now revalidate session ownership, expiry, CSRF binding and OIDC-session binding
   inside the committing transaction. Regressions cover logout and expiry.
2. A profile-bound opaque agent credential could survive disabling onboarding.
   The shared runtime authorizer now enforces dynamic admission for those agents
   through final dispatch/release. Regressions cover denial, explicit static
   allowance and release-time rollback. Standalone credentials retain their policy.

The review reported no minor findings or declined-to-judge items. Fixes were
verified by regression tests and the full suite; no second review is claimed.

## Implementation decisions and limits

- User-approved one-time Keycloak administrator setup removes inherited realm
  default scope assignments, then disables only the setup-required gate. This
  preserves existing built-in clients but adds a setup step before registration.
- Native PKCE/flow policies may normalize metadata instead of returning an error.
  Clients must use the resulting hardened settings; tests assert behavior.
- Public service-account metadata cannot produce client-credentials tokens.
  Pairwise subjects fail the exact owner match. Public UMA creation returns500
  and rolls back; an update cannot enable UMA. Unsupported client settings may
  therefore fail with native errors rather than a uniform Toolbox response.
- Native128-client quota is sequential and not a concurrent hard cap or rate
  limiter. External exposure needs separate edge limits and monitoring; this
  change remains local/private setup support. Toolbox candidate quotas remain
  transactional, with a per-process owner rate limit.

No live Keycloak realm was changed. Live Google/Okta, Google's built-in provider
and hosted ChatGPT/Claude compatibility remain unverified. No production rollout,
remote CI success, push, or pull request is claimed by this record.
