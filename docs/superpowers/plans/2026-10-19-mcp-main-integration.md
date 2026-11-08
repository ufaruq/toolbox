# MCP and Workspace integration plan

> **For agentic workers:** Use superpowers:executing-plans inline. The user authorized conflict resolution and PR review; do not merge either PR.

**Goal:** Resolve #7 against current main and #10, then expose the existing approved Google document flow through standard MCP.

**Architecture:** Keep #5/#10 owner sessions, Google adapters and UI. Add #7's caller profiles, MCP transport and shared HTTP/MCP authorization operations. Keep the local modes explicit; production deployment stays in #4.

**Tech stack:** Go, PostgreSQL/OpenBao, official MCP Go SDK, signed OIDC fixtures, Chromium.

**Spec:** `docs/mvp-delivery.md` and the existing hosted-MCP design, with the integration constraints below taking precedence over its superseded standalone login/runtime.

## Global constraints

- Preserve the organization issuer/subject owner key, existing connections and migration checksums 001–003.
- Map custom authorization-server access-token `uid` only to the same tenant's organization ID-token `sub`; verify issuer/audience/signature/scope/client and require an explicit same-tenant configuration. No email-based linking.
- Caller profiles retain the owner's canonical issuer/subject identity. Each configured OAuth client gets its own agent and grants.
- MCP calls use exactly the Google adapter and authorization checks used by HTTP, including expiry, disable, revoke and final content release.
- Leave #10 and #7 unmerged. Real-provider/actual-client acceptance remains a separately reported gate.

## Review focus

- Existing owner sessions and Google connections survive schema upgrade.
- A different tenant, user, client or document cannot reuse a profile/grant.
- Disabled/expired profiles and revoked grants fail before secret/provider access and before final content release.
- Owner-only and fixture modes preserve their route/cookie isolation.
- The owner UI can approve clients and show verified client identity without exposing provider credentials.

## Tasks

- [x] Resolve overlapping runtime/auth files using #10 as the canonical implementation; preserve shared MCP operations and add migrations 004/005.
- [x] Add failing integration/configuration tests for the same-tenant organization/custom-server identity binding and optional local MCP runtime. Implement validation and caller resolution.
- [x] Add caller controls to the Workspace UI, verify SDK request/approve/read/denial/revoke with existing owner state, and retain the browser regressions from #10.
- [x] Run the full race/store suite, SDK and browser checks, migration upgrade checks, and independent PR review. Prepare the reviewed update for #7 and leave merge decisions with the user.

## Verification record

- `make check` passed with disposable PostgreSQL and OpenBao enabled: formatting, vet, the full race suite and build. The upgrade test starts from main's original migrations and preserves the owner, session and Google connection while adding MCP profiles.
- Official SDK coverage passed for request, owner approval, read, other-document denial and revocation through the combined Workspace runtime. Signed local issuer tests cover the organization/custom-server UID binding and tenant/client rejection.
- Isolated Chromium Workspace, Google probe and OIDC flows passed, including client approval/disable/enable controls and the retained #10 login-return and stale-revoke regressions. Fixture approval/read/denial/revoke/disconnect and all four delayed-review cases also passed.
- Independent read-only PR review found no actionable issues in the MCP delta against `3326cac945abfb2f134812aee4c4c14c9a5619fc`; its independent identity/server/command tests passed.
- Actual Okta custom-server issuance, native-client OAuth/MCP and real Google document acceptance remain pending. Neither PR is merged by this work. Merge #10 first, then #7 after the recorded live gates pass.
