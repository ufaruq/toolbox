# Keycloak Broker Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Introduce optional Keycloak/Okta/Google login with verified continuity
of existing Toolbox owner data and a working MCP path.

**Architecture:** One OIDC owner issuer per runtime, explicit Okta or Keycloak
access-token policy, and unique immutable identity aliases for operator-verified
migration. Keep credential stores and tool authorization unchanged.

**Tech Stack:** Existing Go 1.27.2, go-oidc, PostgreSQL/OpenBao, real pinned
Keycloak container, controlled OIDC fixtures, existing browser tooling.

**Spec:** [Broker design](../specs/2026-11-07-keycloak-broker-design.md).

## Global constraints

- Preserve the existing direct-Okta backend by default and its issuer checks.
- No email matching, silent account/caller merges or grant ownership changes.
- Verify TLS and exact configured realms, API audiences and client IDs.
- Keep secrets in private generated files or environment settings, not commits.
- No mTLS/IAP, production deployment or direct writes to main in this PR.

## Review focus

1. Keycloak ID tokens/service accounts cannot authenticate MCP user calls.
2. Equal emails across upstream providers do not merge identities.
3. A conflicting alias or migration race fails atomically with no reassignment.
4. Legacy accounts/sessions/caller approvals retain their original guarantees.
5. Admin API redirects, malformed bodies and foreign realms cannot produce links.

### Task 1: Optional Keycloak MCP identity backend

Files: `internal/identity/{access,okta,keycloak}.go` and tests;
`cmd/toolbox/{config,mcp}.go` and tests.

Interface: add `Provider string` to `identity.AccessConfig`; empty/`okta` preserves
current behavior; `keycloak` requires exact equal owner/API realm issuers.
`identity.NewAccess` still returns `*identity.Service`; public methods unchanged.

- [x] Write and run failing tests for Keycloak access and configuration.
- [x] Implement strict `sub`/`azp`/`scope`/`typ` policy and bounded discovery.
- [x] Test wrong realm/audience/client, ID tokens, service accounts and times.
- [x] Run identity/config race tests and review.

### Task 2: Verified identity aliases and migration

Files: `internal/domain`, `internal/store` plus migration 006;
`internal/ownerlogin/service.go`, `internal/server/{agent_auth,callers}.go`;
new `internal/identitylink`, CLI integration and tests.

Interface: `domain.IdentityAlias{Issuer,Subject,OwnerID string}`;
`State.IdentityAliases map[string]IdentityAlias`;
`domain.IdentityKey(issuer,subject string) string`;
`domain.ResolveIdentity(*State,issuer,subject string)(User,bool)`;
`domain.IdentityForOwner(*State,ownerID,issuer string)(IdentityAlias,bool)`.
Primary identity plus aliases must be globally unique; aliases append-only.
Migration linker API will be finalized in the task brief before implementation.

- [x] Reproduce alias continuity, conflicts, foreign owner and immutability cases.
- [x] Implement domain/storage constraints and additive SQL migration.
- [x] Resolve owner sessions and caller approvals through explicit aliases.
- [x] Implement pinned Admin API proof, dry-run and atomic audited apply.
- [x] Test Google/email impostors, malformed/foreign proof and repeat migration.
- [x] Run memory and actual PostgreSQL/OpenBao checks and review.

### Task 3: Realm provisioning and actual Keycloak acceptance

Files: new `internal/keycloakrealm`, CLI commands,
`internal/app/keycloak_e2e_test.go`, test assets under `internal/testutil`,
Makefile/CI, placeholder configuration, `docs/keycloak-setup.md` and evidence.

- [x] Test generation of private realm configuration and explicit provider policy.
- [x] Implement confidential owner and public PKCE MCP clients and IdP setup.
- [x] Run real Keycloak with controlled Okta/Google-shaped upstream providers.
- [x] Prove linking preserves an old owner's data and new Google users are isolated.
- [x] Prove MCP caller approval/read/revocation with Keycloak-issued tokens.
- [x] Run `make check`, integration/browser checks, final independent review.
- [ ] Push feature branch and create PR; post sanitized proof in comments.
