# Hosted MCP with Direct Okta Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Add authenticated HTTP MCP to the existing Toolbox service, with separate per-user/per-registered-client permissions and an independent corporate account-linking PR.

**Architecture:** Okta issues tokens directly; one Go service hosts the owner UI, existing HTTP API and `/mcp`. Verified `(issuer, uid, cid)` selects a persisted caller profile and its Agent, and HTTP/MCP share live authorization and execution. Existing provider token storage and exact-document grants remain authoritative.

**Tech Stack:** Go 1.27.2, MCP Go SDK v1.8.0, coreos/go-oidc/v3 v3.21.0, existing PostgreSQL/OpenBao adapters and browser assets.

**Spec:** `docs/superpowers/specs/2026-10-18-hosted-mcp-direct-okta-design.md`.

## Global Constraints

- One Go application container; no Hydra, broker, separate MCP proxy, device attestation or per-installation token infrastructure.
- Logical caller identity is `(issuer, uid, cid)`; multiple sessions of one registered client share permissions.
- Existing file-ID rule `[A-Za-z0-9_-]{1,256}`, request duration 1–604800 seconds, document limit 1 MiB.
- Profile expiry is explicit, at most 30 days. Disable cancels pending requests and revokes grants; enable restores none of them.
- Preserve opaque-credential authentication and repeated/final live authorization. Never pass empty credentials to bypass checks.
- Corporate account eligibility, extra Google identity scopes and live Google runtime wiring stay outside this PR.
- No real Okta/Google/Claude/deployment claim without actually running those checks.

## Review Focus

- Token expiry or caller disable during provider export: final authorization returns no buffered content (Tasks 3/6).
- Same email or display label with another immutable user/client identity: cannot select the first user's profile (Tasks 2/3).
- Pre-disable pending request replay after enable: approval remains denied and fresh request is needed (Task 3).
- Legacy MCP `2025-11-25` request cancellation and cross-request catalog isolation (Tasks 4/6).
- Hosted startup with missing identity/secret settings or fixture route exposure: fails closed (Task 5).

## Task 1: Caller and owner-login persistence

**Files:** `internal/domain/domain.go`, `internal/store/validate.go`, `internal/store/postgres.go`, `internal/store/migrations/002_caller_profiles.sql`, new caller/login store tests.

**Interfaces:** Produce `domain.CallerProfile` with string fields `ID, OwnerID, AgentID, Issuer, UserID, ClientID, Label, Status`, `Tools []string`, and `ApprovedAt, ExpiresAt time.Time`. Produce `domain.OwnerLogin` with string fields `ID, StateHash, NonceHash, BrowserHash, SecretRef`, `ExpiresAt time.Time`, `Consumed bool`. Add `State.CallerProfiles` and `State.OwnerLogins` maps keyed by ID; `NewState` initializes both. Profile statuses are `active` and `disabled`.

- [x] Write failing store tests for unique `(Issuer,UserID,ClientID)`, unique Agent binding, matching owner identity, immutable identity/Agent fields, explicit expiry and one-way consumption of owner login transactions.
- [x] Run `go test ./internal/store` and verify failure is due to missing behavior.
- [x] Implement memory invariants and additive SQL migration/load/sync with equivalent constraints. Follow existing JSON payload schema conventions. Never store codes, PKCE verifiers, raw state or tokens in these records.
- [x] Run `go test -race -count=1 ./internal/store`; run actual Postgres cases when configured. Commit only this task's files.

## Task 2: Configured Okta verification and OIDC exchange

**Files:** new `internal/identity/okta.go`, `internal/identity/okta_test.go`; root owns module dependency updates.

**Interfaces:** `identity.Config{Issuer,Audience,OwnerClientID,OwnerClientSecret,OwnerCallbackURL string; Clients map[string]string; AllowLoopbackHTTP bool}`; `identity.Claims{Issuer,UserID,ClientID string; ExpiresAt time.Time}`; `identity.Owner{Issuer,UserID string}`. Produce `New(ctx context.Context, cfg Config) (*Service,error)`, `(*Service).VerifyAccess(ctx, raw string) (Claims,error)`, `(*Service).AuthorizationURL(state,nonce,verifier string) (string,error)`, `(*Service).Complete(ctx,code,verifier,nonceHash string) (Owner,error)`, `(*Service).Clients() map[string]string`, `(*Service).Issuer() string`.

- [x] Write failing tests with a signed-JWT OIDC fixture: valid user access token passes; wrong algorithm/signature/issuer/audience/client/scope, missing `uid`, ID-token audience, expired/future-time tokens fail. Owner exchange must validate nonce and `uid` and use the configured callback/PKCE.
- [x] Verify the tests fail before implementation.
- [x] Implement using maintained OIDC verification with RS256 allowlisting and additional API claims checks (`uid`,`cid`,`scp`, strict time policy). Use configured issuer/discovery only, bounded HTTP, no redirects and sanitized errors. `AllowLoopbackHTTP` exists only for explicit tests; hosted configuration never enables it. Return copies from `Clients`.
- [x] Require the same immutable `uid` claim in owner ID tokens and MCP access tokens; document tenant configuration. `Complete` validates `security.Hash(idToken.Nonce)` against the supplied nonce hash; do not return OAuth tokens.
- [x] Run `go test -race -count=1 ./internal/identity` and commit task files.

## Task 3: Owner controls and one shared authorization path

**Files:** `internal/server/server.go`, `owner.go`, `delegation.go`, `invoke.go`; new `agent_auth.go`, `operations.go`, `callers.go`, `owner_login.go`, relevant server tests and existing web HTML/JS.

**Interfaces:** Consume Tasks 1/2. Add optional `Config.Identity` implementing Task 2's methods and `Config.LoginSecrets tokens.JSONStore`. Define server-private `agentAccess{AgentID,CredentialID,CallerProfileID string; TokenExpiresAt time.Time}`. `authorizeAgent(st, access, tool string) error` handles either a verified existing credential or a verified Okta caller, with profile ceilings applying to every authentication path of a linked Agent.

- [x] First write failing tests for same user web/Code separation, cross-owner access, caller expiry/disable during export, opaque credential compatibility, profile tool removal and stale pending requests after enable.
- [x] Extract request/poll/mint/invoke operations into shared methods taking authenticated `agentAccess`. Keep audit, bounded integration calls and final release gate identical. HTTP handlers retain existing body validation and error shapes. MCP will call these methods, not a proxy HTTP server.
- [x] Add owner routes: `GET /v1/callers`, `POST /v1/callers` (client_id, label, tools, duration_seconds), `POST /v1/callers/{id}/disable`, `POST /v1/callers/{id}/enable` (explicit new tools/duration). Only allow configured client IDs. Use existing session/Origin/CSRF checks; never allow caller-provided owner/Agent identity.
- [x] Disable atomically deactivates the Agent, revokes its grants and cancels pending requests. Enable is explicit and restores authentication for all valid matching client tokens, but no old grant/request. Show verified client and Agent in approval/audit.
- [x] Implement `GET /auth/login`, `GET /auth/okta/callback`, `POST /auth/logout`: ten-minute one-use DB transaction, browser-bound HttpOnly cookie, nonce/state hashes in DB, verifier in existing JSON secret store, consume before exchange. Validate exact callback parameters; establish an eight-hour secure owner session only after validation. Delete short-lived verifier best-effort with bounded context. No fixture-login route in hosted mode.
- [x] Extend the existing UI with Okta login/logout and caller-profile approval/disable/enable controls; preserve fixture console and browser selectors. Use textContent for labels/identity output.
- [x] Run `go test -race -count=1 ./internal/server ./internal/app`; exercise stored owner-login replay/wrong browser/expired transaction and profile mutation CSRF/cross-owner tests. Commit task files.

## Task 4: MCP transport and tool adapter

**Files:** new `internal/server/mcp.go`, `mcp_test.go`; route wiring in `server.go`.

**Interfaces:** Consume shared operations and `identity.Claims`. `(*Server).serveMCP(w,r)` verifies bearer token and live profile, creates a request-scoped filtered SDK server, and delegates to a stateless handler. `GET /.well-known/oauth-protected-resource/mcp` and the root fallback expose the exact resource/Okta issuer/scopes without secrets.

- [x] Write failing HTTP SDK-client tests for legacy initialize/list/call, missing/invalid token challenges, active-but-unapproved caller denial, per-client tool filtering, cross-client grant/request denial and malformed arguments.
- [x] Use SDK v1.8.0 `NewStreamableHTTPHandler` with `Stateless:true`, `JSONResponse:true`, bounded request bodies and cancellation propagation. Its getServer callback is side-effect-free and may run twice; prepare the SDK server once per request. Explicitly link handler work to incoming request cancellation for legacy versions.
- [x] Register typed generic `mcp.AddTool[In,any]` with explicit object schemas and `additionalProperties:false`. Expose exactly `toolbox_request_document_access`, `toolbox_get_access_request`, `google_drive_read_document_v1`; enforce the tool ceiling inside operations independently of discovery.
- [x] Mint existing delegation tokens internally and discard them after invoking. Return one text JSON result, nil generic output, sanitized `IsError` failures and preserved untrusted metadata. Never return any credential or OAuth token.
- [x] Run actual `StreamableClientTransport` with bearer headers on every request, `ProtocolVersion:"2025-11-25"`, `MaxRetries:-1`. Also verify the SDK's default supported version. Run `go test -race -count=1 ./internal/server ./internal/app` and commit.

## Task 5: Single-container runtime and operator setup

**Files:** `cmd/toolbox/main.go`, new runtime/config tests, `Dockerfile`, `.dockerignore`, new `docs/mcp-setup.md`, README/roadmap/status references and CI changes only where required.

**Interfaces:** Consume Tasks 1–4. Add explicit hosted mode with public HTTPS origin, Okta configuration, persisted signer/pepper, required durable store settings and safe bind validation. Fixture mode keeps its current loopback restrictions and default behavior. Parse client registrations from a structured non-secret configuration value.

- [x] Write failing startup tests for missing identity settings, invalid origins/client map, ephemeral crypto in hosted mode and exposed fixture routes. Preserve existing fixture startup tests/behavior.
- [x] Implement validated hosted configuration and one application image. Reuse existing stores with production TLS/auth validation; no development credentials or automatic runtime schema privilege escalation.
- [x] Keep live Google wiring outside this PR. Hosted startup uses an explicit unavailable-provider integration until live wiring is implemented; it must never substitute the fixture provider. Document that owner Google-connect/read returns an availability error in this mode, while MCP authentication and profile management work. Fixture/library integration tests prove read authorization, not live Google.
- [x] Document exact Okta issuer/audience/uid claims/client assignment, Code fixed callback and CLI, Claude.ai custom-client settings, owner profile setup, persistent secrets/stores, real acceptance checklist and limitations. Reference the separate corporate-linking PR once available.
- [x] Run formatting, vet, race suite, build and Docker build/smoke where Docker is available. Record unavailable checks accurately; commit task files.

## Task 6: End-to-end verification and PR

**Files:** new `internal/app/mcp_acceptance_test.go`, browser coverage if needed, verification documentation and PR body.

- [x] Run HTTP SDK fixture flow: one owner, web→A, Code→B, request/browser-owner approval/poll/read, cross-denials, disable during export, enable with no restored rights, fresh approval and other-client continuity.
- [x] Run `gofmt`, `go vet ./...`, `go test -race -count=1 ./...`, `go build ./...`; use real PostgreSQL/OpenBao tests when available and preserve explicit skips otherwise. Run existing Chromium regressions if dependencies are available.
- [x] Review the complete diff with a fresh reviewer; fix important issues with regression tests and rerun covering checks. Keep corporate account-linking code out of this branch.
- [x] Open the MCP PR against `main` with concrete behavior, validation and unrun live-provider/client checks. Open the corporate-linking PR separately. Do not merge or deploy.

## Execution record

User authorized implementation and separate PRs. Baseline `go test ./...` passes when local networking is permitted; the default sandbox blocks `httptest` listeners. Use `/workspace/toolbox-tools/go/bin/go`, `GOCACHE=/workspace/toolbox-tools/cache`, `GOPATH=/workspace/toolbox-tools/gopath` and explicit local network permissions for tests. Keep scratch reports in `work/` and record deviations in the progress ledger.


## Final implementation notes

- Additive migration 003 permits optional immutable audit attribution fields while retaining the legacy payload contract and append-only protection. Real PostgreSQL tests exposed the original closed-key mismatch; the new migration/regression resolved it.
- Anonymous owner-login starts have a constant-key 60/minute limit and an atomic 1000-row durable cap. Expired verifier deletion retries before dropping its database reference.
- Hosted configuration rejects noncanonical browser origins rather than changing the registered audience silently. Readiness performs a bounded schema-dependent repository transaction.
- SDK sessions may close after a disabled caller receives HTTP 403; acceptance reconnects after explicit re-enable, then proves old rights remain revoked.
- Corporate eligibility is independently reviewable in PR #6. No extra identity service was introduced.
