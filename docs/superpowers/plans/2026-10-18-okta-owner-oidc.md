# Okta Owner OIDC Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver tested Okta owner sign-in code and a reviewable PR before the user configures an external tenant.

**Architecture:** A new `internal/ownerlogin` boundary verifies identities and creates existing Toolbox server sessions. A loopback-only `oidc-local` executable mode exposes owner identity while connector and agent operations remain unavailable. The existing fixture is preserved.

**Tech Stack:** Go 1.27.2, go-oidc v3.21.0, oauth2 v0.37.0, PostgreSQL, OpenBao KV-v2, existing Go/Playwright test tools.

**Spec:** [Okta owner sign-in design](../specs/2026-10-18-okta-owner-oidc-design.md).

**Review state:** Draft requested by the user alongside the design. Product implementation has not started. Review the spec first, then this plan. Recommended execution: native implementation with one independent security/code review before the implementation PR is marked ready.

## Global Constraints

- Go 1.27.2; go-oidc v3.21.0 and oauth2 v0.37.0; no archived Okta sample dependencies.
- Only `fixture` and loopback-only `oidc-local` startup modes; no implicit fallback to a fixture or memory dependency.
- Fixed owner callback `/auth/oidc/callback`; scopes `openid`; Authorization Code with S256 PKCE; RS256 ID tokens.
- Login transaction lifetime 600 seconds; owner session lifetime 8 hours; 32-byte stable session pepper; 500 active logins; 30 starts/minute/server.
- HTTPS trusted issuer/endpoints; 10-second HTTP timeout; 1 MiB response limit; no redirects, exchange retries, or insecure TLS runtime flag.
- Identity key is verified `(iss, sub)`; existing disabled identities stay disabled; no email linking.
- No raw verifier/code/token/client secret in domain snapshots, SQL, logs, responses, screenshots, or repository files.
- Google, agent and delegation APIs are disabled in owner-only mode; existing fixture coverage remains supported.
- Live tenant acceptance and production deployment remain pending after synthetic tests; do not merge or push to `main`.

## Review Focus

- Duplicate callback parameters and provider error variants must not bypass browser/state binding or create sessions (Tasks 2–3).
- Logout while exchange is blocked, or after finalization before cookie delivery, must prevent session recreation (Task 3).
- Existing sessions referenced by Google transactions must survive rotation as expired rows without foreign-key failures (Tasks 1 and 3).
- Old fixture records must not enable any connector/agent operation in owner-only mode (Task 4).
- Restart and secret-store write/read failures must preserve stable owner identity and fail closed for new logins (Tasks 3–5).

## File map

| Files | Responsibility |
| --- | --- |
| `internal/domain/domain.go`, `internal/store/*`, `002_owner_login.sql` | Non-secret login state, immutable identities and adapter parity |
| `internal/ownerlogin/provider.go`, `provider_test.go` | OIDC discovery, code exchange, verified identity and trusted HTTP transport |
| `internal/ownerlogin/service.go`, `service_test.go` | Single-use login orchestration, secret references, session issuance/logout/cleanup |
| `internal/server/auth.go`, `auth_test.go`, existing server/UI files | HTTP binding, cookies, capabilities and owner-only surface |
| `cmd/toolbox/config.go`, `config_test.go`, `main.go` | Fail-closed modes and dependency lifecycle |
| `internal/testutil/oidcidp/idp.go`, `internal/server/oidc_browser_test.go`, `tests/browser/oidc_e2e.py` | Shared synthetic IdP test support and browser acceptance; no production runtime imports the helper |
| `.env.example`, `docs/okta-setup.md`, README, CI | Setup contract and reproducible verification |

## Task 1: Persist login metadata and preserve session/identity invariants

**Files:** Modify `internal/domain/domain.go`, `internal/store/validate.go`, `internal/store/postgres.go`, `internal/store/store_test.go`, `internal/store/postgres_test.go`; create `internal/store/migrations/002_owner_login.sql`.

**Interfaces:** Produce `domain.OwnerLoginTransaction` with string fields `ID, StateHash, BrowserHash, NonceHash, SecretRef, Issuer, ClientID, RedirectURI, PreviousSessionID, IssuedSessionID, Status`, plus `ExpiresAt time.Time`; produce `State.OwnerLogins map[string]OwnerLoginTransaction`. No raw secrets. Existing `Repository.Transact` remains the transaction interface.

- [ ] Write `TestOwnerLoginRepositoryParity`: run on memory and PostgreSQL; round-trip all fields; reject duplicate state hash, missing immutable binding, secret-field injection, backwards status transitions, and issuer/subject changes on existing users. Allow an optional prior-session ID only if it references a session when created. `IssuedSessionID` can change only from empty to a valid session key during completion and is immutable thereafter.
- [ ] Add `TestExpireSessionWithPendingGoogleOAuth`: expire the session at database time while a Google OAuth row references it; assert transaction success and owner authorization denial. Verify the original migration checksum remains unchanged.
- [ ] Run `go test ./internal/store -run 'OwnerLogin|ExpireSession' -count=1`; confirm failures arise from the missing model/behavior.
- [ ] Implement the model, `NewState` initialization, validator, migration constraints/identity trigger, table load and sync ordering. Require complete configuration binding, valid status and immutable metadata; retain expired sessions instead of deleting them during auth operations.
- [ ] Rerun against memory and disposable PostgreSQL; run existing store tests under `-race` with `TOOLBOX_TEST_DATABASE_URL` configured. Require no skipped PostgreSQL cases in the recorded integration run.
- [ ] Commit `feat: persist owner login transactions and identity invariants`.

## Task 2: Verify an OIDC provider through its actual protocol

**Files:** Create `internal/ownerlogin/provider.go`, `provider_test.go`, `internal/testutil/oidcidp/idp.go`; modify `go.mod`, `go.sum`.

**Interfaces:** Define `Identity{Issuer, Subject string}`; `Provider` with `AuthorizationURL(state, nonce, challenge string) (string, error)` and `Exchange(context.Context, code, verifier, nonceHash string) (Identity, error)`; `ProviderConfig{Issuer, ClientID, ClientSecret, RedirectURI string}`; constructor `NewProvider(context.Context, ProviderConfig, *http.Client) (Provider, error)`. The injected client is explicit application/test transport, never caller input.

Shared test support exports `oidcidp.New(testing.TB) *oidcidp.Server`, fields `Issuer, ClientID, ClientSecret string`, and methods `TLSClient() *http.Client`, `SPKIHash() string`, `ExchangeCount() int`, `SetClaims(map[string]any)`, and `BlockExchange() (entered <-chan struct{}, release func())`. Register shutdown through `testing.TB.Cleanup`; protect mutable claims/counters with a mutex. This helper is imported only by tests, including the server browser harness.

- [ ] Build a local TLS fake IdP implementing discovery, JWKS and token exchange. Record attempted exchanges; enforce S256 with an independently computed challenge. Mint actual RS256 tokens with configurable claims and signing key.
- [ ] Write table-driven `TestOIDCProviderValidation`: valid token succeeds with exact issuer/subject; wrong issuer/audience/nonce/azp, missing or oversized/control-character subject, expiry/nbf, missing or future `iat` beyond 60 seconds, invalid signature/algorithm, missing ID token and malformed response all fail. Assert no automatic token-endpoint retry.
- [ ] Write `TestOIDCProviderTransport`: reject mismatched discovered issuer, cross-origin/insecure endpoints, redirects, oversized responses and caller cancellation. Assert auth URL has exact callback/scopes/state/nonce and S256 challenge without a client secret.
- [ ] Run `go test ./internal/ownerlogin -run OIDCProvider -count=1` and confirm an expected missing-interface failure before implementation.
- [ ] Add the two pinned dependencies. Implement exact issuer/endpoint validation, bounded HTTP transport, OAuth2 client-secret code exchange with `oauth2.AuthStyleInHeader` and go-oidc signature/claim verification. Check nonce hash and `azp` explicitly; do not persist tokens. Assert a rejected client authentication triggers exactly one HTTP exchange.
- [ ] Rerun provider tests under `-race`; require actual signature and PKCE verification rather than a stub returning a user ID.
- [ ] Commit `feat: verify owner OIDC authorization code responses`.

## Task 3: Orchestrate one-use login, sessions and local logout

**Files:** Create `internal/ownerlogin/service.go`, `service_test.go`; extend store/provider test fixtures as needed.

**Interfaces:** `ServiceConfig{Issuer, ClientID, RedirectURI string; Pepper []byte}`; `StartResult{AuthorizationURL, BrowserToken string; ExpiresAt time.Time}`; `LoginResult{SessionToken, CSRFToken, UserID string; ExpiresAt time.Time}`. Produce `NewService(domain.Repository, tokens.JSONStore, Provider, ServiceConfig) (*Service, error)`, `Start(ctx context.Context, previousSessionID string) (StartResult, error)`, `Complete(ctx context.Context, state, code, browserToken string) (LoginResult, error)`, `Reject(ctx context.Context, state, browserToken string) error`, `Logout(ctx context.Context, sessionID, browserToken string) error`, and `Cleanup(context.Context) error`.

- [ ] Write `TestOwnerLoginLifecycle`: 600-second bound transaction; verifier only in secret store; verified issuer/subject creates/reuses active user; new 8-hour random session with stored hashes; previous session expires without deleting Google foreign-key parents. Disabled user never reactivates.
- [ ] Write `TestOwnerLoginRejectsReplayAndWrongBrowser`: wrong binding does not consume the legitimate transaction; expired/missing state and repeated/concurrent callbacks create zero extra sessions; concurrent valid callbacks perform exactly one exchange.
- [ ] Write `TestLogoutDuringExchange`: pause the fake token endpoint, log out the prior session, resume exchange and assert no live replacement session. Cover expiry or account disablement while exchange is blocked as well. Add `TestLogoutBeforeCallbackCookieDelivery`: pause the HTTP response after finalization, cancel with its browser binding despite the old session's rotation, release the response and assert its issued cookie cannot authenticate. Persist `IssuedSessionID` and revoke matching completed replacements atomically; retain their metadata until the issued session expires.
- [ ] Write `TestOwnerLoginPersistenceFailure`: secret/DB write failure or uncertain acknowledgement never publishes a usable login/session; replay cannot reuse an exchanged code; cleanup retries known refs without exposing secret values. Verify same subject under distinct issuers remains a distinct identity and two subjects have isolated sessions.
- [ ] Run targeted tests to show the missing service behavior, then implement each transition with short DB transactions and no network I/O inside `Transact`. Use database time before consumption and before finalization, preserve immutable identity, and sanitize errors/audits.
- [ ] Implement cleanup in batches of 100 using bounded contexts. Do not claim hidden historical secret versions were destroyed. Enforce active-login bound of 500.
- [ ] Run service/provider/store tests under `-race`, including real OpenBao CAS/cleanup and PostgreSQL cases with dedicated synthetic stores.
- [ ] Commit `feat: establish and revoke verified owner sessions`.

## Task 4: Expose Okta login through an explicit local runtime

**Files:** Create `internal/server/auth.go`, `auth_test.go`, `cmd/toolbox/config.go`, `config_test.go`; modify `internal/server/server.go`, `owner.go`, `ui.go`, `web/index.html`, `web/app.js`, `cmd/toolbox/main.go`.

**Interfaces:** Add `OwnerOnly bool` and `OwnerLogin *ownerlogin.Service` to `server.Config`. Add private `runtimeConfig` and `loadConfig(getenv func(string) string) (runtimeConfig, error)` in package main. Keep existing fixture `New` callers working; allow nil signer/integration only with nonfixture `OwnerOnly` and a valid login service.

- [ ] Write `TestOIDCLocalConfig`: require every configured setting from the spec; reject unknown modes, nonloopback listener/origin, mismatched origin port/host, issuer HTTP, invalid 32-byte pepper and missing stores. Fixture config remains supported.
- [ ] Write `TestOwnerAuthHTTP`: public safe config; same-origin empty JSON start; bounded unique callback fields; correct cookie Path/HttpOnly/SameSite/MaxAge; generic errors; session reload; CSRF-protected POST session logout and browser-bound pending-login cancellation; query rejection on all other owner paths. Cancellation without an active session can revoke only the matching login/replacement and requires exact Origin. Enforce 30 starts/minute/server.
- [ ] Write `TestOwnerOnlyRejectsFixtureAndToolAPIs`: seed existing users, agents, credentials, connections and grants; assert fixture routes return 404, all disabled operation routes return `503 FEATURE_DISABLED`, no state mutation and no integration call. Reject `Fixture && OwnerOnly`.
- [ ] Run focused config/server tests and confirm expected failure before implementation.
- [ ] Implement fixed routes `/v1/auth/config`, `/auth/oidc/start`, `/auth/oidc/callback`, `/v1/session/logout`. Keep `/v1/session` behavior and expose `owner_only`. Bind prior sessions from validated browser cookies; never accept identity/config fields from JSON.
- [ ] Split startup into fixture and `oidc-local` dependency paths. Require stable pepper/PostgreSQL/OpenBao in the latter, run local additive migrations, initialize provider with application-lifetime context, and stop bounded login cleanup on shutdown. Never construct Google or agent capabilities there.
- [ ] Update UI to load safe auth capabilities before enabling login. Preserve fixture selectors and notices; show “Sign in with Okta”, authenticated owner ID and Toolbox logout in owner-only mode. Keep the complete connector workspace hidden there.
- [ ] Run existing server/fixture acceptance tests plus new config/auth tests under `-race`.
- [ ] Commit `feat: add local Okta owner sign-in runtime and UI`.

## Task 5: Prove browser behavior and document external setup

**Files:** Create `internal/server/oidc_browser_test.go`, `tests/browser/oidc_e2e.py`, `.env.example`, `docs/okta-setup.md`; modify README, `tests/browser/README.md`, `.github/workflows/go.yml`. Keep PR #3's documentation changes separate; reference its roadmap without copying its historical evidence.

**Interfaces:** A Go browser harness imports shared `internal/testutil/oidcidp`, starts real loopback Toolbox and TLS fake-IdP servers, pins the fake CA in its server-side HTTP client, and invokes Playwright with the two explicit origins. Compute the fake certificate's SPKI SHA-256 value and pass it to Chromium's test-only `--ignore-certificate-errors-spki-list` argument, so browser navigation trusts that fixture certificate. Do not disable provider TLS verification in application configuration. Enable the browser test through `TOOLBOX_TEST_OIDC_BROWSER=1`; CI sets it only after installing Playwright/Chromium. Ordinary Go tests must still run all protocol tests without Python.

- [ ] Add `TestOIDCBrowserFlow` and `oidc_e2e.py`: actual redirect to fake IdP, return through callback, visible owner status, reload preserving login, Toolbox logout, denied old session, separate second owner, no fixture/connector UI and no JavaScript errors. Block browser requests outside the two configured synthetic origins; save sanitized result metadata/screenshots without cookies, query traces or secrets.
- [ ] Confirm the new browser test fails before its runner is complete; implement the runner and CI step. Retain both existing fixture scripts and their single-origin boundary.
- [ ] Document exact Okta Integrator Free / OIDC Web Application settings, intended user assignment, organization issuer, Authorization Code + PKCE, the fixed callback, environment placeholders and stable-secret generation. Explain first-party logout and that the registered sign-out redirect is unused by this milestone.
- [ ] Document startup with existing disposable stores, all required settings, missing-config errors and the owner-only local scope. Clearly label real Okta acceptance unrun and leave Google/production milestones open. Keep `.env` ignored; use no usable credentials in `.env.example`.
- [ ] Verify `gofmt`, `go vet ./...`, `go test -race -count=1 ./...`, `go build ./...`, real PostgreSQL/OpenBao cases, the dedicated OIDC browser flow and both fixture browser scripts. Record exact revision, commands, passes and skips; do not turn skipped store/browser tests into success claims.
- [ ] Obtain one independent review of the full diff focused on the spec's negative identity/session cases; fix findings and rerun only the affected checks plus any required final gates.
- [ ] Commit `test: cover Okta sign-in browser flow and setup guide`.
- [ ] Update the draft PR with final code scope and actual evidence; mark ready only when the implementation gates pass. Do not merge or push to `main`. The user can then configure Okta and perform separately recorded live acceptance.

## Current evidence and pending work

At the unchanged application baseline `3e663109df283ee9dc66c41530291a15d83500cf` (documentation follow-up), `go test -race -count=1 ./...` passed on 2026-10-18 after allowing local test sockets in the execution sandbox. This run did not configure the optional real PostgreSQL/OpenBao integrations or browser acceptance. It does not test the proposed OIDC implementation.

Only the design and this draft plan exist in the planning commit. No OIDC product code, new dependencies, live tenant, credential provisioning, merge, deployment, or production readiness is claimed.
