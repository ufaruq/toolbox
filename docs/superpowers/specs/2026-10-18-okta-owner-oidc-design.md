# Okta owner sign-in design

Status: implemented on the feature branch; automated verification is recorded in the PR. Live Okta acceptance is pending the user's tenant configuration.

## Goal and intended use

Implement real Toolbox owner sign-in using an Okta OIDC Web Application. The user will create the Okta organization and configure its app; the code, automated tests, setup instructions, and PR must be ready before that external setup is needed. Development must not depend on a live tenant or its credentials.

The first deliverable is a local owner-sign-in milestone. It must demonstrate verified login, isolated owner identity, session expiry and Toolbox logout. Google consent, Picker, document access, agent integrations, and a public production deployment remain separate work.

The existing fixture stays available. The feature branch starts from `main` at `6279f3aab67465aadf5b1ee07f50ed8a99d4bcb4`; the documentation-only PR #3 remains separate. The authentication implementation is identical at that main revision and the documentation branch.

## Approach and alternatives

Use Okta-hosted login with a confidential OIDC Web Application, Authorization Code flow, S256 PKCE, and a first-party Toolbox session. Use `github.com/coreos/go-oidc/v3 v3.21.0` for ID-token verification and `golang.org/x/oauth2 v0.37.0` for the code exchange. These versions were confirmed through Go module metadata on 2026-10-18 and support the repository's Go 1.27.2 toolchain. Do not copy the archived Okta Go sample into the application.

Alternatives considered: configuring Google as the owner IdP, or adding Keycloak as a broker. The user selected direct Okta integration. Neither alternative is needed for this milestone.

## Runtime boundary

Keep `TOOLBOX_MODE=fixture` behavior. Add `TOOLBOX_MODE=oidc-local`, an explicit real-identity, local-development mode. Reject unset and unknown modes. The new mode binds only loopback, uses a fixed configured loopback HTTP origin, and accepts an HTTPS Okta issuer. There is no public-production mode in this change.

OIDC mode exposes health/readiness, static identity UI, auth configuration, login, callback, current session, and local logout. Existing Google, agent, credential, delegation, grant, audit, and invocation APIs return `503 FEATURE_DISABLED`; no integration is called and no state is changed. `/fixture/login` and `/fixture/authorize` are absent. This applies even if the selected database contains previous fixture state.

`server.Config.OwnerOnly` permits nil signer/integration only for the explicit owner-only mode. `Fixture && OwnerOnly` is invalid. No Google fixture provider, delegation signer, agent credential generator, or Google cleanup worker is constructed in `oidc-local`. Its page shows owner sign-in status and explains that Google connections and delegated document access are not configured.

PostgreSQL and OpenBao are required in `oidc-local`; never silently fall back to memory. Local disposable Compose services can be used. The development OpenBao constructor is allowed only in this loopback development mode. This is not a claim that its dev credentials or secret retention are suitable for production.

## Configuration and Okta contract

| Setting | Contract |
| --- | --- |
| `TOOLBOX_MODE` | `oidc-local` for real local owner sign-in; `fixture` retains the synthetic demo |
| `TOOLBOX_ADDR` | Default `127.0.0.1:8080`; host must be a loopback address or `localhost`, with an explicit port |
| `TOOLBOX_ORIGIN` | Required exact loopback HTTP origin matching the listener's configured host and port; no path, userinfo, query, or fragment |
| `TOOLBOX_OIDC_ISSUER` | Required trusted HTTPS issuer; no userinfo, query, fragment, or arbitrary trailing slash normalization |
| `TOOLBOX_OIDC_CLIENT_ID` | Required confidential Web Application client ID and expected ID-token audience |
| `TOOLBOX_OIDC_CLIENT_SECRET` | Required server-side client secret; never logged, committed, or sent to the browser |
| `TOOLBOX_SESSION_PEPPER` | Required base64 encoding of exactly 32 random bytes, stable across restarts |
| `DATABASE_URL` | Required PostgreSQL connection; run additive migrations for this local mode |
| `OPENBAO_ADDR`, `OPENBAO_TOKEN` | Required local secret-store configuration; KV-v2 mount `secret`, matching the current Compose setup; no namespace in this local milestone |

Do not infer the origin, issuer, callback, client, or scopes from request headers or caller input. Derive the callback as `TOOLBOX_ORIGIN + "/auth/oidc/callback"`.

The documented Okta application is named `Toolbox Development`, uses **OIDC / Web Application**, client-secret authentication and Authorization Code flow, with PKCE S256 on each request. The default setup uses the Okta organization issuer, such as `https://integrator-123456.okta.com`; a deliberately configured custom authorization-server issuer is also accepted through exact discovery validation. No custom API authorization server is required for this owner-login use case.

Register `http://127.0.0.1:8080/auth/oidc/callback` as the sign-in redirect for the default local address. Assign only intended test users to the app. Successful tokens for this issuer/client, together with app assignment, are the initial admission policy; Toolbox does not add an email-domain allowlist or administrative roles.

The previously suggested sign-out redirect `http://127.0.0.1:8080/` can be registered, but this milestone implements Toolbox session logout only. It does not invoke Okta-wide logout or retain an ID token for that purpose. An existing Okta browser session can sign the user in again without another password prompt.

## Login and session flow

1. `GET /v1/auth/config` returns only `{fixture, owner_only, login_url}`. The UI's Okta button sends an empty JSON `POST /auth/oidc/start`, requiring the configured Origin and rejecting cross-site fetch metadata. Limit active login transactions to 500 and start requests to 30 per minute per server; return `429` when exhausted.
2. Generate independent cryptographically random state, nonce, initial browser-binding token, and PKCE verifier, each with at least 256 bits of entropy. Set `toolbox_login` as an HttpOnly, SameSite=Lax, Path=/ cookie with a 600-second lifetime. The local HTTP cookie exception is restricted to `oidc-local`; it is not a configurable production override. A replacement start with a recognized live cookie reuses that binding and atomically retires earlier pending flows. Capture the source transaction generation before secret I/O and recheck its unchanged live status before publishing a replacement, so logout during that I/O cannot publish a new login afterward. Concurrent replacement starts may fail closed and require retry.
3. Store the verifier in OpenBao under `owner-login/<transaction-id>`. Persist only hashes, immutable configuration binding, a secret reference, optional prior session ID, expiry, and status in a new `owner_login_transactions` table. SQL and domain snapshots never contain a raw verifier, authorization code, ID token, or client secret. Store the secret before publishing the transaction; failed/uncertain writes never return an authorization URL.
4. Return an authorization URL for fixed scopes `openid`, response type `code`, nonce, state, exact callback and S256 challenge. The browser navigates to Okta. No refresh token or offline scope is requested.
5. `GET /auth/oidc/callback` allows bounded, nonduplicated `state` plus either `code` or `error`; allow optional `iss` only if it exactly matches the configured issuer. Also allow bounded `error_description` and `error_uri` only on error responses and discard their values. State is at most 256 bytes, code at most 4096 bytes, issuer at most 2048 bytes, and each provider error field at most 2048 bytes; reject unknown, empty, duplicated or conflicting fields. Check the binding cookie, state hash, stored issuer/client/callback and database-time expiry. Atomically move `pending` to `exchanging` before the single code exchange. A wrong browser must not consume someone else's transaction.
6. The provider exchanges the code server-side and verifies the ID token: RS256 signature against trusted JWKS, exact issuer, configured audience, expiry, `nbf` when present, a nonempty subject of at most 255 bytes without control characters, expected nonce, and matching `azp` whenever present (required for multiple audiences). Require `iat` and reject issuance more than 60 seconds in the future. Never enable skip-verification flags. Reject malformed/oversized responses and return generic errors without provider bodies or query values.
7. Recheck the transaction's live `exchanging` state and expiry after network I/O. Resolve a user only by verified `(iss, sub)`; never join by email, Google connection identity, or an unverified claim. Preserve disabled users and reject their login. Reuse an existing active user's stable internal ID; otherwise create an active user atomically with the session.
8. Create a fresh random 8-hour Toolbox session, storing only its hash and CSRF hash. Expire the previous browser session by setting `ExpiresAt` to database time, preserving foreign keys from existing Google transactions. Mark login complete atomically. Owner-only requests require the retained completed issuance record to match the configured issuer, client and callback; historical fixture and old-client sessions are rejected. Only then set the session cookie and clear the binding cookie. Discard all OIDC tokens. Failure to persist creates no usable session.
9. `POST /v1/session/logout` requires exact Origin and rejects cross-site fetch metadata. Normal session logout requires the active session and its CSRF token. A matching HttpOnly login-binding cookie also permits cancellation of only that browser's pending/finalizing login, including when its previous session has already expired during rotation; this cancellation path cannot authenticate a user or mutate unrelated state. Atomically expire the authenticated session, cancel its pending/exchanging login transactions, and expire any replacement session recorded on a matching completed transaction. Record `IssuedSessionID` during callback finalization so logout can invalidate a session whose `Set-Cookie` has not arrived yet. Finalization rechecks cancellation and any prior-session validity. Clear cookies after successful revocation. A delayed callback may set an already-expired cookie, but it can never restore access. Logout does not revoke independent agent grants or other browsers' sessions.

Use the existing no-store, no-referrer, content-type and CSP headers. Allow query strings only on the fixed owner callback in addition to existing fixture/Google exceptions. Never log callback URLs, codes, state, verifiers, tokens, cookies, or raw provider errors. Append sanitized successful login and local logout audit events using internal user IDs.

Logout is scoped to the authenticated session and the recognized login binding's chain. Initial anonymous flows started before sharing a cookie cannot be correlated as one browser identity; they are separate cancellation scopes, including across independently initialized tabs. The UI serializes login initiation within its page only. Browser-bound cancellation without an active authenticated session returns `login_cancelled`, not a claim of account-wide logout. The delayed-response guarantee above applies to the identified scopes, not unknown initial flows or other browsers.

## Persistence and outbound HTTP

Add `domain.OwnerLoginTransaction` and `State.OwnerLogins`, update both repository adapters, and add `002_owner_login.sql`. Never edit `001_initial.sql`. Configuration/binding fields are immutable; `IssuedSessionID` starts empty and is set exactly once when transitioning to complete, referencing the hashed session key. Statuses transition `pending -> exchanging -> complete|failed|cancelled` or `pending -> cancelled`. No transition makes a transaction reusable. Add application and SQL protection against mutating an existing user's issuer/subject.

The secret-store namespace is separate from Google OAuth. Cleanup runs every minute in bounded batches of 100: expire login rows, hide their current secret versions, and remove eligible metadata only after cleanup succeeds. Retain completed login metadata while its issued session remains live, so the logout relationship cannot disappear before delayed response delivery. Clean up known orphan references after start failures with a bounded context. Historical OpenBao version destruction remains a production-retention requirement; deletion does not claim erasure.

Discovery must report the exact configured issuer. Authorization, token and JWKS endpoints must use HTTPS and the configured issuer's origin. Use a 10-second HTTP timeout, 1 MiB response bounds and no HTTP redirects or automatic exchange retries. Pin client-secret authentication to `oauth2.AuthStyleInHeader` (`client_secret_basic`) to prevent OAuth2 authentication-style autodetection from retrying the code exchange. Ignore token-header `jku`/`x5u` URLs. Use explicit transport policy rather than inheriting arbitrary proxy settings. A trusted test TLS client can be injected in tests; no runtime switch permits insecure provider TLS. Provider/JWKS lifetime follows application shutdown, not an individual callback context.

## Verification and completion criteria

Tests use a local TLS IdP with actual discovery, JWKS, signed tokens, a token endpoint, PKCE enforcement and exchange-call counters. No Okta account or secret is needed. Test malformed/duplicated callback fields; provider denial; wrong cookie/state/nonce/issuer/audience/algorithm/signature; expired/not-yet-valid tokens; replay; concurrent callbacks; disabled users; two distinct owners; session rotation/expiry/logout/CSRF; logout during exchange and between finalization and cookie delivery; failed/uncertain persistence; dependency outages; cleanup; restart with a stable pepper; and missing/conflicting runtime settings.

Run storage regressions with real disposable PostgreSQL/OpenBao, the full Go race suite, gofmt, vet and build. Add a separate Chromium redirect/login/reload/logout test that permits only the two synthetic test origins and records no credentials or traces. Existing fixture browser tests remain intact. CI needs no live tenant secrets.

The implementation PR must contain the code, additive migration, test evidence, an environment-variable example containing placeholders, and exact Okta setup instructions. Automated synthetic acceptance can pass before tenant setup. Real Okta acceptance remains explicitly unrun until the user provisions the tenant and a real browser login/logout is observed. M1 must not be marked fully complete before that acceptance. M2 and M3 remain open.

## References

- Existing implementation: `internal/server`, `internal/domain`, `internal/store`, `internal/tokens`, `cmd/toolbox/main.go`.
- [Current roadmap in PR #3](https://github.com/ufaruq/toolbox/blob/docs/consolidate-roadmap/docs/ROADMAP.md#m1-real-owner-sign-in).
- [Okta authorization servers](https://developer.okta.com/docs/concepts/auth-servers/).
- [Okta Web Application integration](https://developer.okta.com/docs/guides/sign-into-web-app-redirect/go/main/) (account/app configuration only; the sample is archived).
- [Okta Integrator Free Plan limits](https://developer.okta.com/docs/reference/org-defaults/).
