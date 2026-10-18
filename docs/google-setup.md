# Google connection setup and release gates

[Project overview](../README.md) · [Current roadmap](ROADMAP.md) ·
[Implementation evidence](implementation-status.md)

This is the technical reference for Google integration. The [roadmap](ROADMAP.md)
is the single pending-work index: **M1** covers real owner OIDC, **M2** covers live
Google/Picker wiring and acceptance, and **M3** covers a deployable controlled
pilot, including persistent/rotatable keys, least-privilege stores, secret cleanup
and operations. **M4** covers larger-workload storage, rate limits and retention;
optional agent clients/MCP (**F1**) and more tools/providers (**F2**) are future
features, not prerequisites for proving this Google integration.

The repository includes real Google OAuth and Drive adapters and an explicit
fixture provider. The executable wires fixture Google/Drive only, creates an
ephemeral signer and credential pepper on each start, and has no real Picker UI.
The real adapters are not configured or validated for live use. This work has
**not** created a Google Cloud project or OAuth client,
used real credentials, completed a real Google consent flow, proved Google's
PKCE enforcement, or run the real Drive/Picker integration spike.

The runnable fixture is deliberately a development demonstration. A fixture
owner session or fixture Google subject is not human authentication. Production
owner OIDC, deployment identity, and live Google integration remain release gates.
Do not expose fixture login or `/fixture/authorize` on a public deployment.

## 1. Keep owner identity separate

A human signs in to Toolbox through a selected production OIDC identity provider.
That integration must validate the provider's signature, configured issuer,
audience, nonce and lifetime, then establish a secure first-party server session.
Select and implement this integration before enabling a production server. Do not
replace it with a user ID from JSON, an unverified JWT claim, a trusted-looking
header, or fixture login.

The Google account connected for Drive can differ from the Toolbox sign-in
account. `oauth.Service` takes the authenticated owner and session IDs from the
server and checks the active owner, session ownership and DB-time expiry. It does
not create or authenticate Toolbox users. It records Google's validated `sub` as
the connection identity; email is not an account key. The owner UI should show
which Google account is connected before approving any delegation.

## 2. Prepare a dedicated Google test configuration

These are operator steps, not actions performed by this implementation:

1. In a separate Google Cloud test project, enable the Google Drive API and, when
   integrating the real selection UI, Google Picker API.
2. Configure the consent screen and limited test users. Request only `openid` and
   `https://www.googleapis.com/auth/drive.file`. No `drive.readonly`, broad `drive`,
   `email`, or `profile` fallback is implemented.
3. Create a web-application OAuth client. Register the **exact** configured
   callback URI. The fixture server currently uses
   `http://127.0.0.1:8080/oauth/callback`; use the actual configured local port.
   The adapter accepts `/oauth/callback` or `/v1/oauth/google/callback` as its fixed
   path. Production callbacks must use HTTPS. Local HTTP requires the explicit
   `AllowLoopbackHTTP` option and `localhost`, `127.0.0.1`, or `::1`.
4. Supply the client ID and client secret through a reviewed server-side secret
   mechanism. Never commit them, enter them into the owner UI, place them in
   callback URLs, or persist them in Postgres. Do not reuse production credentials
   for local development.
5. Restrict the Picker API key to the intended APIs and browser origins; use the
   same reviewed project/client identity for the OAuth grant, Picker app ID
   (project number), and Drive access. Use synthetic documents and accounts for
   the spike.

`drive.file` can confer creation/modification authority over app-authorized files.
Toolbox narrows its own tools to the approved read operation; the Google token is
not intrinsically read-only or bound to the agent's one document. Picker's required
access-token exposure to the trusted owner browser must be explicitly accepted
before the real Picker UI is released. Keep that token in memory only, use
`Cache-Control: no-store`, and disclose its actual provider expiry. Refresh tokens
must never reach the browser or agent.

## 3. Mandatory PKCE enforcement spike

`NewGoogleProvider` refuses construction unless `GoogleConfig.PKCEValidated` is
true. This is an operator-controlled release assertion, **not evidence** that the
provider enforced PKCE. Leave it false until the following tests are completed
against the exact Google project, web client and callback intended for release:

- Authorize with a random verifier and its SHA-256/S256 challenge; exchange the
  code using the matching verifier and confirm success.
- Authorize a fresh, separate code with an S256 challenge; omit `code_verifier`
  during exchange and confirm rejection.
- Authorize another fresh code; supply a different, valid-shaped verifier and
  confirm rejection.
- Use a fresh transaction for each negative test. A previously consumed code
  failing again proves only code reuse protection, not PKCE enforcement.
- Repeat the positive flow after negative tests. Preserve only sanitized results
  and configuration identifiers in the review record, never codes, raw state,
  nonces, verifiers, client secrets or provider tokens.

Also verify that the exact `openid` plus `drive.file` request returns the required
ID token and exact granted scopes. Google's current OIDC endpoint reference says
its scope list includes `openid` plus `profile` or `email`; this differs from the
minimal design adopted here and must be resolved by the real-project spike and
review. The implementation intentionally does not add personal-data scopes. If
the minimal request does not work, treat the scope/identity design as blocked and
obtain review before changing it.

If either negative test succeeds, do not set the flag. Revise the architecture or
client arrangement and review the result. Do not omit the challenge, switch to
plain PKCE, remove the verifier, or silently weaken the flow to obtain a working
demo. Fixture PKCE tests and mocked Google HTTP tests do not satisfy this gate.

The adapter always sends `code_challenge_method=S256`, the challenge, and the
server-held verifier. The fixed authorization request also contains the nonce,
offline access, an account/consent prompt, and `include_granted_scopes=false`.
Callbacks and scopes are server configuration, never agent/request parameters.

## 4. Library integration

```go
provider, err := oauth.NewGoogleProvider(oauth.GoogleConfig{
    ClientID:          configuredClientID,
    ClientSecret:      injectedClientSecret,
    CallbackURL:       "https://toolbox.example/oauth/callback",
    PKCEValidated:     false, // Deliberately fails until the release gate is met.
    AllowLoopbackHTTP: false,
})
if err != nil {
    // Return a sanitized configuration failure. Never log the config object.
    return err
}
service, err := oauth.NewService(repo, bao, provider)
```

This shows the library API, not an assertion that live server configuration is
wired or production owner login is complete. The same `provider` implements
`tokens.Provider` for coordinated refresh and revocation. There is no SDK token
source performing background refresh outside that coordinator.

The trusted owner endpoint calls:

- `Start(ctx, ownerID, sessionID)` after first-party authentication, CSRF and
  same-origin checks. It returns `AuthorizationURL`, `ConnectionID` and
  `ExpiresAt`. Redirect only to that returned URL.
- `Complete(ctx, ownerID, sessionID, state, code)` for the fixed callback. Require
  a single state and code value; reject malformed/duplicate callback parameters
  and provider error callbacks before exchanging. The callback uses the same
  first-party session. Do not derive owner/session from query parameters or
  from the Google subject. Do not treat the callback as grant approval.

Provider cancellation or an unknown exchange outcome leaves a blocked pending
connection. A rejected response containing known credentials is retained only for
cleanup; a missing refresh token can mark the connection `needs_reauth`. None of
these states has execution rights. Completing a new connection does not create a
document selection or agent grant. The owner must select/verify the document and
explicitly approve new delegation.

## 5. Persistence and failure behavior

- Each start creates a new random connection ID and a ten-minute, one-use
  transaction. Postgres contains owner/session bindings, hashes of state/nonce,
  expiry, and an internally generated secret reference. Only OpenBao receives
  the PKCE verifier; codes are neither persisted nor logged.
- The callback atomically validates and consumes the transaction before it reads
  the verifier or calls Google's token endpoint. A failed/uncertain exchange
  cannot be replayed. The owner starts a fresh transaction.
- The Google adapter verifies RS256 signatures using the fixed
  `https://www.googleapis.com/oauth2/v3/certs` trust endpoint. It validates
  Google issuer, configured client audience, authorized party where applicable,
  subject, expiry/issued time and nonce. It never follows JWT-provided `jku` or
  `x5u` URLs. It rejects missing, unexpected, or broadened granted scopes.
- Before calling the token endpoint, the service locks the connection, rechecks
  its pending state and live owner session, and CAS-writes a durable,
  operation-bound `refreshing` intent at `connections/{connection_id}`. It checks
  unlock success before dispatching the exchange. The provider call runs outside
  that lock. Disconnect cleanup cannot treat an unresolved intent as completed
  merely because credentials have not arrived.
- Known exchange credentials are persisted using a bounded detached context,
  including after cancellation, expired sessions, disconnect, and rejected
  identity/scope results. The service reacquires the connection lock and replaces
  only its original CAS intent. A valid complete bundle can activate the DB
  connection only after fresh identity, scope, session, lifecycle and expiry
  checks. An access-only response is retained as cleanup-only and changes the DB
  connection to `needs_reauth` when the session/lifecycle checks still pass; it
  never activates the connection.
- A secret-write timeout is reconciled only when a strictly newer version at the
  authoritative stable path contains the exact operation and complete expected
  bundle. This applies to the intent and response writes. No blind write or
  code-exchange retry occurs. Unknown exchange outcomes remain fenced by the
  unresolved intent and keep provider cleanup pending.
- If the post-exchange lock cannot be reacquired, the service uses a fresh bounded
  detached deadline to attempt CAS persistence of the known response as
  cleanup-only. A competing generation is never overwritten. If activation fails
  or the lock is lost, the service attempts to convert its exact persisted
  response to cleanup-only and mark an already-active matching DB connection
  `needs_reauth`. Failed or uncertain persistence returns an error and requires
  durable-state review; it does not establish cleanup completion or authorize
  automatic activation of an orphan. Reconnect uses a new connection. Review
  retained operations and provider cleanup
  before retiring old records: account-level revocation can affect other
  connections for the app.
- The consumed verifier's current KV version is deleted on a best-effort basis.
  Start failures, secret-read failures and crashes can leave orphans. A
  separately permissioned expiry/retention job must remove expired OAuth secrets
  and destroy retained KV historical versions before production; current-version
  deletion alone is not physical erasure.
- A lost connection-lock session causes the callback to return a sanitized
  persistence error rather than success. DB activation or provider work may
  already have occurred when lock loss is discovered; the lock does not provide
  atomic fencing of Google's endpoint. Durable state and lifecycle/epoch checks
  remain authoritative.
- Reconnect creates a new connection ID and path. Old grants remain bound to the
  old connection/epoch and cannot silently revive when the Google account changes.
- Revocation accepts HTTP 200 or the specific HTTP 400 `invalid_token` result as
  terminal for the stored credential. Google's reference defines the latter as
  expired or already revoked. This supports idempotent cleanup after a lost write
  response; it does not prove removal of every historical account/project grant.
  Generic errors, including `invalid_request`, keep cleanup pending.
- Refresh responses that omit a refresh token or scope leave preservation to the
  durable token manager. Refresh outcome uncertainty is not automatically retried;
  `invalid_grant` requires reconnect. Provider error bodies are never surfaced.

Google HTTP calls use fixed HTTPS endpoints, bounded timeouts/body sizes, no
redirects, no ambient proxy, and public-address-only dialing. Add deployment-level
egress controls and workload-secret authentication as independent protections.

## 6. Verification and live acceptance criteria

Run the local tests with the pinned toolchain:

```sh
go test -race ./internal/oauth
go test -race ./...
```

OAuth tests cover wrong state/session/owner, nonce mismatch, transaction expiry,
callback replay and races, missing/mismatched fixture PKCE, missing refresh token,
scope mismatch, initial secret failures, reconciliation of a confirmed write,
new-identity reconnect, signed ID-token claim failures, signature/algorithm/key URL
rejection, fixed token/JWKS/revocation endpoints, redirect refusal, and durable
exchange-intent/cleanup races. Coverage includes late responses after disconnect,
caller cancellation or session expiry, post-exchange lock loss, uncertain writes,
and competing generations. They use synthetic credentials and do not contact
Google. The recorded verification at `f6e9c7c` includes 280 Go tests/subtests with
real PostgreSQL/OpenBao and Chromium fixture checks; see
[implementation evidence](implementation-status.md) for scope and provenance.
This documentation update does not rerun those application checks.

The acceptance criteria for roadmap **M1–M3** include real owner OIDC integration,
the PKCE spike, Google Picker selection under the chosen app identity, Drive metadata plus
plain-text export of a native document, denied/unselected document behavior,
revoked provider access, re-consent/missing-refresh behavior, cross-account consent,
restricted downloads and multi-tab coverage. Confirm consent-screen publishing,
verification and test-user/token lifetime rules for the actual project. Confirm
production OpenBao history destruction, orphan cleanup, backups, and audit
retention. These remain unresolved live-release gates; fixture and real-store
test passes do not close them. Track their current status in the roadmap.

## Official references

Checked 18 October 2026. These sources describe provider behavior; they do not
prove that this app's unperformed configuration/spike passes.

- [Google OAuth for web server applications](https://developers.google.com/identity/protocols/oauth2/web-server)
- [Google OpenID Connect](https://developers.google.com/identity/openid-connect/openid-connect)
- [Google OIDC endpoint reference and revocation errors](https://developers.google.com/identity/openid-connect/reference)
- [Google OIDC discovery metadata](https://accounts.google.com/.well-known/openid-configuration)
- [Drive OAuth scope selection](https://developers.google.com/workspace/drive/api/guides/api-specific-auth)
- [Google Picker integration](https://developers.google.com/workspace/drive/picker/guides/web-picker)
- [Google OAuth token expiration](https://developers.google.com/identity/protocols/oauth2#expiration)
