# Local Okta owner sign-in

`TOOLBOX_MODE=oidc-local` signs an owner into Toolbox through an Okta-hosted login page. It binds to loopback HTTP and requires PostgreSQL and OpenBao. Google connections, Picker, document access, agents and delegation are disabled in this mode, including when a database contains old fixture records. It is a local development milestone; there is no public production mode.

The code and synthetic tests can be prepared and reviewed before you create an Okta account or supply a client secret. **Real Okta acceptance is unrun.** A synthetic pass does not complete M1's live owner-login acceptance. Live Google and production milestones remain open. See the [owner sign-in design](superpowers/specs/2026-10-18-okta-owner-oidc-design.md) and [roadmap in PR #3](https://github.com/ufaruq/toolbox/blob/docs/consolidate-roadmap/docs/ROADMAP.md#m1-real-owner-sign-in).

## Verify without an Okta tenant

Use Go **1.27.2**. Protocol tests use a local TLS identity provider with signed tokens, discovery, JWKS and PKCE enforcement; they need no live account or secrets. Ordinary Go tests do not need Python:

```sh
go vet ./...
go test -race -count=1 ./...
go build ./...
```

Unset `TOOLBOX_TEST_DATABASE_URL` or `TOOLBOX_TEST_OPENBAO_ADDR` causes the corresponding store integrations to skip; a skip is not verification of that store. See [storage test setup](storage.md) for disposable PostgreSQL and the root [README](../README.md#checks) for both integration settings. The separate [OIDC browser flow](../tests/browser/README.md#synthetic-oidc-browser-flow) runs a real Chromium redirect through the synthetic TLS provider. It also requires no Okta account. Keep actual command results and skipped checks with the implementation PR; this guide itself is not execution evidence.

## Create the Okta application after the implementation is ready

1. Create a development organization using the [Okta Integrator Free Plan](https://developer.okta.com/signup/). Use dedicated test accounts.
2. In the Okta Admin Console, open **Applications → Applications → Create App Integration**. Choose **OIDC - OpenID Connect**, then **Web Application**. Name the app **Toolbox Development**.
3. Use **Client secret** authentication (`client_secret_basic`) and enable **Authorization Code**. Toolbox sends an S256 PKCE challenge on every authorization request. If the console offers a separate requirement for PKCE, enable it. Implicit, refresh-token and offline-access flows are not used.
4. Add this exact **Sign-in redirect URI** for the default local address:

   ```text
   http://127.0.0.1:8080/auth/oidc/callback
   ```

   If you change the local host or port, change the registered URI and both local address settings together. `localhost` and `127.0.0.1` are different origins; use the configured spelling throughout.
5. You may register `http://127.0.0.1:8080/` as a sign-out redirect URI, but this milestone does not call Okta logout or use that redirect. The Toolbox logout button expires the local Toolbox session only. An existing Okta browser session can sign you in again without another password prompt.
6. Assign only the intended test users or test group to the application. Successful verification for the configured issuer/client and the app's assignment policy admits an owner. Toolbox does not add an email-domain allowlist or administrator roles, and it identifies owners by verified issuer plus subject rather than email.
7. Save the app and copy its client ID and client secret into your private local environment. Do not place them in a URL, browser UI, screenshot, issue, test artifact or Git commit.
8. Use the exact organization issuer, for example `https://integrator-123456.okta.com`, with no added trailing slash. A custom API authorization server is not required for owner login; do not add `/oauth2/default` by habit. A deliberately configured custom authorization-server issuer is supported when discovery returns that exact issuer. Use the issuer shown by your organization, including its domain suffix.

Toolbox requests only `openid` and discards OIDC tokens after establishing its own eight-hour owner session. It does not request email/profile or retain an ID token for provider logout. Application code exchanges the authorization code server-side with the client secret and PKCE verifier; no client secret goes to the browser.

Toolbox logout revokes the current authenticated session and the recognized login cookie's pending/replacement chain. Independently initialized anonymous flows that do not yet share a cookie are separate cancellation scopes, including initial flows in different tabs. This is not account-wide or Okta-wide logout. Concurrent replacement starts can fail closed; begin a fresh login if that occurs. Sessions originating from fixture login or a different configured OIDC client are rejected in owner mode.

## Configure local dependencies and secrets

Start the existing disposable, loopback-bound stores from the repository root:

```sh
make deps
cp .env.example .env
```

`make deps` starts PostgreSQL and OpenBao and configures the KV-v2 `secret` mount to require CAS. It does not start Toolbox. `make dev` starts the fixture service, so use the owner-mode command below for Okta login.

The committed Compose setup uses database `toolbox`, user `toolbox`, password `fixture-only`, and OpenBao token `fixture-only`. For these disposable stores, replace the corresponding `.env` placeholders with:

```dotenv
DATABASE_URL='postgres://toolbox:fixture-only@127.0.0.1:5432/toolbox?sslmode=disable'
OPENBAO_ADDR=http://127.0.0.1:8200
OPENBAO_TOKEN='fixture-only'
```

Those public development values are appropriate only for the loopback disposable stack. OpenBao dev mode and its token are not production secret storage. Stopping or recreating the stores can lose local identity, session and login state. Use a dedicated disposable database rather than sharing an active fixture process's stores. Cleanup hides current verifier-secret versions; it does not claim to erase historical OpenBao versions.

Replace every remaining `<...>` placeholder in `.env`. Generate the session pepper locally:

```sh
openssl rand -base64 32
```

Copy that output into `TOOLBOX_SESSION_PEPPER` and keep the same value across restarts of this local environment. It must decode to exactly 32 random bytes. Do not commit or publish the generated value. `.env` is ignored; `.env.example` contains only credential placeholders.

| Variable | Required value or behavior |
| --- | --- |
| `TOOLBOX_MODE` | Explicit `oidc-local`; `fixture` remains the separate synthetic demo. Unset and unknown modes are rejected. |
| `TOOLBOX_ADDR` | Loopback host and explicit port; defaults to `127.0.0.1:8080`. Public/wildcard listeners are rejected. |
| `TOOLBOX_ORIGIN` | Exact loopback HTTP origin matching the listener's host and port, for example `http://127.0.0.1:8080`. No path, userinfo, query or fragment. |
| `TOOLBOX_OIDC_ISSUER` | Exact trusted HTTPS issuer, with discovery matching it. No userinfo, query or fragment. |
| `TOOLBOX_OIDC_CLIENT_ID` | Confidential Web Application client ID; expected ID-token audience. |
| `TOOLBOX_OIDC_CLIENT_SECRET` | Server-side client secret from that app. |
| `TOOLBOX_SESSION_PEPPER` | Stable base64 encoding of exactly 32 random bytes. |
| `DATABASE_URL` | Required PostgreSQL connection. Startup applies additive migrations; there is no in-memory fallback. |
| `OPENBAO_ADDR`, `OPENBAO_TOKEN` | Required local OpenBao connection with KV-v2 mount `secret`; namespaces are not supported in this milestone. There is no in-memory fallback. |

The callback is always `TOOLBOX_ORIGIN` plus `/auth/oidc/callback`; request headers and browser input cannot select it, the issuer, client or scopes. Provider discovery, token and JWKS endpoints use trusted HTTPS on the issuer's origin. There is no runtime option to disable provider TLS verification.

## Run and perform live acceptance

The executable does not read `.env` automatically. Load your edited local file and start it from the same shell:

```sh
set -a
. ./.env
set +a
go run ./cmd/toolbox
```

Open the exact `TOOLBOX_ORIGIN` and choose **Sign in with Okta**. Missing required settings, an invalid pepper, an origin/listener mismatch, or unavailable required stores prevents startup or readiness; it never switches to fixture identity. For sign-in failure, check the exact issuer, app assignment, client secret and registered callback in your private configuration. A generic callback error does not justify publishing the callback URL or provider response.

Record live acceptance separately after the tenant is configured:

1. Sign in as an assigned test owner and verify the owner status. The page must not expose Google/agent controls.
2. Reload and verify the same owner session remains active. A later sign-in for that verified issuer/subject must retain the same internal owner ID, including after an application restart with unchanged stores and pepper.
3. Use **Sign out of Toolbox** and verify the local owner session no longer authenticates after reload. A fresh login can reuse the existing Okta browser session; this is expected local logout behavior.
4. Use another browser profile for a second assigned test user and verify that it receives a distinct internal owner ID and independent session.
5. Record the tested revision, date, issuer/app identifiers and pass/fail outcomes without secrets or callback URLs. Leave live acceptance marked unrun until an actual Okta browser login and Toolbox logout have been observed.

Do not capture browser traces, network query logs, cookies, authorization codes, raw state/nonces, verifiers, tokens or provider error bodies as evidence. Local owner sessions expire after eight hours; the synthetic tests cover expiry and negative protocol/session cases without waiting for a live session to expire.
