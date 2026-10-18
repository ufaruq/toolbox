# Hosted MCP setup with direct Okta authentication

Toolbox serves its owner UI, HTTP API and stateless Streamable HTTP MCP endpoint from one application image. Okta issues access tokens directly; there is no broker, Hydra service or MCP proxy. The database and OpenBao are separately operated durable dependencies. Terminate public HTTPS at the deployment ingress and forward to the application on its private bind address.

**Live Google runtime wiring is not included.** Hosted mode uses an explicit unavailable provider: Google connect, document inspection/read and provider cleanup fail closed. Owner Okta login, caller-profile management and MCP authentication can operate, but a real hosted Google document read cannot pass yet. Fixture/library tests exercise authorization with synthetic providers; they do not prove compatibility with a live tenant, Claude client or Google deployment. Corporate-account eligibility/linking is tracked separately in [PR #6](https://github.com/ufaruq/toolbox/pull/6).

## Runtime configuration

Select `TOOLBOX_MODE=hosted` explicitly. Configuration is validated before dependencies are opened. Never put production secrets in source, the image, committed environment files, command arguments or logs; inject them through your deployment's secret mechanism.

| Variable | Hosted value |
| --- | --- |
| `TOOLBOX_PUBLIC_ORIGIN` | Public HTTPS origin, for example `https://toolbox.example`; no path, credentials, query or fragment. Use a canonical lowercase ASCII hostname (Punycode for international domains), omit the default `:443`, and avoid trailing host dots or leading zeros in ports. Noncanonical browser origins are rejected. |
| `TOOLBOX_ADDR` | Private listen IP and port; default `0.0.0.0:8080`. |
| `DATABASE_URL` | PostgreSQL URL with explicit `sslmode=verify-full`, trusted server CA, verified hostname and no alternate-host/TLS fallback. Runtime role must have no schema ownership or DDL privileges. |
| `OPENBAO_ADDR` | HTTPS OpenBao origin with trusted TLS. |
| `OPENBAO_TOKEN` | Least-privilege workload token; never a development/root token. |
| `OPENBAO_MOUNT` | Existing KV-v2 mount; default `secret`. |
| `OPENBAO_NAMESPACE` | Optional deployment namespace. |
| `TOOLBOX_OKTA_ISSUER` | Exact custom authorization-server issuer, such as `https://tenant.okta.com/oauth2/default`. |
| `TOOLBOX_OKTA_OWNER_CLIENT_ID` | Separate confidential OIDC application for owner login. |
| `TOOLBOX_OKTA_OWNER_CLIENT_SECRET` | Owner OIDC application secret. |
| `TOOLBOX_MCP_CLIENTS` | JSON object of registered OAuth client IDs to display labels, such as `{"web-client-id":"Claude.ai","code-client-id":"Claude Code"}`. Duplicate/blank entries are rejected. |
| `TOOLBOX_SIGNING_SEED` | Persisted standard-base64 encoding of exactly 32 random bytes for Ed25519 signing. |
| `TOOLBOX_SIGNING_KEY_ID` | Stable nonblank signing key identifier. |
| `TOOLBOX_CREDENTIAL_PEPPER` | Persisted standard-base64 encoding of exactly 32 independently generated random bytes. |

The access-token audience is derived as `${TOOLBOX_PUBLIC_ORIGIN}/mcp`; there is no audience override. Owner callback is derived as `${TOOLBOX_PUBLIC_ORIGIN}/auth/okta/callback`. Persist the seed, key ID and pepper across restarts. Generate the seed and pepper independently with a cryptographic random generator into your secret manager. Rotation requires a deliberate session/credential/token invalidation plan; this version has one signing key.

Use verified TLS for every hosted dependency. Supply private CA files through deployment mounts and the relevant platform trust settings; for PostgreSQL, include the mounted `sslrootcert` path in the DSN when a private CA is needed. The application never enables identity's loopback HTTP test option in hosted mode. No memory repository or memory secret-store fallback is used if a dependency is missing or unavailable. Startup verifies the migrated PostgreSQL schema with a bounded snapshot transaction and checks OpenBao; `/readyz` repeats those checks. This readiness probe uses the same low-throughput adapter and must be monitored accordingly. `/healthz` is process liveness.

Apply migrations before starting the runtime with a separate, short-lived migration identity:

```sh
# Inject DATABASE_URL for the migration owner through your secret mechanism.
TOOLBOX_MODE=hosted ./toolbox migrate
# Replace DATABASE_URL with the less-privileged runtime identity before serving.
TOOLBOX_MODE=hosted ./toolbox
```

`migrate` needs the selected mode and database URL, not Okta, OpenBao or signing settings. Hosted startup never runs schema migrations. See [storage.md](storage.md) for runtime privileges, audit protection and the complete-snapshot adapter's throughput limitations. Grant the runtime role access to the new `caller_profiles` and `owner_logins` tables too, and read-only `SELECT` on `toolbox_migrations` for readiness checks. Give OpenBao only the KV-v2 read/write/delete access needed for `connections/*`, OAuth transaction secret paths and `owner-logins/*`; historical secret-version destruction belongs to a separate retention operator.

## Okta authorization server and registrations

1. Use one Okta custom authorization server with API audience exactly `https://toolbox.example/mcp` and scope `mcp`. Configure an access policy permitting only assigned users and the explicitly registered clients, with authorization code and S256 PKCE. This server verifies RS256 tokens; configure the authorization server accordingly.
2. Include the same immutable Okta user-ID claim named `uid` in **both** owner OIDC ID tokens and MCP API access tokens. For an appropriate Okta tenant this can use `user.getInternalProperty("id")`; verify the tenant's expression and claim configuration. Do not use email, display name, or configurable `sub` as the owner key. API access tokens also require Okta's registered client claim `cid`, `scp` containing `mcp`, and valid `iat`/`exp` (and `nbf` when present).
3. Register the owner web application separately as confidential OIDC, authorization-code/S256, `client_secret_basic`, with the exact HTTPS callback `https://toolbox.example/auth/okta/callback`. Owner login requests `openid`. Configure `uid` on those ID tokens and assign the owners. An owner session or ID token never authenticates MCP.
4. Register Claude Code as a native/public OAuth client: authorization code, S256 PKCE, token endpoint authentication `none`, exact fixed-port loopback redirect `http://localhost:8765/callback`. Use the same fixed port in the installed CLI. Do not supply a confidential secret to this public registration.
5. Register Claude.ai separately as confidential OAuth: authorization code, S256 PKCE, `client_secret_basic`, exact redirect `https://claude.ai/api/mcp/auth_callback`. Put its client ID and secret into Claude.ai's supported custom-connector settings. Do not enable dynamic client registration merely to avoid this registration step.
6. Add the two MCP registration IDs to `TOOLBOX_MCP_CLIENTS` with distinct labels and assign the intended users. Ensure issuer discovery, authorization, JWKS and token endpoints are reachable through trusted HTTPS. Configure refresh-token policy and client refresh behavior if long-lived sessions are needed; Toolbox accepts the current access token on every MCP request and does not hold a Claude client's refresh token.

Protected-resource metadata is at `https://toolbox.example/.well-known/oauth-protected-resource/mcp` with a root metadata fallback. A missing/invalid bearer token receives a 401 challenge referring to that metadata; metadata points directly to the configured Okta issuer and `mcp` scope.

## Client and owner setup

**Approve the caller profiles before the first Claude connection.** An owner signs in at `https://toolbox.example/auth/login`, then creates one caller profile for each desired registered client in the owner UI. Select its permitted tools and an explicit duration of at most 30 days. The verified `(issuer, uid, cid)` selects that profile and its own Toolbox Agent. Separate web and Code registrations therefore get separate grants. Multiple installations/sessions using the same user/client registration share permissions; independent installation profiles require independent registrations.

An otherwise valid token without an active approved caller profile receives 403 deliberately. That denial may close the SDK client session; after an owner creates/enables the profile, reconnect or authenticate the client again.

For a Claude Code version that supports preconfigured OAuth registrations:

```sh
claude mcp add --transport http --client-id YOUR_CODE_CLIENT_ID --callback-port 8765 toolbox https://toolbox.example/mcp
claude
# Use /mcp to authenticate the toolbox connection in the CLI.
```

Check `claude mcp add --help` for the installed CLI version before registration, and verify the authorization request's exact callback and requested scopes against Okta. These commands describe the intended configuration; real Code/Okta acceptance must still be run.

In Claude.ai, add a custom connector using `https://toolbox.example/mcp`. Set **Authentication → Sign in now**, then **OAuth client → Use your own OAuth client**, and supply its separately registered confidential client ID and secret. Complete the Okta login only after the owner has approved this client profile; the default client choice is a different registration. Verify the exact callback against the registration and confirm that the issued access token's `aud`, `uid`, `cid` and scope match the API configuration. Neither a caller label nor an MCP session ID proves a physical installation's identity.

After live Google wiring is available, connect the owner's Google account, request exact-document access from the client, and approve that request in the owner UI. Merely creating a caller profile never grants document access. Disabling a profile revokes its grants and cancels pending requests. Explicitly enabling it restores authentication with new tools/duration, but old grants and requests remain unusable.

See the official [Claude Code preconfigured OAuth credentials guide](https://code.claude.com/docs/en/mcp#use-pre-configured-oauth-credentials) and [Claude.ai remote custom connectors guide](https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp) for the current client controls.

## Container and fixture operation

```sh
docker build -t toolbox:local .
# Inject the complete hosted configuration through the platform secret settings.
docker run --rm --env-file /secure/runtime.env -p 127.0.0.1:8080:8080 toolbox:local
```

The image runs a static binary as a non-root user and includes only that binary and the runtime base's trust data. Build-only corporate proxy trust can be supplied with `docker build --secret id=proxy_ca,src=/secure/proxy-ca.pem ...`; that secret is mounted for build commands and never copied into the image. Runtime private CA trust is a separate deployment concern. The container healthcheck runs `toolbox healthcheck` against the private local `/readyz`, including schema and dependency readiness. Run the migration as a separate job using the same image with argument `migrate` and the migration identity.

Local fixture behavior remains explicit and loopback-only:

```sh
TOOLBOX_MODE=fixture go run ./cmd/toolbox
# Container fixture mode must override the image's wildcard bind.
docker run --rm -e TOOLBOX_MODE=fixture -e TOOLBOX_ADDR=127.0.0.1:8080 toolbox:local
```

Fixture mode uses synthetic identity/Google and ephemeral crypto, with in-memory stores by default. Existing optional `DATABASE_URL` and `OPENBAO_ADDR`/`OPENBAO_TOKEN` settings remain available for disposable local dependencies; fixture startup retains its convenience migration behavior. The repository's Compose credentials and development OpenBao must never be used for hosted mode.

## Real acceptance checklist and current limits

Before claiming a live deployment, record real evidence for issuer discovery/signatures, wrong audience/client/scope denial, owner nonce/state/PKCE, exact callbacks, token expiry/refresh, secure cookies, migrations/runtime role separation, durable restart behavior, OpenBao policy and both Claude clients. Test one owner with web→document A and Code→document B, cross-denials, disable during an in-flight export with no content released, enable with no restored rights, fresh approval, and continued access for the other client.

Hosted Google export is currently unavailable, so the document portion of this real acceptance checklist is blocked on the separate live-Google milestone. The synthetic fixture/SDK tests and container startup checks must be reported separately from real Okta, Claude.ai, Claude Code and Google acceptance.
