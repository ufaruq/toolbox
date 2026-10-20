# Local MCP with the real Workspace runtime

Merge order: #10 first, then #7. The MCP branch includes #10 so it can be tested before either is merged. Do not merge until the remaining live acceptance gates pass.

## Runtime and identity

Use `workspace-local` from [Workspace setup](workspace-demo.md). Keep the existing Okta Web client, organization issuer, callback, stable crypto, database and OpenBao configuration. There is one owner-login implementation, at `/auth/oidc/start` and `/auth/oidc/callback`; the earlier draft's `/auth/okta/callback` and standalone `hosted` mode are superseded. Public production deployment belongs to #4.

MCP uses a separate Okta **custom authorization server**, pinned to the same tenant as the owner organization issuer. Existing owners retain their organization issuer/subject key and Google connections. The verified access-token `uid` matches the organization's ID-token `sub`; the access-token `sub`, email and browser-provided identity fields are not used for linking. A different tenant or organization issuer is rejected.

This follows [Okta's reserved token claims](https://developer.okta.com/docs/api/openapi/okta-oauth/guides/overview/) and [access-token validation guidance](https://developer.okta.com/docs/guides/validate-access-tokens/). Org access tokens are for Okta APIs; use the custom server's token for Toolbox.

## Configure the Okta API and client

1. In **Security → API**, configure a custom authorization server such as `default`. Set its audience to the exact Toolbox resource, for example `http://127.0.0.1:8080/mcp` locally. Create an `mcp` scope and an access policy allowing the intended users and registered agent clients.
2. Register a separate native/public OAuth client for a local MCP client. Use authorization code with S256 PKCE and no client secret. Register the exact callback supported by that client; callback configuration is client-specific, while Toolbox permissions are the same for all clients. Keep the existing confidential Web client for owner login separate.
3. Ensure the API access token contains signed `iss`, `aud`, `uid`, `cid`, `scp` with `mcp`, `iat` and `exp`. Toolbox checks the signature and these claims. ID tokens and client-only tokens cannot authenticate an MCP caller.
4. Add these optional values to the private `.env` already used by `make workspace`:

```sh
TOOLBOX_MCP_ISSUER='https://<your-okta-org>.okta.com/oauth2/default'
TOOLBOX_MCP_CLIENTS='{"<native-oauth-client-id>":"Local agent"}'
```

Both settings are required to enable MCP. Omitting both retains the existing Google-only Workspace app. Duplicate, empty, unknown-owner-tenant and role-confused client configuration is rejected. Do not use the owner Web client's ID as an MCP client ID.

5. Restart with `make workspace`. Sign in with Okta, connect Google and choose a harmless native Google Doc as described in the Workspace guide.
6. Expand **Agent clients · MCP permissions**. Select the configured registration, review the read-tool ceiling and expiry, and approve it. Each registration has its own persisted Agent and document grants. Multiple sessions of one registration share this approval; this is not device attestation.
7. Configure the local client's standard Streamable HTTP MCP connection to `http://127.0.0.1:8080/mcp`, using its registered client ID and Okta authorization-code/PKCE flow with the `mcp` scope. Use the client's supported OAuth configuration; a real Codex/Claude Code configuration has not yet been validated for this integration. A later hosted connector needs reachable HTTPS and its own exact registration.

Toolbox publishes protected-resource metadata at `/.well-known/oauth-protected-resource/mcp` and the root fallback, pointing directly to the pinned custom authorization server. Native clients may omit `Origin`; browser origins must match Toolbox. Bearer credentials belong in the authorization header.

## Tool and approval flow

The three MCP tools are:

- `toolbox_request_document_access`: request a bounded read of an exact document and receive an owner approval URL.
- `toolbox_get_access_request`: poll the calling agent's request and obtain the grant ID after approval.
- `google_drive_read_document_v1`: read the approved document using the same provider and authorization engine as HTTP.

Open the approval URL in the owner browser, sign in if needed, review the verified client/agent/account/document/expiry, then approve. Agent authentication never grants document access by itself. Provider credentials and internal delegation tokens are not returned to MCP clients.

Disabling a caller revokes its grants and cancels pending requests. Re-enabling it or changing the ceiling requires fresh document approval. Expiry, other-client/document denial, revocation and final content-release checks apply equally through HTTP and MCP.

## Storage and upgrade

Migrations 001–003 from main are unchanged. Additive 004 creates caller profiles and 005 adds audit attribution. Existing organization owners, sessions, Google connections and grant state remain in their original tables. The superseded MCP draft's standalone owner-login table is not installed. Do not reuse a disposable database previously migrated by that unreleased draft: its migration ledger is a different history. Recreate that test database; never rewrite checksums in a live store.

The reference PostgreSQL adapter still uses a bounded whole-state snapshot. Caller tables and audit fields contain no OAuth tokens or PKCE material; secrets remain in OpenBao.

## Verification and limits

Automated coverage uses signed local issuers and simulated Google data: canonical owner binding, exact tenant/client/scope checks, SDK discovery/request/approval/read, cross-client/document denial, expiry, disabled callers, in-flight final release, legacy HTTP cancellation, main-schema upgrade, UI client controls and the #10 browser regressions.

Real Google Picker/document acceptance remains pending in #10. Actual Okta custom-server issuance and a local Codex/Claude Code OAuth/MCP session have not been verified here. SDK/synthetic tests must not be reported as a live agent demo. Keep both remaining gates visible before merge.
