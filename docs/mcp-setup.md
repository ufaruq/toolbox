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
6. Expand **Agent clients · MCP permissions**. Select the configured registration, review the read-tool ceiling and expiry, and approve it. Confirmation appears in that panel, and the saved entry shows its status and expiry. Approve each registration once. **Save name** renames the existing Agent without changing its identity, permissions, pending requests or document grants; review an open request again to refresh the displayed name. **Update permissions** and **Enable caller** use the tools and duration above, revoke existing document grants and cancel pending requests. Multiple sessions of one registration share its approval; this is not device attestation.
7. Configure the local client's standard Streamable HTTP MCP connection to `http://127.0.0.1:8080/mcp`, using its registered client ID and Okta authorization-code/PKCE flow with the `mcp` scope. Codex CLI 0.163.0 has completed actual OAuth, discovery, request, approval and Google read acceptance; see the verification record below. Claude Code has not completed that live acceptance. A later hosted connector needs reachable HTTPS and its own exact registration.

### Validated Codex configuration

Use the exact callback printed by the installed Codex client. Codex may append a
server-specific identifier to `/callback` when the issuer does not advertise
issuer-bound authorization responses. Register that complete URL in the native
app's **Sign-in redirect URIs**; a URI ending at `/callback` does not cover its
longer path. The callback's explicit port must match `callback_port`.

```toml
[mcp_servers.toolbox-local]
url = "http://127.0.0.1:8080/mcp"
scopes = ["openid", "mcp"]

[mcp_servers.toolbox-local.oauth]
client_id = "<native-client-id>"
callback_port = 8765
callback_url = "<exact-Codex-callback-URL>"
```

Then authenticate with `codex mcp login toolbox-local --scopes openid,mcp`.
The tested flow used S256 PKCE and requested no `offline_access`. Keep the native
app's Refresh Token grant disabled for this access-only configuration. The
tested access-policy rule allowed Authorization Code, assigned users, `openid`
and `mcp`, with an eight-hour access-token lifetime. Refresh-token lifetime
fields in the rule do not themselves enable the app's Refresh Token grant.
Requiring fresh authentication after eight hours also needs the app's sign-in
policy configured; expiring an access token does not expire the browser's Okta
session. That reauthentication policy has not yet been verified.

See [Codex MCP configuration](https://learn.chatgpt.com/docs/extend/mcp) and
[Okta access policies](https://developer.okta.com/docs/guides/customize-authz-server/main/#create-access-policies).
Use the configured Toolbox browser origin exactly: `localhost:8080` and
`127.0.0.1:8080` are different origins, and owner sign-in rejects an unexpected
origin. The native OAuth callback can separately use `localhost:8765`.

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

### Actual local acceptance, 19 October 2026

The combined candidate based on `839e11c6e254f9dc534eb265840905589d922b20`
completed these checks with the actual Okta tenant and Google account:

- Owner sign-in, Google connection, real Picker selection, metadata review and
  approved HTTP test-client export succeeded. Drive initially returned
  `403 SERVICE_DISABLED`; enabling Drive API in the OAuth project resolved it.
- Codex CLI 0.163.0 completed authorization-code/S256 login with `openid mcp`
  and no refresh-token scope. Tokens remained in the client's credential store.
- Codex app-server discovered all three tools and invoked the request tool.
  A read without a grant returned `NOT_AUTHORIZED`.
- After the owner approved that request, Codex's MCP read returned six bytes
  from the actual Google document. Content was not included in this record.
- Reading a different resource with that grant returned `RESOURCE_NOT_ALLOWED`.
- After restarting Toolbox with the same keys and PostgreSQL/OpenBao stores,
  the existing Codex credentials, caller approval, Google connection and grant
  still produced a successful six-byte MCP read.

These native-client checks used Codex app-server's tool-call API, without a model
invocation. This record does not claim that this chat's tool catalog or Claude
Code has been connected. The caller feedback/name follow-up passed the real-server
Chromium flow and `make check`, including race tests with PostgreSQL/OpenBao.
The rename regression also verifies that review uses the saved Agent name and
that renaming preserves existing grants, pending requests and expiry.

Live per-document revocation, disabled-client denial, disconnect/provider cleanup
and second-client isolation still need their results recorded before claiming
the entire acceptance matrix passed. Automated coverage of those cases is not
a substitute for an unperformed live check. Neither PR has been merged.
