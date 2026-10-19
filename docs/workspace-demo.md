# Connect a real Google Workspace account locally

This branch adds `workspace-local`: verified Okta owner sessions, actual Google
OAuth and Drive adapters, Google Picker, and exact-document read approval in one
app. There is no fixture fallback. The Google client and real-account acceptance
remain required before this draft is demo-ready. `oidc-local` remains owner sign-in
only; `fixture` remains the separate simulated developer console.

## 1. Create the Google test project and client

Sign in to [Google Cloud Console](https://console.cloud.google.com/) with your
Workspace admin account. Create a dedicated `toolbox-demo` project under your
organization. This user-consent flow connects the account that approves it;
being a Workspace administrator does not grant the app access to everyone's files.

1. Under **APIs & Services → Library**, enable **Google Drive API** and **Google
   Picker API**.
2. Under **Google Auth Platform → Branding**, configure the app name and contact
   emails. Select **Internal** if available and testing only with your organization.
   Otherwise select **External**, keep publishing status **Testing**, and add the
   intended Workspace email as a test user under **Audience**.
3. Under **Data Access**, configure `openid`, `email`, and
   `https://www.googleapis.com/auth/drive.file`. The runtime requests exactly these
   scopes. Do not add broad Drive or profile scopes to work around a failure.
4. Create a **Web application** OAuth client under **Clients**:
   - Authorized JavaScript origin: `http://127.0.0.1:8080`
   - Authorized redirect URI: `http://127.0.0.1:8080/oauth/callback`
5. Keep its client ID and secret locally. The Okta callback remains the separate
   `http://127.0.0.1:8080/auth/oidc/callback` registered in Okta.
6. Create an API key in **APIs & Services → Credentials**. Restrict it to the
   **Google Picker API** and **Google Drive API**, with website restrictions
   `http://127.0.0.1:8080/*` and `https://docs.google.com/*`. Picker's iframe uses the
   latter origin. Copy the numeric **project number** from **IAM & Admin → Settings**.
   Use the same project for the OAuth client, Picker key, and project number.

Sources: [Google consent configuration](https://developers.google.com/workspace/guides/configure-oauth-consent),
[web OAuth client setup](https://developers.google.com/identity/protocols/oauth2/web-server),
[Picker prerequisites](https://developers.google.com/workspace/drive/picker/guides/web-picker-sample).

If your Workspace organization blocks the test client's requested access, review
that specific client in its app access controls. Do not enable domain-wide
delegation or relax all third-party app controls for this flow.

## 2. Prepare local configuration

Use the PostgreSQL and OpenBao dependencies from [Okta setup](okta-setup.md). Preserve
their volumes. Keep the existing Okta client and session pepper if continuing the
same local owner environment. Copy [.env.workspace.example](../.env.workspace.example)
to `.env`, replace every placeholder, and protect it with `chmod 600 .env`. The
Make targets load this ignored file as trusted shell configuration; quote literal
secret values. Keep credentials out of chat, commits, screenshots, and logs.

Generate the credential pepper and signing seed independently:

```sh
openssl rand -base64 32
openssl rand -base64 32
```

Keep all three crypto values stable across restarts. Reusing them for different
purposes is rejected. The server stores OAuth tokens in OpenBao and relational
authorization state in PostgreSQL. These local dev dependencies are not a public
deployment or production backup strategy; deployment work remains separate.

## 3. Verify the actual Google client's PKCE behavior

Stop the app occupying port 8080, then run:

```sh
make google-pkce-check
```

Open `http://127.0.0.1:8080/`. Click **Continue with Google** four times, completing
each separate consent flow. The checker tests matching verifier → missing verifier
→ incorrect verifier → matching verifier. Every code must be fresh. Both positive
flows verify the signed ID token, nonce, expiry and exact scopes. Both negative
flows must be rejected by Google; a generic client/configuration failure cannot
pass. Reused codes are rejected before the exchange.

The checker does not create a Toolbox connection or write provider credentials
to disk. It holds known tokens for revocation and revokes them at completion or
normal shutdown. **Use the dedicated test client:** revocation can remove the
app's other authorization to this Google account. A forced termination or unknown
provider outcome may need manual removal of the test app in Google Account
connections. The checker never changes the runtime flag itself.

Only after the page reports all four checks passed and cleanup completed, stop the
checker and set `TOOLBOX_GOOGLE_PKCE_VALIDATED=true` in `.env`. Keep it false on
failure. Reset it and repeat when changing the Google project, client or callback.
Record only sanitized outcomes and configuration identifiers, never codes,
verifiers, nonces, tokens or secrets. This is the live gate described in
[Google setup](google-setup.md#3-mandatory-pkce-enforcement-spike).

## 4. Run the real document flow

```sh
make workspace
```

1. Sign in with Okta. Choose **Google Drive → Connect Google account** and grant
   consent using the intended Workspace account.
2. Confirm the connected account and the supported policy: **Require approval ·
   one document · read only**. This describes the server-enforced grant policy;
   there is only one supported policy today. Account connection grants no agent
   document access.
3. Click **Choose from Google Drive** and select a native Google Doc containing
   harmless test text. Picker uses the connected account's short-lived access
   token; refresh tokens stay server-side. Provider `drive.file` permission is
   broader than Toolbox's read-only, exact-document grant. Picker is trusted
   first-party owner UI, not an agent credential endpoint.
4. **Request a test read** creates an independent HTTP test client if needed.
   Review the verified account, agent, document ID/name and expiry, then approve.
   Read the document and compare the returned text with the actual Google Doc.
5. Verify that a different document ID is denied, revoke the grant and confirm
   another read fails, then disconnect and confirm its grants remain blocked.
   **Advanced** exposes the HTTP test credential, duration, IDs and audit events;
   secrets are kept in the tab's memory and disappear on reload.
6. Restart using the same database, OpenBao volumes and cryptographic config.
   Confirm the owner identity and Google connection survive. Recreate a tab-only
   test credential if you did not save it. Revoked grants must remain revoked.

This proves the real account/tool boundary using an HTTP test client. Hosted MCP
and an external AI client's authentication/configuration remain separate work in
PR #7. Google Docs is the only supported file format; no Gmail, Sheets, Drive
search, editing or organization-wide indexing is implemented.

## Verification status

The local automated suites cover runtime isolation, Google signed-token/scope
validation, callback denial/replay, owner/session/connection checks at Picker token
release, provider token expiry, and browser approval/read/denial/revocation/
disconnect/logout. Browser tests use a signed synthetic OIDC provider, simulated
Google consent/Drive and a controlled Picker loader; they do not verify Google's
actual JavaScript loader or the user's Google tenant. Delayed read/revoke and
approval/account-switch races have browser regressions.

Run `make check` with actual disposable test stores, and run
`make workspace-browser-check` with Python/Chromium installed as described in the
[browser test guide](../tests/browser/README.md). CI runs both browser checks.

Still unperformed: actual-client PKCE, actual Google consent and returned scope
spellings, the real Picker/CSP/API-key behavior, real document read/denial, provider
revocation/disconnect and restart acceptance. Keep the PR draft until those pass.
