# Live Google Workspace local demo

## Required result

Replace the developer harness as the demo with a loopback application that uses the already verified Okta owner login and an actual user-authorized Google Drive connection. A real Google document must pass through agent request, owner approval, read, denial, revocation and disconnect. A synthetic test pass is not live acceptance.

The product flow is connector → connect account → policy → document/access requests. Google Drive is the only supported connector. The initial supported policy requires owner approval for each exact document and permits plain-text reads only. Expiry and agent test controls belong under Advanced. Do not show unsupported connectors or pretend that a different policy is enforced.

## Existing work and integration boundary

- #5 provides verified Okta owner sessions and login cancellation/revocation.
- #6 provides an optional corporate Google account-matching policy; it is not an enterprise-only Toolbox login policy and is not required to demonstrate Drive.
- #7 provides a separate MCP implementation but deliberately leaves Google unavailable. Its owner authentication must be reconciled with #5 before integration. This change proves the live HTTP tool path first; it does not claim an MCP/Claude acceptance pass.
- #4 provides later deployment/crypto/storage work. This change remains loopback only and makes no public deployment claim.

The branch initially stacks on #6. Retarget onto main once #6 merges. Reuse the OAuth service, token manager, fixed Google Drive executor and exact-document grant checks; do not implement a second permission engine.

## Runtime and identity

Add explicit `workspace-local` alongside the unchanged `fixture` and `oidc-local` modes. Require PostgreSQL, the local secret store, the same trusted Okta issuer/client/callback, stable independent session/credential peppers, persisted Ed25519 signing material, Google OAuth Web client credentials, and Picker project configuration. There is no simulated-provider fallback.

Enable the existing owner-login routes alongside tool routes, preserving issuer/subject identity and the session's issuance/configuration binding. Keep fixture login/authorization absent. Reuse `http://127.0.0.1:8080/auth/oidc/callback`; Google uses `http://127.0.0.1:8080/oauth/callback`. Authentication/dependency failures fail closed. Provider callback URLs, tokens and raw provider errors never enter logs or evidence.

Use an explicit Google email identity scope contract for live connection identity: `openid email https://www.googleapis.com/auth/drive.file`. Independent Google-account linking remains the default; enable exact corporate matching only through a trusted server resolver. Preserve the old minimal fixture/library contract. Normalize only Google's documented email scope alias at the trusted adapter boundary; reject additional, missing and duplicate scopes after normalization. Google `sub` remains the account key.

Keep the existing actual-client PKCE release gate. Supply a controlled live probe using fresh codes for positive, missing-verifier, wrong-verifier and final-positive cases; no reused code may count as a negative test. Configuration remains unverified until this completes for the actual Web client.

## Google connection and selection

Construct the real Google OAuth provider and `gdrive.New()` executor in the runtime. Connect sends the browser to Google's consent page, handles only explicitly allowed bounded callback fields, verifies state/session/identity/scopes and redirects to a clean application URL. User denial consumes only the bound login attempt without creating an active connection. Issued credentials from rejected outcomes retain the existing cleanup-only lifecycle.

Use Google Picker for user-authorized document selection under the same Google project/client. An authenticated, same-origin, CSRF-protected owner endpoint may issue only a short-lived Google access token for that owner's active connection, with its actual expiry. Recheck session/connection authority before release. Never expose a refresh token, return provider credentials to an agent, or put tokens in browser storage. Restrict Picker to native Google documents; verify file identity/type again through the existing executor before approval/read. Treat browser-returned fields as input, never authorization evidence.

## Interface and agent flow

Use a focused connector card with real connection state, a concise policy summary and document selection. Show incoming/linked approval requests with account, agent, exact document, read-only action and expiry. Approval and revocation continue to use the existing server grants and final authorization check. Put the manual agent client and credential controls under Advanced, clearly labeled as a test client; it is not an AI model or an MCP client.

## Verification and completion

Automated gates: configuration/route isolation; signed Google identity and exact scopes; callback success/denial/replay/malformed fields; cross-owner/session/connection denial; owner-only Picker token release; no refresh-token exposure; browser connect/select/approve/read/deny/revoke/disconnect; both legacy modes; real PostgreSQL/OpenBao; formatting, vet, race suite and build; container verification.

Live gate: with the user's dedicated Google test configuration and a synthetic document in their real Workspace account, record actual Okta login, Google consent, Picker selection, approved text read, a different-document denial, grant revocation, disconnect and application restart. Do not mark the PR demo-ready until the live gate passes. Client setup and live acceptance require user-controlled credentials/consent, but implementation and synthetic verification proceed independently.

Sources checked 2026-10-19: [Google Web OAuth](https://developers.google.com/identity/protocols/oauth2/web-server), [OIDC](https://developers.google.com/identity/openid-connect/openid-connect), [Picker](https://developers.google.com/workspace/drive/picker/guides/overview), [Drive scopes](https://developers.google.com/workspace/drive/api/guides/api-specific-auth).
