# Live Google Workspace verification

Code revision: `1e20d742c9ba50a4e145a70923cd483041398dd8`.
Date: 19 October 2026, 09:32 America/Los_Angeles (16:32 UTC).

## Actual Google client check: passed

The user configured a dedicated Google Web OAuth client, Picker key and project
number privately. The client ID's project prefix matches the configured project
number. Configuration values remain in the ignored local `.env`; no client
secret, token, authorization code, state, nonce or verifier is recorded here.

Configuration fingerprint (SHA-256): `11bbf25798550609c544a3a76204f0a1f213df649f03881fd49dd08b3dbc4655`.
It covers the client ID, exact callback, project number and requested scopes,
serialized as sorted compact JSON. It excludes all secrets. A changed client,
project or callback requires a new four-code check.

The interactive `make google-pkce-check` ran against Google's actual fixed OAuth
and JWKS endpoints. The user completed four separate consent rounds. The running
checker recorded these outcomes:

| Step | Exchange | Result |
|---|---|---|
| 1 | Fresh code with matching S256 verifier | Passed at 09:32:16 |
| 2 | Fresh code with verifier omitted | Expected rejection passed at 09:32:47 |
| 3 | Fresh code with incorrect verifier | Expected rejection passed at 09:32:52 |
| 4 | Fresh code with matching verifier again | Passed at 09:32:58 |

Positive exchanges used the normal adapter validation: signature, issuer,
audience, authorized party where applicable, nonce and lifetime, exact canonical
`openid email drive.file` scopes and an offline refresh token. The probe rejects
previously submitted code hashes; a reused code cannot count as a negative case.
No raw token response or scope string was captured. This establishes the accepted
canonical scope contract, without claiming which equivalent email spelling Google
returned.

The user reported PASS. A separate loopback read confirmed `Completed: 4 / 4`, the
PASS outcome and known probe-token revocation; the sanitized process log confirms
all four steps. The checker only reports PASS after its known credential cleanup
succeeds. It created no Toolbox Google connection or document grant.

After confirming this, the private runtime PKCE assertion was enabled for this
configuration. The checker was stopped and `make workspace` started. `/healthz`
and `/readyz` passed; `/v1/auth/config` reports `fixture=false`, `owner_only=false`,
`workspace=true`. The real connector UI is served on the same loopback origin.

## Automated verification: passed

[Hosted CI passed](https://github.com/ufaruq/toolbox/actions/runs/39283419974) for
the code revision above, including the real-store race suite and all browser
checks. Local `make check` passed with disposable PostgreSQL/OpenBao enabled.
Chromium Workspace, probe navigation, signed synthetic OIDC, fixture and all four
delayed-review regressions passed. Independent review findings were fixed and
rechecked with no remaining actionable findings.

These automated browser checks simulate Google consent, Picker and Drive. They
are separate from the actual-client protocol check above.

## Remaining live acceptance

- [ ] Connect the Google account through the combined Workspace app.
- [ ] Open the actual Google Picker under the configured key/origin/CSP and select
      a real native Google Doc with harmless test text.
- [ ] Verify real metadata and plain-text export after exact-document approval.
- [ ] Verify another document is denied and revoked grants cannot be used again.
- [ ] Verify app disconnect and provider cleanup behavior.
- [ ] Restart with the same keys/stores; verify stable owner/connection state and
      continued revocation.
- [ ] Complete remaining cross-account, re-consent, restricted-download/shared
      drive and multi-tab checks or explicitly bound the supported contract.

PR #10 remains draft. The actual-client PKCE gate passing does not establish a
working real document demo, corporate owner matching, hosted MCP, or production
readiness. Follow [the Workspace setup guide](workspace-demo.md) for the next steps.
