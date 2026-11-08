# Local Okta verification

Date: 2026-10-19. Application revision: [`828f3162c7105c45fcd03ed26d9fd04703345bed`](https://github.com/ufaruq/toolbox/commit/828f3162c7105c45fcd03ed26d9fd04703345bed), integrated with main after PR #3. Subsequent acceptance-record changes are documentation only.

## Automated checks

- Formatting, whitespace checks, `go vet ./...` and `go build ./...` passed.
- `go test -race -count=1 ./...` passed on macOS with actual disposable PostgreSQL 17.11 and OpenBao 2.4.1 integrations enabled.
- The Chromium OIDC browser test passed in Linux Docker with Playwright 1.62.0: two synthetic owners, actual signed-provider redirects, reload, CSRF rejection, logout and sign-in control recovery after another tab logs out.
- The fixture browser flow and all four delayed-review regressions passed against the rebuilt service in Docker.
- New regressions reproduced the delayed two-rotation logout, cleanup relationship deletion, repository lookup failures and stale-tab UI failure before their fixes. Final checks passed. Independent review found no further actionable correctness or security findings.
- [Hosted CI passed for the application revision](https://github.com/ufaruq/toolbox/actions/runs/39220522018), including the Linux race/integration suite and all browser flows.

## Live Okta checks

One assigned user tested a confidential OIDC Web Application using its organization issuer, `openid` scope, Authorization Code with S256 PKCE and the registered `http://127.0.0.1:8080/auth/oidc/callback` callback. The client secret and session pepper stayed in an ignored local file with mode 0600; no secret values, cookies or callback query strings are included here.

The user observed and confirmed these browser outcomes:

1. Okta sign-in returned to Toolbox with an internal owner ID.
2. Restarting only the application process and reloading preserved the signed-in owner and its ID with the same stores and pepper.
3. Signing out of Toolbox, then reloading, showed a signed-out browser.
4. Signing in again returned the same internal owner ID.

Database checks corroborated one Okta owner, two login audit events, one logout audit event, an expired prior session and one active replacement session. Application readiness passed after restart. Chrome automation was unavailable, so the live browser observations above are user-confirmed; the agent performed the application restart and database checks.

## Limits

A second live Okta account, live eight-hour expiry, and live dependency-failure tests were not exercised. Automated tests cover owner separation, expiry, invalid identity claims, replay, CSRF, storage errors and logout races with synthetic identities. This record does not claim the complete M1 live multi-user gate, public production identity, Google/Picker or hosted deployment acceptance. Both local modes remain loopback only; owner mode disables Google and agent operations. See the [roadmap](ROADMAP.md).
