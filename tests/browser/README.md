# Browser acceptance checks

Use the [roadmap](../../docs/ROADMAP.md) for pending work and [implementation status](../../docs/implementation-status.md) for recorded results. These automated tests use synthetic providers. Real-account Google and hosted acceptance remain separate gates.

`make check` runs the Go checks but skips browser tests unless their opt-in environment variables are set. A passing `make check` alone is not browser acceptance. Run the explicit commands below and record the browser results separately.

## Synthetic Workspace and client-check flows

After installing the pinned Python dependencies and Chromium described below:

```sh
make workspace-browser-check
```

`TestWorkspaceBrowserFlow` starts the real Workspace UI and authorization engine
with a signed synthetic TLS OIDC provider, simulated Google consent/Drive and a
controlled Picker loader. It covers account connection, document picking,
approval/read, MCP client approval/disable/enable, a different document's denial, revocation, disconnect, logout,
late reads after revoke, late revoke responses after a new grant, late approvals
after account changes, approval links through owner login and mobile overflow.
Approval return paths are restricted to local request URLs, and their temporary
tab storage is cleared after sign-in; unsafe destinations are rejected.
All external network calls are intercepted or rejected. Screenshots mask the
tab-only agent credential. `TestProbeBrowserFlow` verifies that the local Google
client-check form can navigate to a controlled Google consent destination under
its actual CSP and referrer policy. It does not contact Google or validate PKCE.

The real-client checker is the separate interactive `make google-pkce-check`
command. See [Workspace setup](../../docs/workspace-demo.md) for console settings,
the four actual-client exchanges and unperformed live acceptance gates.

## Fixture browser flow

These checks drive the running Toolbox UI in headless Chromium. They cover fixture owner login, the synthetic OAuth redirect, an independent agent credential, the trusted approval link, review interrupted by reload, exact-document approval, approval replay rejection, a successful `doc-A` read, denied `doc-B` access, revoked-grant denial, request denial, disconnect and redacted audit events. Unhandled browser JavaScript exceptions fail the run.

This is **synthetic fixture coverage**, not production OIDC, real Google consent/Picker/Drive, or a deployment check. Use a disposable service and stores: the test creates synthetic state and disconnects the fixture Google account. Reusing a store from an earlier fixture process is unsupported because its ephemeral provider secrets are gone.

Start the service in another terminal:

```sh
TOOLBOX_ADDR=127.0.0.1:18080 make run
```

Install the pinned runner and its matching Chromium, then run:

```sh
make browser-install
make browser-fixture-check
make browser-review-check
```

CI can use the same commands after launching the fixture service and waiting for `/readyz` to return 200. The runner returns a nonzero status on failure. PostgreSQL/OpenBao-backed runs use the service's documented storage variables; the browser runner requires no storage credentials.

Run these scripts in that order on a fresh fixture service and stores. `review_race.py` holds actual review responses while the request or connection selection changes, including changing away and back. All four cases must leave approval disabled, submit no stale approval, and allow a fresh review. It creates multiple active connections, while the main flow expects its initial connection to be the only active one.

Each run captures four full-page PNGs after verifying the reviewed request, allowed read, denied other-document read and revoked-grant denial. The agent credential field is masked in every image. A successful run also writes `result.json` with the browser/runner versions, viewport, fixture scope and screenshot names. This metadata is written only after the entire E2E flow passes. CI uploads screenshots, metadata and service logs as the `browser-e2e` artifact on successful and failed runs.

- `TOOLBOX_BASE_URL` overrides `http://127.0.0.1:18080`. Only a plain loopback HTTP origin is accepted. The fixture notice is checked before the first mutation, and the authenticated session must report explicit fixture mode before account/agent changes. Browser requests outside that origin are blocked.
- `TOOLBOX_BROWSER_EXECUTABLE` optionally selects an already installed Chromium, such as `/usr/bin/chromium`. Leave it unset to use Playwright's matching bundled browser in CI.
- `TOOLBOX_BROWSER_ARTIFACT_DIR` selects the artifact root, defaulting to `toolbox-browser-artifacts` under the system temporary directory. Every run uses a new `run-*` subdirectory, preserving earlier files and keeping current-run evidence separate. The runner prints that directory. Screenshots mask the credential field. The runner deliberately avoids traces, network dumps and raw Playwright errors, which could expose credentials.
- `TOOLBOX_E2E_REVISION` optionally records the tested checkout revision in `result.json`; CI supplies its checkout SHA. An unset value remains `null` rather than guessing a revision.

Waits follow browser navigation, API responses and visible UI state. No fixed sleeps or live account credentials are used.

## Synthetic OIDC browser flow

The separate `TestOIDCBrowserFlow` harness starts loopback Toolbox and a local TLS identity provider, then runs `oidc_e2e.py` in Chromium. It needs no running fixture service, Okta tenant or credentials. It exercises the actual owner sign-in redirect, callback, visible owner identity, reload, local Toolbox logout, rejection of the old session and a distinct second owner. It also checks that fixture and connector controls are absent and that no unhandled JavaScript errors occur.

Install the pinned Python requirements and Playwright Chromium using the commands above, then run from the repository root:

```sh
make oidc-browser-check
```

`TOOLBOX_TEST_OIDC_BROWSER=1` explicitly enables this optional browser check. `TOOLBOX_TEST_PYTHON` selects the exact Python binary containing the pinned requirements; it is optional when the harness can find an appropriate `python3`. `TOOLBOX_BROWSER_EXECUTABLE` optionally selects an installed Chromium. Leave it unset to use Playwright's matching browser. Without the browser opt-in the harness skips; ordinary Go protocol tests continue to run without Python. Record skips as skips.

Both OIDC and Workspace Go harnesses register their exact callback URL with the
synthetic OIDC provider before sign-in. Its HTTP authorization endpoint rejects
unregistered callbacks on GET and POST; scheme/host checks alone are insufficient.
The callback allowlist is configured by trusted test setup, never by browser input.
A line-specific Semgrep annotation documents this validated destination: the rule
does not model the exact allowlist and flags request state even when URL-encoded
only into the query. Regression tests cover callback mismatches and hostile state
values without suppressing CodeQL or excluding the fixture from either scan.

The Go harness supplies the two allowed origins and a pin for the fake provider certificate's SPKI. Browser requests outside the Toolbox and synthetic TLS-provider origins are blocked. Chromium's certificate exception is limited to that fake certificate's SPKI; application provider TLS verification remains enabled. Do not point this synthetic runner at an Okta tenant or pass real credentials to it.

The runner avoids browser traces, query/network logs, cookies, raw callback URLs and provider secrets. Any saved screenshots or result metadata must remain sanitized synthetic evidence. This flow proves local browser behavior against the fake provider. **Real Okta acceptance remains unrun** until a separately configured app has an observed real browser login and Toolbox logout; see [Okta setup](../../docs/okta-setup.md).

## Synthetic GitHub owner flow

`make github-browser-check` starts Toolbox with a controlled GitHub provider and
runs the real `/github` page in Chromium. It connects a repository, requests a
scope as an authenticated agent, reviews and approves it as the owner, invokes
the allowed read, revokes it and verifies denial. It checks untrusted agent names
render as text and the narrow layout does not overflow. This proves owner UI and
application authorization behavior, not a live GitHub API operation. It uses the
same pinned browser dependencies and `TOOLBOX_TEST_WORKSPACE_BROWSER=1` gate;
`make test-all` requires this suite to pass.
