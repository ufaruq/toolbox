# Fixture browser E2E

Use the [roadmap](../../docs/ROADMAP.md) for pending work and [implementation status](../../docs/implementation-status.md) for recorded results. This page documents the existing fixture runner; live sign-in/Google and hosted acceptance belong to M1–M3.

These checks drive the running Toolbox UI in headless Chromium. They cover fixture owner login, the synthetic OAuth redirect, an independent agent credential, the trusted approval link, review interrupted by reload, exact-document approval, approval replay rejection, a successful `doc-A` read, denied `doc-B` access, revoked-grant denial, request denial, disconnect and redacted audit events. Unhandled browser JavaScript exceptions fail the run.

This is **synthetic fixture coverage**, not production OIDC, real Google consent/Picker/Drive, or a deployment check. Use a disposable service and stores: the test creates synthetic state and disconnects the fixture Google account. Reusing a store from an earlier fixture process is unsupported because its ephemeral provider secrets are gone.

Start the service in another terminal:

```sh
TOOLBOX_MODE=fixture TOOLBOX_ADDR=127.0.0.1:18080 go run ./cmd/toolbox
```

Install the pinned runner and its matching Chromium, then run:

```sh
python3 -m venv /tmp/toolbox-browser-venv
/tmp/toolbox-browser-venv/bin/pip install -r tests/browser/requirements.txt
/tmp/toolbox-browser-venv/bin/playwright install --with-deps chromium
/tmp/toolbox-browser-venv/bin/python tests/browser/fixture_e2e.py
/tmp/toolbox-browser-venv/bin/python tests/browser/review_race.py
```

CI can use the same commands after launching the fixture service and waiting for `/readyz` to return 200. The runner returns a nonzero status on failure. PostgreSQL/OpenBao-backed runs use the service's documented storage variables; the browser runner requires no storage credentials.

Run these scripts in that order on a fresh fixture service and stores. `review_race.py` holds actual review responses while the request or connection selection changes, including changing away and back. All four cases must leave approval disabled, submit no stale approval, and allow a fresh review. It creates multiple active connections, while the main flow expects its initial connection to be the only active one.

Each run captures four full-page PNGs after verifying the reviewed request, allowed read, denied other-document read and revoked-grant denial. The agent credential field is masked in every image. A successful run also writes `result.json` with the browser/runner versions, viewport, fixture scope and screenshot names. This metadata is written only after the entire E2E flow passes. CI uploads screenshots, metadata and service logs as the `browser-e2e` artifact on successful and failed runs.

- `TOOLBOX_BASE_URL` overrides `http://127.0.0.1:18080`. Only a plain loopback HTTP origin is accepted. The fixture notice is checked before the first mutation, and the authenticated session must report explicit fixture mode before account/agent changes. Browser requests outside that origin are blocked.
- `TOOLBOX_BROWSER_EXECUTABLE` optionally selects an already installed Chromium, such as `/usr/bin/chromium`. Leave it unset to use Playwright's matching bundled browser in CI.
- `TOOLBOX_BROWSER_ARTIFACT_DIR` selects the artifact root, defaulting to `toolbox-browser-artifacts` under the system temporary directory. Every run uses a new `run-*` subdirectory, preserving earlier files and keeping current-run evidence separate. The runner prints that directory. Screenshots mask the credential field. The runner deliberately avoids traces, network dumps and raw Playwright errors, which could expose credentials.
- `TOOLBOX_E2E_REVISION` optionally records the tested checkout revision in `result.json`; CI supplies its checkout SHA. An unset value remains `null` rather than guessing a revision.

Waits follow browser navigation, API responses and visible UI state. No fixed sleeps or live account credentials are used.
