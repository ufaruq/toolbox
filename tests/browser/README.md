# Fixture browser E2E

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
```

CI can use the same commands after launching the fixture service and waiting for `/readyz` to return 200. The runner returns a nonzero status on failure. PostgreSQL/OpenBao-backed runs use the service's documented storage variables; the browser runner requires no storage credentials.

- `TOOLBOX_BASE_URL` overrides `http://127.0.0.1:18080`. Only a plain loopback HTTP origin is accepted. The fixture notice is checked before the first mutation, and the authenticated session must report explicit fixture mode before account/agent changes. Browser requests outside that origin are blocked.
- `TOOLBOX_BROWSER_EXECUTABLE` optionally selects an already installed Chromium, such as `/usr/bin/chromium`. Leave it unset to use Playwright's matching bundled browser in CI.
- `TOOLBOX_BROWSER_ARTIFACT_DIR` selects the failure screenshot directory; it defaults to a unique directory under the system temporary directory. Screenshots mask the credential field. The runner deliberately avoids traces, network dumps and raw Playwright errors, which could expose credentials.

Waits follow browser navigation, API responses and visible UI state. No fixed sleeps or live account credentials are used.
