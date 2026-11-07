# Keycloak broker validation

Observed on 2026-11-07 in Linux with Go 1.27.2. This record accompanies the
Keycloak implementation; the PR proof comment identifies the exact commit and
hosted CI run. See [setup and cutover instructions](keycloak-setup.md).

## Real broker acceptance

`make keycloak-check` passed with the race detector: `TestKeycloakBrokerFlow`
completed in **41.32s**. The [sanitized output](experiments/keycloak-e2e.txt)
records the pinned Keycloak 26.8.2 image and individual acceptance milestones.
The test starts a real broker, verifies its TLS certificate using a local CA,
and drives authorization-code/PKCE redirects with HTTP cookie clients.

The assertions cover:

- Okta-shaped upstream login and stable repeat login through Keycloak.
- Read-only Admin API proof, denied realm writes, migration dry-run, atomic
  application and idempotence.
- An alias resolving to the original owner, with the original connection,
  agent and grant retained.
- Valid user access tokens and rejection of ID tokens, operator tokens and
  access tokens requested without the MCP scope.
- Fresh MCP caller approval, SDK tool request/read, wrong-resource denial,
  live grant revocation and caller disable.
- A Google-shaped account with the same email remaining a separate owner
  without access to the Okta owner's grants.

Fixture upstreams are controlled HTTPS OIDC servers. The Google-shaped test
uses generic OIDC, whereas the generated operator realm uses Keycloak's built-in
Google provider. **No live Okta/Google tenant, built-in Google adapter or Google
hosted-domain acceptance is claimed.** These require external credentials and
the live acceptance steps in the setup guide.

## Regression checks

`make check` passed after the broker test completed: formatting, `go vet`, the
entire race-enabled Go suite and `go build`. Disposable PostgreSQL 17.11 and
OpenBao 2.4.1 integrations were enabled. Storage tests include upgrading schema
005 to 006, global identity uniqueness, alias immutability and caller ownership.

The existing Playwright 1.62.0 flows also passed with system Chromium selected
via `TOOLBOX_BROWSER_EXECUTABLE=/usr/bin/chromium`:

| Check | Command selector | Package result |
| --- | --- | --- |
| Owner OIDC | `TOOLBOX_TEST_OIDC_BROWSER=1`, `^TestOIDCBrowserFlow$` | 8.207s |
| Workspace | `TOOLBOX_TEST_WORKSPACE_BROWSER=1`, `^TestWorkspaceBrowserFlow$` | 21.482s |
| Google probe | `TOOLBOX_TEST_WORKSPACE_BROWSER=1`, `^TestProbeBrowserFlow$` | 2.791s |

One earlier full-suite run during simultaneous broker startup and browser tests
failed the existing 20ms `deadline-during-fetch` cancellation case before it
reached provider dispatch. The final full suite ran sequentially and passed;
the production cancellation behavior and test timeout were not changed.

Independent review of token verification, alias migration, realm configuration,
the issuer-aware caller UI and setup instructions found no outstanding material
security or correctness findings before publication.

## Remaining external acceptance

Configure real Okta and optional Google Workspace using the setup guide, enroll
existing owners, and review migration counts before applying links. Confirm
repeat login, preserved owner data, same-email isolation, fresh caller approval,
document reads, revocation, disconnect and logout with those real accounts.
Existing grants are retained but are not silently transferred to a newly
approved MCP agent. mTLS/IAP and production deployment remain separate work.
