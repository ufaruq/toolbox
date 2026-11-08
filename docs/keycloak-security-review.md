# Keycloak PR security review — 2026-11-08

Scope: focused review of PR #13 authentication and authorization boundaries,
plus Go dependency scanning. This is not a whole-product penetration test or a
guarantee of absence of vulnerabilities.

## Additional review findings

A subsequent Copilot review identified two issues missed by the initial focused
review. The earlier absence of a confirmed bypass was not security sign-off.

- Migration Admin API JSON rejected lowercase-equivalent duplicate names but
  missed Unicode simple-fold equivalents accepted by Go's JSON decoder. The
  `userId` / `uſerId` pair demonstrably overwrites the decoded subject. Duplicate
  checking now uses Unicode simple folding, recursively, with regressions for
  identity, provider, service-account and nested fields. Exploitation requires
  ambiguous data from the trusted Admin API; it is not a public login parameter.
- The default Keycloak browser flow allowed local passwords, and brokered users
  could request password setup despite registration being disabled. Generated
  realms now use an upstream-only flow with a mandatory denial on local username
  submission, no local credential or cookie authentication, and disabled local
  credential-setup actions. The theme shows only provider choices. Real Keycloak
  acceptance tests include a seeded valid local password, application-initiated
  password setup, and inspection of the actual required-action policy.

Existing realms need the explicit administrative cutover in
[the setup guide](keycloak-setup.md#upstream-only-authentication-and-existing-realms).
The running local development realm is not silently migrated by this PR.

Regression evidence: the original realm produced an authorization code from the
seeded local password and displayed the application-initiated password setup
form. The same real-Keycloak test passes with the hardened realm (20.02 seconds,
race detector enabled), including broker/migration/MCP acceptance. The Unicode
shadow test likewise failed before the parser fix and passes after it.

## Dependency findings and remediation

`govulncheck v1.9.0` found four reachable advisories on head e888521:

| Advisory | Affected component | Remediation |
| --- | --- | --- |
| [GO-2026-6809](https://pkg.go.dev/vuln/GO-2026-6809) | Go certificate validation | Go 1.27.3 |
| [GO-2026-6629](https://pkg.go.dev/vuln/GO-2026-6629) | x/text crafted-input panic | x/text v0.41.0 |
| [GO-2026-5970](https://pkg.go.dev/vuln/GO-2026-5970) | x/text invalid-input loop | x/text v0.41.0 |
| [GO-2026-5004](https://pkg.go.dev/vuln/GO-2026-5004) | pgx placeholder sanitization | pgx v5.9.2 |

Reachability is not proof of exploitability through a Toolbox request. These
dependencies are upgraded regardless. CI now runs the pinned scanner against
the current vulnerability database on every normal workflow run.

After upgrades, scanning on macOS/arm64 with Go 1.27.3 reports zero reachable
and zero imported-package vulnerabilities. The remaining module-only advisory,
[GO-2026-5024](https://pkg.go.dev/vuln/GO-2026-5024), affects an unimported
x/sys/windows package. The Linux CI scan checks its own platform.

## Boundaries reviewed and verification

- Token verification pins issuer, audience, authorized client, RS256 signature,
  user session, MCP scope and lifetime; malformed and ambiguous claims fail closed.
- Discovery/JWKS requests stay on the configured TLS origin with bounded bodies
  and no redirect following.
- Migration requires exact upstream subject evidence, rejects ambiguous or
  premerged identities, rechecks owner state and writes aliases atomically.
  Email is not used to transfer ownership.
- Login transactions use state, nonce, PKCE and a browser binding. Callback
  consumption is fenced against replay. Mutations require origin/CSRF checks.
- Caller authorization checks active owner, agent, profile and grants. Alias
  storage enforces identity uniqueness and immutable bindings.
- Generated credential files are exclusive-create, mode 0600; migration output
  reports counts rather than identities or credentials.

Focused security regression tests passed under the race detector. Following the
dependency upgrades, `make check` passed with PostgreSQL and OpenBao integration
opt-ins enabled: formatting, vet, full race suite and build. Hosted CI must also
pass on the new commit before merging. No confirmed authentication bypass was
found in the reviewed paths.

## Operational limits and remaining acceptance

Toolbox browser sessions have an eight-hour lifetime and are not automatically
revoked by upstream Google/Keycloak logout or deprovisioning. MCP JWT validation
is offline; upstream revocation is not consulted for each request. Local Toolbox
owner/caller disabling and grant revocation are checked, but upstream offboarding
must not be represented as instantaneous. Production requirements may call for
backchannel logout, revocation synchronization or shorter sessions.

The successful manual Google login is a smoke test. Separate Gmail/Workspace
accounts, live hosted-domain enforcement, live Okta migration and a real
Google-to-MCP grant/revocation flow remain acceptance gaps. Keycloak admin access,
production TLS, persistent secrets, backups and deployment configuration need
their own review. The running local preview is a development deployment and is
not automatically rebuilt by changing Go dependencies.
