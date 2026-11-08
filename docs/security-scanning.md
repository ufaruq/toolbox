# Security scanning

All scanner workflows use pull_request (never pull_request_target), main pushes,
weekly schedules and manual dispatch. No scanner service account or paid API key
is required. Action revisions and scanner containers are pinned. GitHub Actions
updates are managed by Dependabot; container pins require reviewed updates. Dependabot has an explicit three-day
version-update cooldown; security updates are not delayed.

| Tool | Scope and gate | Location |
| --- | --- | --- |
| CodeQL | Go, JS/TS, Python, Actions; security-extended | PR #17; disable GitHub default setup when switching to advanced |
| Semgrep CE | p/ci rules, scan errors and findings fail; reviewed inline exceptions only | PR #16 |
| Trivy | source dependencies, secrets, Dockerfile/IaC, actual runtime images; high/critical fail even without a patch | trivy.yml |
| Dependabot | daily Go; weekly Actions and both Python requirement directories | PR #15 and aligned scanner PRs |
| Gitleaks | complete fetched Git history; redacted output, findings fail | gitleaks.yml |
| ZAP | disposable in-memory fixture; passive baseline; medium/high fail | zap.yml |
| govulncheck | reachable Go vulnerabilities | existing Go workflow |
| Dependency Review | new vulnerable PR dependencies, low and above | existing Dependency review workflow |

Require these checks in the main branch ruleset after verifying their hosted
runs. Enabling the scanners or choosing an alert severity threshold alone does
not prevent merging. The operator is monitoring hosted CI; local verification
below is not a hosted-run claim.

ZAP does not use personal credentials or contact real providers. Its initial
crawl reaches six fixture URLs. It does not establish authenticated Google/MCP
coverage, run an active attack scan, or validate production TLS. Informational
"Modern Web Application" detection remains in its report. The report gate rejects
missing/wrong target reports and medium/high alerts; scanner failures also fail.

## Fixes and local evidence (2026-11-08)

- Go jose/v4 4.1.4 → 4.1.6 fixes CVE-2026-116587. Combined with #13 upgrades,
  Trivy's source dependency scan has no high/critical findings.
- OpenBao 2.4.1 → 2.7.2, immutable image digest: high/critical package findings
  reduced from 101 to 3. These are package matches, not confirmed exploitable
  paths in Toolbox.
- PostgreSQL stays on 17.11. Its disposable fixture uses a pinned Alpine 3.24
  base instead of Debian, replaces the obsolete Go-based gosu helper with
  Alpine's su-exec, and starts as postgres (UID/GID 70). Compose provisions its
  data tmpfs with that owner. No existing persistent database is converted.
  High/critical image findings reduced from 93 to zero. The rootless startup and
  store/token/migration integration tests are validated locally.
- Full make check passes with the updated Go dependency and actual upgraded
  PostgreSQL/OpenBao services; formatting, vet, race tests and build included.
- Semgrep passes after pinning Actions and reviewing seven exact redirect warnings.
  Its documented exceptions explain the already-validated target or synthetic
  test intent; no broad security-rule exclusions.
- Gitleaks scans the fetched history. One exact historical documentation-prose
  match is ignored by fingerprint; no directory or secret-pattern allowlist.
- ZAP baseline succeeds, with zero medium/high alerts. The JSON gate also rejects
  a synthetic medium alert and an empty report in local verification.
- actionlint validates the workflow files. No hosted CodeQL result is claimed.

## Remaining upstream image findings: still fail the gate

Current official releases are not completely clear of package advisories. These
are deliberately not ignored or downgraded. The image job remains red until a
patched/validated image or a separately reviewed applicability decision exists.
Do not describe all scanners as passing or this change as production sign-off.

| Image | Advisory | Component | Available fix in scan database |
| --- | --- | --- | --- |
| OpenBao 2.7.2 | CVE-2026-116587 | go-jose/v3 3.0.5 | none listed |
| OpenBao 2.7.2 | CVE-2026-116587 | go-jose/v4 4.1.4 | 4.1.6; not yet in latest official OpenBao image |
| OpenBao 2.7.2 | CVE-2026-78661 | x/net 0.61.0 | 0.62.0; not yet in latest official OpenBao image |
| Keycloak 26.8.2 | CVE-2026-102554 | Guava 33.6.0-jre | 33.7.2; not yet in latest official Keycloak image |
| Keycloak 26.8.2 | CVE-2026-91403 | OpenJDK/CA trust | see Red Hat CA-package guidance |
| Keycloak 26.8.2 | CVE-2026-119373 | sqlite-libs | none listed |
| Keycloak 26.8.2 | CVE-2026-119586 | sqlite-libs | none listed |

The Go-module updates in this repo cannot patch binaries inside vendor images.
Replacing bundled Keycloak libraries or forking/rebuilding OpenBao requires a
separate maintained vendor build and compatibility validation. Until that work
or an official release addresses them, these findings remain explicit blockers
for a clean image-scan gate. SQLite package presence is not proof Keycloak
exposes the vulnerable FTS5 or recovery operations; no unsupported exemption has
been applied.

Red Hat explains that its OpenJDK RPMs use the system CA package, so the
"will not fix" label on the OpenJDK advisory is not a safe-ignore decision:
https://access.redhat.com/security/cve/cve-2026-91403

Scanner coverage complements tests and review; it does not prove the absence of
security issues. CodeQL default/advanced switching reference:
https://docs.github.com/en/code-security/reference/code-scanning/troubleshoot-analysis-errors/results-different-than-expected
