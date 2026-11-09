# Security model and validation

[Overview](../../README.md) · [Architecture](../architecture/README.md) · [Development](../development/README.md)

## Invariants

Owner identity, provider consent, MCP caller identity, agent identity and document authorization are separate checks. Never infer document access from login or an account connection. Preserve exact issuer/audience/client validation, verified migration rather than email matching, bounded grants, final revocation checks, and isolation between owners. Provider secrets remain server-side. Untrusted document text is data, not instructions.

The [Keycloak security review](../keycloak-security-review.md) covers broker and migration risks and evidence. Realm configuration changes do not automatically harden existing deployed realms: follow the [Keycloak setup and cutover instructions](../keycloak-setup.md).

## Automated coverage

The full test gate includes race detection, real disposable storage, synthetic browser flows, and real Keycloak/MCP containers with controlled upstream identities. See [development](../development/README.md). These tests complement code review; passing tests do not establish absence of vulnerabilities.

Inspect the checked-out [.github/workflows](../../.github/workflows) for the scanners actually configured in that revision. Repository settings, workflow files, and required branch checks are separate controls. Dependency scanning detects known advisories; static analysis looks for code weaknesses; secret scanners detect supported credential patterns; dynamic web scans exercise reachable running routes. None replaces authorization and account-linking tests. Do not silence unfixed container findings merely to make a gate green: record the affected package, vendor image, available fix and disposition.

See [security scanning](../security-scanning.md) for Trivy, Gitleaks and ZAP coverage, failure thresholds and recorded vendor-image blockers.

## CodeQL configuration

The [CodeQL advanced workflow](../../.github/workflows/codeql.yml) scans Go,
JavaScript/TypeScript, Python and GitHub Actions with `security-extended` queries.
It runs for pull requests targeting `main`, pushes to `main`, weekly on Tuesday
at 14:45 UTC, and manual dispatch. Go uses the toolchain in `go.mod` and an
explicit `go build ./...` after CodeQL initialization; the other languages do
not require a build. Each language runs independently with a 30-minute timeout.
Actions are pinned to immutable commits and updated through Dependabot.

Use repository **Settings → Advanced Security → CodeQL analysis** to select
advanced setup when adopting this workflow. Default setup must be disabled:
GitHub rejects advanced-workflow uploads while default setup is enabled, even
when extraction and queries succeed. If logs report this conflict, correct the
repository setting before rerunning the failed jobs. The workflow's name alone
does not change that setting. Avoid running a second advanced workflow with the
same language categories.

Check all four `Analyze (...)` jobs and their upload processing results before
claiming CodeQL passed. Pull-request results do not establish a baseline for
`main`; verify the first post-merge run as well. Configure the applicable CodeQL
checks in the branch ruleset if they must block merging. These scans do not
replace the full acceptance gate or live-provider validation.

## Live evidence and release limits

- [Keycloak verification](../keycloak-verification.md)
- [Okta verification](../okta-verification.md)
- [Workspace verification](../workspace-verification.md)
- [Browser evidence gallery](../e2e-evidence/README.md)

These reports are scoped to their recorded revisions and scenarios. Production deployment, broader live-provider acceptance and operational recovery must satisfy the [roadmap](../ROADMAP.md). Keep credentials out of source, screenshots, logs and PR discussions; use synthetic accounts for repeatable automated tests.
