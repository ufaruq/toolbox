# Security model and validation

[Overview](../../README.md) · [Architecture](../architecture/README.md) · [Development](../development/README.md)

## Invariants

Owner identity, provider consent, MCP caller identity, agent identity and document authorization are separate checks. Never infer document access from login or an account connection. Preserve exact issuer/audience/client validation, verified migration rather than email matching, bounded grants, final revocation checks, and isolation between owners. Provider secrets remain server-side. Untrusted document text is data, not instructions.

The [Keycloak security review](../keycloak-security-review.md) covers broker and migration risks and evidence. Realm configuration changes do not automatically harden existing deployed realms: follow the [Keycloak setup and cutover instructions](../keycloak-setup.md).

GitHub installation access is a separate ceiling. Owner connections, caller tool
approval and immutable repository/action/branch/path/revision grants are all
required. The App key stays with the operator; downstream contexts receive
short-lived installation tokens for one repository. Read operations do not get
write permissions. Discovery uses an independently revoked metadata-only token.
See [GitHub authorization and race limits](../github-connector.md); upstream
locator changes, unconditional multi-file writes and PR retargeting are not made
atomic by preflight checks. Unknown mutation outcomes require inspection before
retrying. Docker Engine and its operator are trusted service components.

## Automated coverage

The full test gate includes race detection, real disposable storage, synthetic browser flows, and real Keycloak/MCP containers with controlled upstream identities. See [development](../development/README.md). These tests complement code review; passing tests do not establish absence of vulnerabilities.

Inspect the checked-out [.github/workflows](../../.github/workflows) for the scanners actually configured in that revision. Repository settings, workflow files, and required branch checks are separate controls. Dependency scanning detects known advisories; static analysis looks for code weaknesses; secret scanners detect supported credential patterns; dynamic web scans exercise reachable running routes. None replaces authorization and account-linking tests. Do not silence unfixed container findings merely to make a gate green: record the affected package, vendor image, available fix and disposition.

## Live evidence and release limits

- [Keycloak verification](../keycloak-verification.md)
- [Okta verification](../okta-verification.md)
- [Workspace verification](../workspace-verification.md)
- [Browser evidence gallery](../e2e-evidence/README.md)

These reports are scoped to their recorded revisions and scenarios. Production deployment, broader live-provider acceptance and operational recovery must satisfy the [roadmap](../ROADMAP.md). Keep credentials out of source, screenshots, logs and PR discussions; use synthetic accounts for repeatable automated tests.
