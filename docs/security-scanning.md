# Security scanning

All scanner workflows use pull_request (never pull_request_target), main pushes,
weekly schedules and manual dispatch. No scanner service account or paid API key
is required. Action revisions and scanner containers are pinned. GitHub Actions
updates are managed by Dependabot; container pins require reviewed updates. Dependabot has an explicit seven-day
version-update cooldown; security updates are not delayed.

| Tool | Scope and gate | Location |
| --- | --- | --- |
| CodeQL | Go, JS/TS, Python, Actions; security-extended | [Current configuration](security/README.md#codeql-configuration) |
| Semgrep CE | p/ci rules, scan errors and findings fail; reviewed inline exceptions only | semgrep.yml |
| Trivy | source dependencies, secrets, Dockerfile/IaC, actual runtime images; high/critical fail even without a patch | trivy.yml |
| Dependabot | daily Go; weekly Actions and both Python requirement directories | .github/dependabot.yml |
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

Gitleaks retains a redacted JSON report. Its two exact historical fingerprint
exceptions cover documentation prose and a public Go module checksum in patch
context; no path-wide or credential-pattern allowlist is used.

## Maintained vendor images

Toolbox owns narrow downstream recipes for its disposable dependency containers.
They are built locally and in CI, not published by this PR. No running operator
service is automatically upgraded. Base manifests, source archives and the new
Guava artifact are checksum-pinned in the recipes; module updates include Go
sumdb checksums. Build contexts contain only each component's recipe and patches.

| Component | Recipe and changes |
| --- | --- |
| PostgreSQL 17.11 | [Recipe](../deploy/postgres/Dockerfile): pinned Alpine base, su-exec replaces the obsolete Go-based gosu binary; non-root UID/GID 70 and disposable owned tmpfs. No persistent database migration. |
| OpenBao 2.7.2+toolbox.1 | [Recipe](../deploy/openbao/Dockerfile): checksum-verified upstream source distribution including the release UI; CAP 0.15.0, JOSE v4.1.6, x/net 0.62.0; narrow [Okta SDK patch](../deploy/openbao/okta-jose-v4.patch) moves its signing code from JOSE v3 to v4. The final binary must not link JOSE v3. Upstream runtime, entrypoint and licenses are retained. |
| Keycloak 26.8.2 | [Recipe](../deploy/keycloak/Dockerfile): upstream distribution and licenses, pinned Temurin Java 25 LTS Alpine runtime, checksum-verified Guava 33.7.2-jre. Assert unused GPG tools and their SQLite dependency are absent from the Java 25 base. Assert affected CA roots are absent from the Java truststore. |

Keycloak's replacement Guava JAR retains its original **classpath filename**,
which Quarkus persists in its application model. Its contents, manifest and Maven
metadata are the unmodified 33.7.2-jre release; they are not relabeled. The build
checks embedded metadata and runs Keycloak's Quarkus build. Scans identify the
actual replacement library. Native Java deserialization is the prerequisite for
the Guava advisory; package presence alone does not prove Toolbox exploitation.

OpenBao's image build tests the patched Okta signer, verifies its JWT claims and
key ID, and tests rejection of private JWK parameters before RSA parsing
(CVE-2026-116587). Both the source dependency patch and upstream checksums are
tracked. `go version -m` output is retained inside the image at
`/usr/share/toolbox/openbao-build-info.txt`. The `+toolbox.1` version suffix marks
the downstream binary. Build tools stay in the build stage.

### Build, test and scan the same artifacts

```sh
image=$(scripts/build-vendor-image keycloak)
scripts/scan-vendor-image "$image" work/security/keycloak
make test-all
```

The build helper prints an immutable local image ID. The scan helper exports
that exact image and writes `image-id.txt`, `sbom.cdx.json` (all detected packages)
and `vulnerabilities.json` (HIGH/CRITICAL findings). It fails on scan errors or
findings, including those without an available fix. No advisory ignores or VEX
exemptions are introduced for these images.

`make test-all` builds all three recipes, uses their IDs for the real storage and
broker integration tests, then scans those same IDs and retains the reports
alongside its browser/test evidence. This also runs in the pre-push gate and
hosted Full acceptance job. The separate Trivy image matrix scans every recipe
on PRs, main pushes and weekly runs, uploading per-image SBOMs and findings.
The isolated images and test runner consume only synthetic provider fixtures;
see [development](development/README.md) for prerequisites and artifact paths.

The source misconfiguration scan has one line-specific exception: the disposable
acceptance runner explicitly runs as root to control sibling Docker fixtures and
restore host artifact ownership. It already has Docker Engine authority and must
only run trusted test code. This exception does not apply to runtime images or
package vulnerabilities. All three runtime recipes select non-root users.

### Upstream tracking and patch retirement

Dependabot checks the Docker base pins weekly. The scheduled/manual Trivy
workflow also compares OpenBao and Keycloak's latest upstream releases against
the pinned versions and fails its maintenance job if review is due. Updates are
reviewed, not automatically merged. An OpenBao update must keep the source URL,
checksum, runtime manifest and version ldflags consistent; a base-only bump is
not a source upgrade. Reproduce each advisory against the updated artifact,
remove obsolete local patches, regenerate SBOMs and rerun full acceptance before
switching back to an unmodified upstream image.

### Advisory baseline

The original OpenBao image had three HIGH package findings: JOSE v3/v4
CVE-2026-116587 and x/net CVE-2026-78661. The original Keycloak image had Guava
CVE-2026-102554, OpenJDK/CA CVE-2026-91403 and SQLite CVE-2026-119373 /
CVE-2026-119586. These are package matches, not confirmed exploitable Toolbox
paths. The recipes fix or remove the components rather than suppressing them.

The CA issue is checked against the actual Java truststore, not treated as
resolved merely because a different vendor's package has no scanner match.
[Red Hat guidance](https://access.redhat.com/security/vulnerabilities/RHSB-2026-012)
identifies AAA Certificate Services and emSign ECC Root CA - G3; the build fails
if either remains a trust anchor. The base's system CA bundle remains available;
Keycloak's explicit custom-truststore configuration is unchanged.

Scanner coverage complements tests and review; it does not prove absence of
security issues. Synthetic acceptance does not establish live Google/Okta or
production TLS behavior. See [CodeQL configuration](security/README.md#codeql-configuration)
for the advanced/default setup requirement.
