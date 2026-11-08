# Semgrep Community Edition

The workflow runs `semgrep scan --config p/ci --error --strict` without Semgrep credentials, including on fork and Dependabot PRs. It scans on PRs, main, weekly and manually. Findings or scan/configuration errors fail the job. Reports are retained for 14 days and uploaded to GitHub code scanning. Metrics/version checks are disabled. The container and Actions use immutable pins; the community registry ruleset is fetched when each scan runs and can evolve.

Six exact redirect sites have reviewed, rule-specific `nosemgrep` explanations: one validates the configured origin and callback path; one uses a fixed relative fragment with an escaped ID; four are intentionally configurable synthetic identity-provider test redirects. Tests remain in scan scope. No file-wide security exclusions were added.

Local Semgrep scan: 168 files, 63 applicable rules, zero unsuppressed findings. This is pattern analysis, not proof of absence of vulnerabilities.
