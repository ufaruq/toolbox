# CodeQL advanced setup

This workflow covers Go, JavaScript/TypeScript, Python test helpers and Actions. Go uses the version in go.mod and a manual `go build ./...`; security-extended queries run on PRs, main, weekly and manually. Actions are pinned to immutable commits.

Before using this workflow, open repository Settings → Advanced Security → CodeQL analysis and disable **default setup**, then use this advanced workflow. GitHub default setup blocks CodeQL uploads from custom workflows. Keep the other security settings enabled.

After a successful hosted run, require the CodeQL analysis checks in the main branch ruleset. Configuring a failure threshold alone does not prevent merges. Local workflow syntax validation does not replace a hosted CodeQL analysis.

Reference: https://docs.github.com/en/code-security/reference/code-scanning/troubleshoot-analysis-errors/results-different-than-expected
