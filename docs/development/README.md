# Development

[Overview](../../README.md) · [Architecture](../architecture/README.md) · [Agent rules](../../AGENTS.md)

## Setup

Use the Go version in [go.mod](../../go.mod), Git, Docker Engine, and Docker Compose >=2.24.4. Run `make install-hooks` once per clone. The installer copies the hook into the shared Git directory, so linked worktrees use it even after the installing worktree is removed. Rerun installation when the tracked hook changes. An existing custom hooks path is preserved: integrate this gate with it before replacing it.

Run `TOOLBOX_MODE=fixture go run ./cmd/toolbox` for the in-memory synthetic demo, or `make dev` for disposable local stores. Real-provider setup is indexed in [operations](../operations/README.md).

## Test workflow

Use targeted Go tests during editing. `make check` is a quick baseline, not complete acceptance: unset integration environments cause some tests to skip.

Run `make test-all` for full validation. The runner builds a pinned Linux image with Go, Chromium/Playwright and Docker CLI; starts unique PostgreSQL/OpenBao fixtures on a dedicated Docker bridge without published storage ports; enables all gated Go suites; runs race detection, formatting, vet and build; and runs standalone fixture/review-race browsers. It rejects skipped tests and requires the five named browser/Keycloak/MCP acceptance suites to pass.

The runner needs image download access and Docker socket access. It runs trusted repository test code with control of the local Docker engine. Do not run untrusted contributions on a machine with sensitive Docker workloads. It uses only its own disposable resources, does not source `.env`, and does not use personal provider credentials. Evidence stays in the printed temporary directory after cleanup. Initial image downloads and builds can take several minutes.

The pre-push hook archives the commit being pushed and validates that snapshot. Dirty files and untracked secrets are excluded. Non-HEAD pushes are rejected: check out the intended commit and push separately. Deletes do not introduce code and do not run the suite. A commit without the gate script is rejected after hook installation.

A failing or unavailable test blocks the push. Fix the failure and commit before retrying; do not use `--no-verify`. Hooks cannot enforce every remote client: configure a GitHub branch ruleset requiring the full acceptance check and applicable security checks, with controlled bypass permissions. A tracked `AGENTS.md` communicates expectations but is not a security boundary.

## Troubleshooting and evidence

- Docker unavailable: start the engine and rerun; this is not a passing result.
- Browser failure: inspect the printed evidence directory and stage, avoiding raw logs containing credentials. See [browser tests](../../tests/browser/README.md).
- Local pass but CI failure: compare exact revision, enabled suites, platform and artifacts; reproduce the failed assertion before changing it.
- Live provider behavior: record it separately from synthetic browser and container acceptance. Successful sign-in does not prove Google Drive consent, MCP access, tenant isolation or production readiness.

## Documentation conventions

Keep one authoritative explanation per topic. The root README gives the overview and navigation; focused READMEs explain current architecture, development, security and operations. Setup guides retain exact provider-specific steps. Verification reports record revision, date, commands and limitations. Label historical checkpoints; never silently turn old evidence into a current passing claim.

Update documentation in the same change as behavior. Run `python3 tests/docs/check_links.py` to check local documentation targets. Add nested `AGENTS.md` files only when a subtree has genuinely different rules; avoid contradictory duplicate instructions.
