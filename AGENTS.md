# Working on Toolbox

Read [README.md](README.md) first, then the relevant [architecture](docs/architecture/README.md), [development](docs/development/README.md), and [security](docs/security/README.md) sections. Historical plans describe intent; current code and reproducible tests establish behavior.

## Isolate every change

Before editing files for any task or PR, read and follow
[task-worktrees](.agents/skills/task-worktrees/SKILL.md).
This applies to Codex, Claude, and other agents, including documentation and
configuration changes. Read-only investigation can happen in the main checkout.

- Keep the main checkout as the coordination checkout. Do all task edits in a
  linked Git worktree at `<main-checkout>/work/<task-slug>` on its own branch.
- Use one worktree and branch per task/PR. Independent concurrent writers need
  separate worktrees; a handoff may reuse the task worktree once its writer stops.
- Reuse your current worktree only when it belongs to the current task and is in
  the canonical location. Never create `work/` inside a linked worktree.
- Use `python3 scripts/worktree.py create <task-slug>` from any checkout, then
  change to the printed path. Run `python3 scripts/worktree.py check` there
  before edits. Do not fall back to editing the main checkout if creation fails.
- This explicit location overrides generic skill defaults. Native agent worktree
  features are suitable only if they honor this location; otherwise launch the
  agent in the helper-created directory without automatic worktree creation.
- Do not move, delete, reset, stash, or reuse another task's worktree or branch.
  Do not change shared Git config/hooks or switch the main checkout's branch as
  incidental setup. Ask the user to resolve blocked isolation.

## Required workflow

- Run `make install-hooks` once per fresh clone before pushing; linked worktrees share hooks, so do not replace an existing custom hook configuration.
- Use `make help` to discover commands and `make test TEST_PACKAGES=./internal/store TEST_RUN=TestMemoryRepository` for focused tests while editing. Before every push, the installed hook must complete the full `scripts/test-all` gate against the committed revision. Use `make test-all` to debug the same suite before committing.
- Before every push, inspect the current `.github/workflows/` and map each applicable check to local verification. Run all locally executable checks relevant to the diff on the final contents, including `make semgrep-check`, `make vuln-check` for Go/dependency changes, and the pinned Trivy source scan for Docker/configuration changes. The full acceptance gate does not include every independent CI scanner. Do not use a push as the first test of a locally reproducible failure.
- For image recipes, download URLs, checksums or build-tool changes, verify the affected download/build stage without cache as well as the full gate. Check expected digests against upstream release metadata; never change a pin to match an unexplained failed download. Cached local success alone does not validate fresh CI downloads.
- Do not push with any known unresolved failure or an unrun required local check. After changing code/configuration, rerun the affected checks before committing; the pre-push hook must then validate the exact committed revision. Record commands, revision and results. Identify genuinely CI-only checks explicitly instead of treating them as local passes.
- After every push, inspect every PR check for the new head revision and monitor them through completion. Read failed job logs, fix the cause, repeat local verification and monitor the replacement run. Do not hand off a PR as complete, green or ready while any applicable check is pending, failed or unexpectedly skipped. An external outage is a blocker to report, not a passing result; rerun only when evidence supports a transient failure. Never merge without verified passing required CI checks.
- Never bypass the gate with `--no-verify`, disable hooks, remove opt-in tests, suppress failures, or describe missing prerequisites/skipped tests as a pass. If the gate cannot run, report the blocker and do not push.
- `make check` and ordinary `go test ./...` alone are insufficient: browser, PostgreSQL, OpenBao, Keycloak and MCP acceptance require explicit setup. The full runner supplies it.
- Report the tested revision, commands, results, and any remaining live-provider validation. Synthetic providers do not prove live Google/Okta behavior. Do not claim CI passed without checking its result.
- Preserve unrelated work and private local configuration. Use an isolated worktree when appropriate. Never commit downloaded OAuth credentials, `.env` files, tokens, or unredacted browser artifacts.

## Change boundaries

- Keep owner login, provider authorization, MCP caller identity, agent credentials, and document grants distinct. Account connection alone never authorizes document access.
- Never link identities by email alone or weaken issuer/audience/client validation. Preserve final authorization and revocation checks at dispatch.
- Add regression coverage for security fixes and reproduced bugs. Do not loosen assertions to make CI green.
- Add database migrations; do not rewrite applied migrations. See [storage](docs/storage.md).
- Update the relevant focused documentation when behavior or setup changes. Keep the root README an overview; link to details instead of duplicating them.
- Keep verification records dated/revision-specific and separate from current architecture. Do not present proposed features as implemented.

## Keep component documentation current

- Before changing a component, locate and read its existing documentation: nearby READMEs, the documentation map in the root README, and relevant guides under `docs/`. Search for the component name, configuration keys, and commands to find affected references.
- Update the affected documentation in the same PR whenever a change alters documented behavior, APIs, configuration, setup, architecture, security guarantees, limitations, or testing instructions. A component change is not complete while its documentation describes the previous behavior.
- Update the existing authoritative guide instead of creating a competing explanation. Keep the root README as an overview and update its links when documentation moves or new guides are added. Preserve dated historical evidence; update current guidance separately.
- For login, identity linking, Google, or MCP changes, review the corresponding provider/setup guides and architecture/security documentation. For storage changes, review `docs/storage.md`. For Make targets, CI, tests, or hooks, review `docs/development/README.md` and the relevant test README. For worktree tooling, review `docs/agent-worktrees.md` and `.agents/skills/task-worktrees/SKILL.md`.
- Verify changed commands and examples where practical, run `make docs-check`, and identify the documentation updated in the PR description. If no documentation update is needed, briefly explain why the existing documentation remains accurate; do not make cosmetic edits just to satisfy this rule.

## Navigation

- Application wiring and acceptance: `internal/app`, `cmd/toolbox`.
- HTTP/UI/MCP and authorization: `internal/server`, `internal/security`.
- Login and migration: `internal/ownerlogin`, `internal/identity`, `internal/identitylink`, `internal/keycloakrealm`.
- Provider access and persistence: `internal/oauth`, `internal/connectors`, `internal/tokens`, `internal/store`.
- Test runner and push enforcement: `scripts/test-all`, `tests/runner`, `.githooks/pre-push`.

Git hooks are local and technically bypassable. Repository rules must also require CI checks before merging; this file alone cannot enforce compliance by every client or agent.

Worktree helper checks: `python3 -m unittest discover -s tests/worktrees -v`.

Worktrees share Git refs and object storage, but not untracked files. Set up dependencies and private configuration per task; never copy secrets by default. Use separate ports, Compose project names, databases, and volumes for parallel runtime tests. Coordinate shared external services explicitly.
