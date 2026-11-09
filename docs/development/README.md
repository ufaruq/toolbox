# Development

[Overview](../../README.md) · [Architecture](../architecture/README.md) · [Agent rules](../../AGENTS.md)

## Setup

Use the Go version in [go.mod](../../go.mod), Git, Docker Engine, and Docker Compose >=2.24.4. Run `make install-hooks` once per clone. The installer copies the hook into the shared Git directory, so linked worktrees use it even after the installing worktree is removed. Rerun installation when the tracked hook changes. An existing custom hooks path is preserved: integrate this gate with it before replacing it.

Run `make run` for the in-memory synthetic demo, or `make dev` for disposable local stores. Real-provider setup is indexed in [operations](../operations/README.md).

## Make command reference

`make` or `make help` lists every supported target. Commands run from the repository root. Environment variables still configure private credentials and runtime addresses; do not put secrets in Make arguments or commit them.

| Purpose | Command |
| --- | --- |
| In-memory fixture | `make run` |
| Stores plus foreground fixture | `make dev` |
| Stores only / test database | `make deps` / `make deps-test` |
| Inspect / follow dependency logs / stop | `make dev-status` / `make dev-logs` / `make dev-down` |
| Start with already-exported settings, without reloading `.env` | `make run-configured` |
| Real owner login / Google document flow | `make oidc` / `make workspace` |
| Render realm / migration dry run / explicit apply | `make keycloak-config` / `make keycloak-link` / `make keycloak-link-apply` |
| Live Google client PKCE check | `make google-pkce-check` |
| Format / verify formatting / static analysis | `make fmt` / `make fmt-check` / `make vet` |
| Build packages / executable | `make build` / `make build-binary` |
| Race tests / focused test | `make test` / `make test TEST_PACKAGES=./internal/store TEST_RUN=TestMemoryRepository` |
| Configured disposable-store tests | `make test-integration` |
| Quick combined checks | `make check` |
| Complete isolated acceptance | `make test-all` |
| Go vulnerability scan / Semgrep CE | `make vuln-check` / `make semgrep-check` |
| Documentation links / gate regressions | `make docs-check` / `make test-tools` |
| Install pinned browser dependencies | `make browser-install` |
| Synthetic OIDC / Workspace browsers | `make oidc-browser-check` / `make workspace-browser-check` |
| Running fixture / delayed-review browsers | `make browser-fixture-check` / `make browser-review-check` |
| GitHub authorization / browser flow | `make github-check` / `make github-browser-check` |
| All browser flows | `make browser-check` |
| Real Keycloak / MCP gateway acceptance | `make keycloak-check` / `make mcp-gateway-check` |
| Install local push gate | `make install-hooks` |

`make dev` and `make run` remain in the foreground; Ctrl-C stops the app. `make dev-down` only stops/removes the selected Compose project's dependencies and loses their disposable state. It does not terminate a separately started app. Set `COMPOSE='docker compose -p your-project'` consistently to select a different Compose project; the default project/ports follow `compose.yaml`.

`make oidc`, `make workspace`, and `make google-pkce-check` load trusted private `ENV_FILE` (default `.env`). Keycloak configuration/migration targets consume already-exported settings, following [Keycloak setup](../keycloak-setup.md); `keycloak-link` is a dry run and only `keycloak-link-apply` performs migration. Realm output defaults to `KEYCLOAK_REALM_FILE=work/keycloak/realm.json`. Nothing starts or reconfigures an existing Keycloak server automatically.

`make test-integration` requires all three `TOOLBOX_TEST_DATABASE_URL`, `TOOLBOX_TEST_OPENBAO_ADDR`, and `TOOLBOX_TEST_OPENBAO_TOKEN` variables, failing if missing. See [storage setup](../storage.md#verification). `make test-all` supplies isolated stores automatically and is the preferred complete check.

`make browser-install` creates `work/browser-venv`; override `BROWSER_VENV` if needed. Browser checks use its Python by default. An existing installation can be selected with `BROWSER_PYTHON=/absolute/path/to/python3` (or `BROWSER_PYTHON=python3` in the acceptance image). `make browser-check` needs a fresh synthetic fixture running at `http://127.0.0.1:18080`: start it separately with `TOOLBOX_ADDR=127.0.0.1:18080 make run`. It runs fixture approval before delayed-review scenarios. Synthetic OIDC/Workspace targets create their own servers. See [browser coverage](../../tests/browser/README.md).

Internal runner targets are also discoverable: `make test-json` runs every Go package serially and emits JSON; `make test-results-check TEST_RESULTS=/path/to/results.json` validates coverage; `make test-artifacts RUNNER_IMAGE=<built-image-id>` verifies Linux artifact permissions. The complete runner calls these targets and restores artifact ownership to the invoking host user on success or failure, without making private evidence world-readable.

## Test workflow

Use `make test TEST_PACKAGES=./internal/store TEST_RUN=TestMemoryRepository` for targeted checks during editing. `make check` is a quick baseline, not complete acceptance: unset integration environments cause some tests to skip.

Run `make test-all` for full validation. The runner builds a pinned Linux image with Go, Chromium/Playwright and Docker CLI; starts unique PostgreSQL/OpenBao fixtures on a dedicated Docker bridge without published storage ports; enables all gated Go suites; runs race detection, formatting, vet and build; and runs standalone fixture/review-race browsers. It rejects skipped tests and requires the named browser/Keycloak/MCP acceptance suites to pass.

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

Update documentation in the same change as behavior. Run `make docs-check` to check local documentation targets. Add nested `AGENTS.md` files only when a subtree has genuinely different rules; avoid contradictory duplicate instructions.

### GitHub App registration

`make github-app-setup` prints a prefilled registration URL without reading secrets or creating an App. Follow [GitHub App setup](../../github-app/README.md) to register and install it; see [GitHub access](../github-connector.md) for the owner approval flow and current runtime limits.
