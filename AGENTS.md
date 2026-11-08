# Working on Toolbox

Read [README.md](README.md) first, then the relevant [architecture](docs/architecture/README.md), [development](docs/development/README.md), and [security](docs/security/README.md) sections. Historical plans describe intent; current code and reproducible tests establish behavior.

## Required workflow

- Run `make install-hooks` in each fresh clone before pushing.
- Use focused tests while editing. Before every push, the installed hook must complete the full `scripts/test-all` gate against the committed revision. Use `make test-all` to debug the same suite before committing.
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

## Navigation

- Application wiring and acceptance: `internal/app`, `cmd/toolbox`.
- HTTP/UI/MCP and authorization: `internal/server`, `internal/security`.
- Login and migration: `internal/ownerlogin`, `internal/identity`, `internal/identitylink`, `internal/keycloakrealm`.
- Provider access and persistence: `internal/oauth`, `internal/connectors`, `internal/tokens`, `internal/store`.
- Test runner and push enforcement: `scripts/test-all`, `tests/runner`, `.githooks/pre-push`.

Git hooks are local and technically bypassable. Repository rules must also require CI checks before merging; this file alone cannot enforce compliance by every client or agent.
