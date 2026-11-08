# Agent instructions

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

## Project checks

See README.md and docs/HANDOFF.md for project context. The application is Go;
`make check` runs formatting, vet, race tests, and build. Run checks appropriate
to the change. Worktree helper checks: `python3 -m unittest discover -s tests/worktrees -v`.

Worktrees share Git refs and object storage, but not untracked files. Set up
dependencies and private configuration per task; never copy secrets by default.
Use separate ports, Compose project names, databases, and volumes for parallel
runtime tests. Coordinate shared external services explicitly.
