---
name: task-worktrees
description: Use before making changes in Toolbox, when starting a task or PR, or when handing off concurrent agent work.
---

# Task worktrees

The canonical parent is `work/` in the main checkout, never relative to the
current linked worktree. The repository helper resolves it using shared Git
metadata. Python 3 and Git are required.

1. Inspect `git status --short`, `git branch --show-current`, and
   `python3 scripts/worktree.py list`. Identify the current task and owner.
2. If already in this task's canonical worktree, run
   `python3 scripts/worktree.py check` and continue there. A passing check verifies
   location and branch, not ownership: do not join another active writer.
3. Otherwise choose a descriptive lowercase hyphenated slug, such as
   `fix-token-refresh` or `pr-123-token-refresh`. Create it:

   ```sh
   python3 scripts/worktree.py create fix-token-refresh
   # Then cd to the absolute path printed on stdout.
   ```

   Default branch: `task/<slug>`; default base: local `main`. To choose explicitly:

   ```sh
   python3 scripts/worktree.py create fix-token-refresh --branch fix/token-refresh --base origin/main
   ```

   Inspect base freshness. Fetch if needed and permitted before choosing
   `origin/main`; the helper deliberately does not fetch, install, or copy files.
   Existing paths/branches fail rather than silently sharing a task. If two
   sessions collide, choose a distinct meaningful slug; never use `--force`.
4. Change directory, run the helper's `check`, inspect the clean baseline, and
   run appropriate baseline checks before implementation. Report pre-existing
   failures separately. Keep every edit, install, build, and commit in that
   worktree. If sandbox permissions block Git metadata writes, request the
   necessary permission; do not continue in the main checkout.
5. At handoff, report absolute path, branch, base, checks, and any running services.
   Keep the worktree until the PR is merged or the user explicitly requests
   cleanup. After checking status, saved commits, and inactive sessions, use
   `git worktree remove <absolute-path>` without force. Branch deletion is a
   separate decision; never automatically delete branches or dirty worktrees.

Existing worktrees outside `work/` are legacy sessions: leave them alone and
report the location mismatch. New tasks use the canonical location. Do not nest
new worktrees under a legacy or harness-managed checkout.
