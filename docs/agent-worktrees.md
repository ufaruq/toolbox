# Parallel agent work

All new task checkouts live at `<main-checkout>/work/<task-slug>`.
The main checkout is for coordination; each task/PR has a separate branch and
worktree. Existing external worktrees are left in place until their owners
finish them. No migration or deletion is automatic.

```sh
# From the main checkout (or any linked checkout containing this helper):
python3 scripts/worktree.py list
python3 scripts/worktree.py create fix-token-refresh
cd /path/to/toolbox/work/fix-token-refresh  # use the printed absolute path
python3 scripts/worktree.py check
codex  # or claude; start the agent here without another --worktree option
```

The base defaults to local `main`. Check freshness first; fetch explicitly if
needed, then pass `--base origin/main`. Branches default to `task/<task-slug>`;
`--branch fix/token-refresh` overrides that. Names must be unique. The helper
never fetches, copies secrets, installs dependencies, removes worktrees, or
changes existing checkouts. Run it with `--help` for commands.

`AGENTS.md` contains the always-on policy and references the local skill at
`.agents/skills/task-worktrees/SKILL.md`. `CLAUDE.md` imports `AGENTS.md` for
compatibility with Claude sessions that do not load it directly. A relative
symlink at `.claude/skills/task-worktrees` exposes the same skill to Claude;
there is only one maintained copy. On systems without Git symlink support,
agents can still follow the explicit skill path in `AGENTS.md`.

These instructions guide agents; they are not a security boundary or a universal
write interceptor. An agent must load the project instructions and honor them.
The helper enforces its own creation/check rules, but cannot intercept arbitrary
shell commands. Restart existing agents after adopting the policy and confirm
they loaded the instructions/skill. Agents without AGENTS.md support must be
configured to read it. For Codex, inspect the skill selector; for Claude, inspect
`/context all` and the skills list.

Before a parallel run, reserve distinct runtime ports and, when using Compose,
distinct project names and data resources. Git worktrees share refs, config,
hooks, and object storage. They isolate files and indexes, not external services
or changes to the same code at merge time. One active writer per task directory
avoids file races. Integrate PRs sequentially and resolve overlapping changes.

After the PR merges, stop its sessions/services, inspect `git status --short`
inside the worktree and verify commits are saved, then use
`git worktree remove <absolute-task-path>` without force. Delete its branch only
after verifying it is no longer needed. Never remove directories with `rm -rf`
or automatically prune another session's work.

## Research and choices (2026-11-08)

- [Git worktree manual](https://git-scm.com/docs/git-worktree): separate working
  trees and indexes share repository data; Git normally prevents a branch being
  checked out twice. Use Git lifecycle commands instead of directory deletion.
- [Codex skill discovery](https://learn.chatgpt.com/docs/build-skills): repository
  skills live under `.agents/skills`, with symlinked folders supported.
  [Customization](https://learn.chatgpt.com/docs/customization/overview) places
  durable project guidance in `AGENTS.md`.
- [Claude project memory](https://code.claude.com/docs/en/memory): a `CLAUDE.md`
  import keeps `AGENTS.md` shared across tools and older sessions.
  [Claude skills](https://code.claude.com/docs/en/skills) support project skills
  under `.claude/skills` and symlinked skill directories.
- [Claude parallel worktrees](https://code.claude.com/docs/en/common-workflows#run-parallel-sessions-with-worktrees)
  confirms the separate-checkout approach. Its automatic location is not this
  repository's chosen location, so start Claude in an already-created checkout.
- The installed Superpowers `using-git-worktrees` skill recommends detecting
  existing isolation, honoring explicit directory preferences, verifying ignored
  local worktree directories, and checking the baseline. This repo adopts those
  principles, with one fixed `work/` parent and no in-place fallback on failure.

Instructions alone are lighter but leave path selection to each agent. Agent
native worktree defaults are convenient but differ by tool. The shared policy,
single skill, and small Git helper give this repo consistent placement across
tools without requiring global configuration or installing Superpowers.
