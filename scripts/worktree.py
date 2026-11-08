#!/usr/bin/env python3
"""Create and verify task worktrees under the main checkout's work/ directory."""

import argparse
from pathlib import Path
import re
import subprocess
import sys


def git(*args, cwd=None):
    return subprocess.check_output(
        ["git", *args], cwd=cwd, text=True, stderr=subprocess.PIPE
    ).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create")
    create.add_argument("slug")
    create.add_argument("--branch")
    create.add_argument("--base", default="main")
    commands.add_parser("list")
    commands.add_parser("check")
    args = parser.parse_args()

    if git("rev-parse", "--show-superproject-working-tree"):
        raise ValueError("Run from the Toolbox checkout, not a submodule.")
    common = Path(git("rev-parse", "--path-format=absolute", "--git-common-dir")).resolve()
    root = common.parent
    if common.name != ".git" or not (root / ".git").is_dir():
        raise ValueError("Expected a main checkout with a .git directory (bare/separate Git dirs unsupported).")
    parent = root / "work"
    if parent.is_symlink() or parent.resolve() != parent:
        raise ValueError("Canonical work/ must not redirect outside the main checkout.")

    if args.command == "list":
        print(git("worktree", "list", cwd=root))
    elif args.command == "check":
        current = Path(git("rev-parse", "--show-toplevel")).resolve()
        own_git = Path(git("rev-parse", "--absolute-git-dir")).resolve()
        branch = git("branch", "--show-current")
        if (own_git == common or current.parent != parent
                or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", current.name)
                or not branch or branch in ("main", "master")):
            raise ValueError("Edits require a task branch in a linked worktree at " + str(parent / "<task-slug>"))
        print(f"{current} [{branch}]")
    else:
        if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", args.slug):
            raise ValueError("Use a lowercase hyphenated task slug, without slashes or dots.")
        target = parent / args.slug
        if target.exists() or target.is_symlink():
            raise ValueError(f"Path already exists; do not share an active task: {target}")
        branch = args.branch or f"task/{args.slug}"
        if branch in ("main", "master"):
            raise ValueError("Use a task branch, not main/master.")
        git("check-ref-format", "--branch", branch, cwd=root)
        # Verify the exact target is ignored before creating a checkout.
        git("check-ignore", "-q", "--", str(target), cwd=root)
        git("rev-parse", "--verify", "--end-of-options", args.base + "^{commit}", cwd=root)
        # Git atomically refuses existing branches, including concurrent claims.
        result = subprocess.run(
            ["git", "worktree", "add", "-b", branch, str(target), args.base],
            cwd=root, capture_output=True, text=True, check=True,
        )
        print(result.stdout, end="", file=sys.stderr)
        print(result.stderr, end="", file=sys.stderr)
        print(target)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, subprocess.CalledProcessError) as error:
        detail = error.stderr if isinstance(error, subprocess.CalledProcessError) else str(error)
        print(f"worktree: {detail or str(error)}", file=sys.stderr)
        sys.exit(1)
