"""Exercise isolation rules against real disposable Git repositories."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HELPER = Path(__file__).resolve().parents[2] / "scripts/worktree.py"


class WorktreeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve() / "repo with spaces"
        self.root.mkdir()
        self.git("init", "-b", "main")
        self.git("config", "user.email", "test@example.invalid")
        self.git("config", "user.name", "Worktree Test")
        (self.root / ".gitignore").write_text("/work/\n")
        self.git("add", ".gitignore")
        self.git("commit", "-m", "initial")

    def git(self, *args):
        return subprocess.check_output(["git", *args], cwd=self.root, stderr=subprocess.PIPE, text=True)

    def run_helper(self, *args, cwd=None, success=True):
        result = subprocess.run([sys.executable, str(HELPER), *args], cwd=cwd or self.root,
                                capture_output=True, text=True)
        self.assertEqual(result.returncode == 0, success, result.stderr)
        return result

    def test_creation_and_check_from_linked_checkout(self):
        result = self.run_helper("create", "first-task")
        first = self.root / "work/first-task"
        self.assertEqual(result.stdout.strip(), str(first))
        self.run_helper("check", cwd=first)
        self.run_helper("create", "second-task", cwd=first)
        self.assertTrue((self.root / "work/second-task/.git").is_file())
        self.assertFalse((first / "work").exists())
        self.assertEqual(self.git("branch", "--show-current").strip(), "main")

    def test_reject_main_and_legacy_worktrees(self):
        self.run_helper("check", success=False)
        legacy = self.root.parent / "legacy"
        self.git("worktree", "add", "-b", "legacy", str(legacy))
        self.run_helper("check", cwd=legacy, success=False)

    def test_collisions_preserve_work(self):
        self.run_helper("create", "first-task")
        sentinel = self.root / "work/first-task/private.txt"
        sentinel.write_text("unsaved work")
        self.run_helper("create", "first-task", success=False)
        self.run_helper("create", "second-task", "--branch", "task/first-task", success=False)
        self.assertEqual(sentinel.read_text(), "unsaved work")

    def test_reject_unsafe_names_and_missing_base(self):
        for slug in ("../escape", "nested/task", "UPPER", "--force", "bad.name"):
            self.run_helper("create", slug, success=False)
        self.run_helper("create", "valid", "--base", "missing-ref", success=False)
        self.assertFalse((self.root / "work/valid").exists())

    def test_require_ignore_rule(self):
        (self.root / ".gitignore").write_text("")
        self.run_helper("create", "unignored", success=False)
        self.assertFalse((self.root / "work/unignored").exists())

    def test_reject_redirected_parent(self):
        (self.root / "work").symlink_to(self.root.parent, target_is_directory=True)
        self.run_helper("create", "escaped", success=False)
        self.assertFalse((self.root.parent / "escaped").exists())

    def test_explicit_base_and_detached_check(self):
        self.git("branch", "base")
        self.run_helper("create", "custom", "--branch", "fix/custom", "--base", "base")
        custom = self.root / "work/custom"
        self.run_helper("check", cwd=custom)
        subprocess.check_call(["git", "checkout", "--detach"], cwd=custom,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.run_helper("check", cwd=custom, success=False)


if __name__ == "__main__":
    unittest.main()
