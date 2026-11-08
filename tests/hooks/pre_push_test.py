"""Exercise push enforcement against real temporary Git repositories."""
import os
from pathlib import Path
import subprocess
import shutil
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
HOOK = ROOT / '.githooks/pre-push'

class PushGate(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        self.env = dict(os.environ, GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null')
        self.git('init', '-q')
        self.git('config', 'user.name', 'Hook test')
        self.git('config', 'user.email', 'fixture@example.invalid')
        (self.repo / 'scripts').mkdir()

    def git(self, *args):
        return subprocess.check_output(['git', *args], cwd=self.repo, env=self.env, text=True).strip()

    def commit(self, code):
        script = self.repo / 'scripts/test-all'
        script.write_text('#!/bin/sh\nexit ' + str(code) + '\n')
        script.chmod(0o755)
        self.git('add', '.')
        self.git('commit', '-qm', 'test fixture')
        return self.git('rev-parse', 'HEAD')

    def push(self, oid):
        return subprocess.run(['bash', str(HOOK)], cwd=self.repo, env=self.env,
            input=f'refs/heads/main {oid} refs/heads/main {"0" * 40}\n',
            text=True, capture_output=True)

    def test_passes_committed_suite(self):
        result = self.push(self.commit(0))
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_failure_not_hidden_by_dirty_fix(self):
        oid = self.commit(23)
        (self.repo / 'scripts/test-all').write_text('#!/bin/sh\nexit 0\n')
        self.assertEqual(self.push(oid).returncode, 23)

    def test_non_head_push_rejected(self):
        old = self.commit(0)
        self.commit(23)
        result = self.push(old)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('check out', result.stderr)

    def test_delete_does_not_run_failing_suite(self):
        self.commit(23)
        self.assertEqual(self.push('0' * 40).returncode, 0)

    def install(self):
        (self.repo / '.githooks').mkdir(exist_ok=True)
        shutil.copy2(HOOK, self.repo / '.githooks/pre-push')
        return subprocess.run(['make', '-f', str(ROOT / 'Makefile'), 'install-hooks'],
                              cwd=self.repo, env=self.env, capture_output=True)

    def test_installs_persistent_executable_hook(self):
        self.assertEqual(self.install().returncode, 0)
        installed = Path(self.git('config', '--get', 'core.hooksPath')) / 'pre-push'
        self.assertTrue(os.access(installed, os.X_OK))
        self.assertEqual(installed.read_bytes(), HOOK.read_bytes())
        self.assertEqual(self.install().returncode, 0)

    def test_real_git_push_is_blocked_on_failure(self):
        self.commit(23)
        self.assertEqual(self.install().returncode, 0)
        remote = self.repo / '.git' / 'fixture-remote.git'
        self.git('init', '--bare', '-q', str(remote))
        result = subprocess.run(['git', 'push', str(remote), 'HEAD:refs/heads/main'],
                                cwd=self.repo, env=self.env, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'Validating pushed commit', result.stdout)
        refs = subprocess.run(['git', '--git-dir', str(remote), 'show-ref', '--verify', 'refs/heads/main'],
                              env=self.env, capture_output=True)
        self.assertNotEqual(refs.returncode, 0)

    def test_preserves_existing_custom_hooks(self):
        self.git('config', 'core.hooksPath', '/custom/hooks')
        self.assertNotEqual(self.install().returncode, 0)
        self.assertEqual(self.git('config', '--get', 'core.hooksPath'), '/custom/hooks')

    def test_missing_gate_rejected(self):
        self.commit(0)
        self.git('rm', 'scripts/test-all')
        self.git('commit', '-qm', 'missing runner')
        result = self.push(self.git('rev-parse', 'HEAD'))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('must include', result.stderr)

if __name__ == '__main__':
    unittest.main()
