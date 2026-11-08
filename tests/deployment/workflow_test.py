"""Exercise the deploy command with Docker replaced only at its process boundary."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


@unittest.skipIf(os.getuid() == 0, "deploy intentionally requires an ordinary operator")
class DeployWorkflow(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "scripts").mkdir()
        shutil.copy2(Path(__file__).resolve().parents[2] / "scripts/deploy", self.root / "scripts/deploy")
        tools = self.root / "bin"
        tools.mkdir()
        docker = tools / "docker"
        docker.write_text('''#!/usr/bin/env python3
import os, pathlib, sys
if "browser" in sys.argv:
    state = pathlib.Path(".deploy/verification")
    if not state.is_dir() or state.is_symlink() or state.stat().st_uid != os.getuid() or state.stat().st_mode & 0o077:
        sys.exit("Browser mounted a missing or unprotected state directory")
    with pathlib.Path("browser-runs").open("a") as out:
        out.write("browser\\n")
''')
        docker.chmod(0o700)
        self.env = dict(os.environ, PATH=str(tools) + os.pathsep + os.environ["PATH"], TOOLBOX_ENV="local")

    def run_deploy(self):
        return subprocess.run([str(self.root / "scripts/deploy"), "test"], cwd=self.root, env=self.env, text=True, capture_output=True)

    def test_first_browser_has_private_operator_owned_state(self):
        result = self.run_deploy()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / "browser-runs").read_text().splitlines(), ["browser"] * 3)

    def test_state_directory_cannot_redirect_writes(self):
        (self.root / ".deploy").mkdir()
        outside = self.root / "outside"
        outside.mkdir()
        (self.root / ".deploy/verification").symlink_to(outside, target_is_directory=True)
        result = self.run_deploy()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "browser-runs").exists())


if __name__ == "__main__":
    unittest.main()
