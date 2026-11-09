import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

class ResultsGate(unittest.TestCase):
    def run_gate(self, events):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'events.json'
            path.write_text('\n'.join(json.dumps(e) for e in events))
            return subprocess.run([sys.executable, str(Path(__file__).with_name('check_results.py')), str(path)], capture_output=True).returncode

    def passing(self):
        return [dict(Action='pass', Test=name) for name in (
            'TestWorkspaceBrowserFlow', 'TestProbeBrowserFlow', 'TestOIDCBrowserFlow', 'TestGitHubBrowserFlow',
            'TestKeycloakBrokerFlow', 'TestDockerGatewayOwnerIsolation', 'TestDockerReviewedRuntimeStartup')]

    def test_accept_complete(self):
        self.assertEqual(self.run_gate(self.passing()), 0)

    def test_allow_package_without_tests(self):
        self.assertEqual(self.run_gate(self.passing() + [dict(Action="skip", Package="helper")]), 0)

    def test_reject_missing(self):
        self.assertNotEqual(self.run_gate(self.passing()[:-1]), 0)

    def test_reject_skip(self):
        self.assertNotEqual(self.run_gate(self.passing() + [dict(Action='skip', Test='Integration')]), 0)

    def test_reject_failure(self):
        self.assertNotEqual(self.run_gate(self.passing() + [dict(Action='fail', Package='app')]), 0)

if __name__ == '__main__':
    unittest.main()
