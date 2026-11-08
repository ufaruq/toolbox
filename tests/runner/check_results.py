"""Reject skipped tests and require the opt-in acceptance suites to pass."""
import json
import sys
from pathlib import Path

required = {
    'TestWorkspaceBrowserFlow', 'TestProbeBrowserFlow', 'TestOIDCBrowserFlow',
    'TestKeycloakBrokerFlow', 'TestDockerGatewayOwnerIsolation',
}
passed = set()
skipped = []
failed = []
for line in Path(sys.argv[1]).read_text().splitlines():
    event = json.loads(line)
    action, test = event.get('Action'), event.get('Test')
    if action == 'pass' and test:
        passed.add(test)
    # Go emits package-level skip events for packages containing no tests.
    if action == 'skip' and test:
        skipped.append(test or event.get('Package'))
    if action == 'fail':
        failed.append(test or event.get('Package'))
missing = sorted(required - passed)
if skipped or failed or missing:
    raise SystemExit(f'Incomplete test gate: skipped={skipped}, failed={failed}, missing={missing}')
print(f'{len(passed)} tests/subtests passed; no skips; all five opt-in acceptance suites ran.')
