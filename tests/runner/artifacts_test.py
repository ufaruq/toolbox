"""Linux-only container regression: root-private evidence must be uploadable."""
import os
from pathlib import Path
import subprocess
import sys

# Hosted Linux bind mounts retain the invoking runner's UID. The root test
# process must own the private scratch ancestor before runtime state validation.
scratch = Path('/scratch')
scratch.chmod(0o700)
os.chown(scratch, 1001, 1001)
subprocess.run(['bash', 'tests/runner/prepare-scratch.sh'], check=True,
               env=dict(os.environ, TMPDIR=str(scratch)))
assert scratch.stat().st_uid == os.geteuid(), 'Scratch must belong to the test process'
assert (scratch.stat().st_mode & 0o777) == 0o700, 'Scratch must remain private'

# These are isolated tmpfs mounts in the regression container, never host paths.
for directory in ('/evidence/oidc-run-fixture', '/scratch/root-owned'):
    Path(directory).mkdir(mode=0o700, parents=True)
    target = Path(directory) / 'result.json'
    target.write_text('synthetic evidence')
    target.chmod(0o600)

check = '''
from pathlib import Path
for path in ('/evidence/oidc-run-fixture/result.json', '/scratch/root-owned/result.json'):
    assert Path(path).read_text() == 'synthetic evidence'
'''
def as_runner():
    os.setgroups([])
    os.setgid(1001)
    os.setuid(1001)

before = subprocess.run([sys.executable, '-c', check], preexec_fn=as_runner, capture_output=True)
assert before.returncode != 0 and b'PermissionError' in before.stderr, 'Regression must reproduce EACCES'
subprocess.run(['bash', 'tests/runner/restore-ownership.sh'], check=True,
               env=dict(os.environ, HOST_UID='1001', HOST_GID='1001'))
after = subprocess.run([sys.executable, '-c', check], preexec_fn=as_runner, capture_output=True)
assert after.returncode == 0, after.stderr.decode()
assert (Path('/evidence/oidc-run-fixture').stat().st_mode & 0o777) == 0o700
print('PASS: reproduced EACCES; restored non-root access without making evidence public')
