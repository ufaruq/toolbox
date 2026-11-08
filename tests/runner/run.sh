#!/usr/bin/env bash
set -euo pipefail
export TOOLBOX_TEST_OIDC_BROWSER=1 TOOLBOX_TEST_WORKSPACE_BROWSER=1
export TOOLBOX_TEST_KEYCLOAK=1 TOOLBOX_TEST_DOCKER_MCP=1 TOOLBOX_TEST_DOCKER_BRIDGE=1
python3 tests/hooks/pre_push_test.py
python3 tests/runner/check_results_test.py
python3 tests/docs/check_links.py
[[ -z "$(gofmt -l .)" ]]
go vet ./...
# Serialize packages sharing disposable databases; test/subtest race detection
# remains enabled. All environment-gated suites are explicitly enabled above.
go test -json -race -count=1 -p 1 -timeout=15m ./... | tee "$TOOLBOX_BROWSER_ARTIFACT_DIR/go-tests.json"
python3 tests/runner/check_results.py "$TOOLBOX_BROWSER_ARTIFACT_DIR/go-tests.json"
go build ./...

# Run the two standalone browser scripts too; they are not Go tests.
fixture="$TMPDIR/toolbox-fixture"
go build -o "$fixture" ./cmd/toolbox
port=$(python3 - <<'PY'
import socket
with socket.socket() as listener:
    listener.bind(('127.0.0.1', 0))
    print(listener.getsockname()[1])
PY
)
export TOOLBOX_MODE=fixture TOOLBOX_ADDR="127.0.0.1:$port" TOOLBOX_BASE_URL="http://127.0.0.1:$port"
"$fixture" > "$TOOLBOX_BROWSER_ARTIFACT_DIR/fixture.log" 2>&1 &
fixture_pid=$!
trap 'kill "$fixture_pid" 2>/dev/null || true; wait "$fixture_pid" 2>/dev/null || true' EXIT
export TOOLBOX_TEST_FIXTURE_PID="$fixture_pid"
python3 - <<'PY'
import os
import time
import urllib.request
for attempt in range(60):
    os.kill(int(os.environ['TOOLBOX_TEST_FIXTURE_PID']), 0)
    try:
        with urllib.request.urlopen(os.environ['TOOLBOX_BASE_URL'] + '/readyz', timeout=1) as response:
            if response.status == 200:
                break
    except OSError:
        pass
    time.sleep(.5)
else:
    raise SystemExit('Disposable fixture did not become ready')
PY
python3 tests/browser/fixture_e2e.py
python3 tests/browser/review_race.py
printf 'Full acceptance suite passed for %s\n' "$TOOLBOX_E2E_REVISION"
