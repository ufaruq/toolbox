#!/usr/bin/env bash
# The runner receives its own disposable scratch bind mount from scripts/test-all.
set -euo pipefail
: "${TMPDIR:?missing runner scratch directory}"
# Linux preserves the host user's ownership across the mount. Runtime state
# requires ancestors owned by root or the service UID; change only this mount's
# top directory, retaining its private mode. Cleanup restores host ownership.
chown "$(id -u):$(id -g)" -- "$TMPDIR"
