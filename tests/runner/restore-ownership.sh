#!/usr/bin/env bash
# Run inside the isolated helper container, with only task-owned mounts.
set -euo pipefail
: "${HOST_UID:?missing host UID}" "${HOST_GID:?missing host GID}"
[[ "$HOST_UID" =~ ^[0-9]+$ && "$HOST_GID" =~ ^[0-9]+$ ]]
# Do not follow symlinks, and retain private directory/file modes.
chown -hR "$HOST_UID:$HOST_GID" /evidence /scratch
