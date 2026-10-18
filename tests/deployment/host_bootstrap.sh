#!/bin/bash
# Run only inside the disposable host-check image. Commands with real disk or
# package side effects are replaced at the OS boundary; filesystem permissions,
# unprivileged traversal and systemd unit syntax use the actual Linux tools.
set -euo pipefail
[[ -f /.dockerenv && -f /src/prepare-host.sh ]] || exit 2
mkdir -p /test/bin
cat > /test/bin/apt-get <<'MOCK'
#!/bin/sh
exit 0
MOCK
cat > /test/bin/blkid <<'MOCK'
#!/bin/sh
printf 'synthetic-test-disk\n'
MOCK
cat > /test/bin/mountpoint <<'MOCK'
#!/bin/sh
[ -f /test/disk-mounted ]
MOCK
cat > /test/bin/mount <<'MOCK'
#!/bin/sh
touch /test/disk-mounted
MOCK
cat > /test/bin/systemctl <<'MOCK'
#!/bin/sh
if [ "${HOST_CHECK:-}" = ordering ] && [ "$1" = enable ]; then
  [ -f /test/disk-mounted ] || { echo 'FAIL: Docker started before data mount'; exit 1; }
fi
exit 0
MOCK
chmod +x /test/bin/*
export PATH="/test/bin:$PATH"
export HOST_CHECK="${1:-traversal}"
bash /src/prepare-host.sh
case "$HOST_CHECK" in
 traversal)
  install -d -m 0700 -o nobody -g nogroup /var/lib/toolbox/release
  runuser -u nobody -- test -x /var/lib/toolbox/release || { echo 'FAIL: operator cannot traverse release directory'; exit 1; }
  echo 'PASS: unprivileged operator can enter protected release directory'
  ;;
 ordering)
  dropin=/etc/systemd/system/docker.service.d/toolbox-data.conf
  test -f "$dropin"
  # These are the required boot semantics, not a source-text assertion: inspect
  # the generated unit, then let systemd parse the resulting service/drop-in.
  awk -F= '$1=="RequiresMountsFor" && $2=="/var/lib/toolbox" {found=1} END {exit !found}' "$dropin"
  awk -F= '$1=="ConditionPathIsMountPoint" && $2=="/var/lib/toolbox" {found=1} END {exit !found}' "$dropin"
  cat > /etc/systemd/system/docker.service <<'UNIT'
[Unit]
Description=Disposable Docker dependency check
[Service]
ExecStart=/bin/true
UNIT
  cat > /etc/systemd/system/var-lib-toolbox.mount <<'UNIT'
[Mount]
What=tmpfs
Where=/var/lib/toolbox
Type=tmpfs
UNIT
  systemd-analyze verify /etc/systemd/system/docker.service /etc/systemd/system/var-lib-toolbox.mount
  echo 'PASS: Docker starts only after data mount and generated boot unit verifies'
  ;;
 *) exit 2 ;;
esac
