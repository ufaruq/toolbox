#!/bin/bash
set -euo pipefail
# Prepare and verify the dedicated data disk before installing/starting Docker.
# Never format an existing filesystem; refuse unknown signatures.
device=/dev/disk/by-id/google-toolbox-data
if ! blkid "$device" >/dev/null 2>&1; then
  if wipefs -n "$device" | tail -n +2 | grep -q .; then exit 1; fi
  mkfs.ext4 "$device"
fi
mkdir -p /var/lib/toolbox
if ! mountpoint -q /var/lib/toolbox; then mount "$device" /var/lib/toolbox; fi
mountpoint -q /var/lib/toolbox || { echo 'Required Toolbox data mount unavailable.' >&2; exit 1; }
# Traversal permits the OS Login operator to reach its own 0700 release child.
# PostgreSQL and deployment secret directories keep their separate permissions.
chmod 711 /var/lib/toolbox
mkdir -p /var/lib/toolbox/postgres
uuid=$(blkid -s UUID -o value "$device")
if ! grep -q "UUID=$uuid " /etc/fstab; then
  printf 'UUID=%s /var/lib/toolbox ext4 defaults,nofail 0 2\n' "$uuid" >> /etc/fstab
fi
# nofail keeps SSH available for recovery. Docker itself must require this mount
# and refuse to start against an underlying boot-disk directory after a reboot.
mkdir -p /etc/systemd/system/docker.service.d
cat > /etc/systemd/system/docker.service.d/toolbox-data.conf <<'UNIT'
[Unit]
RequiresMountsFor=/var/lib/toolbox
After=var-lib-toolbox.mount
BindsTo=var-lib-toolbox.mount
ConditionPathIsMountPoint=/var/lib/toolbox
UNIT
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y docker.io docker-compose-v2 python3
systemctl daemon-reload
systemctl enable --now docker
# App installation and secret generation/transfer remain explicit operator steps.
