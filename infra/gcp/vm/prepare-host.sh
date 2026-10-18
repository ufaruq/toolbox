#!/bin/bash
set -euo pipefail
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y docker.io docker-compose-v2 python3
systemctl enable --now docker
# This resource is a dedicated data disk, not the VM boot device. Never format
# an existing filesystem; refuse unknown signatures and let an operator recover.
device=/dev/disk/by-id/google-toolbox-data
if ! blkid "$device" >/dev/null 2>&1; then
  if wipefs -n "$device" | tail -n +2 | grep -q .; then exit 1; fi
  mkfs.ext4 "$device"
fi
mkdir -p /var/lib/toolbox
if ! mountpoint -q /var/lib/toolbox; then mount "$device" /var/lib/toolbox; fi
chmod 700 /var/lib/toolbox
mkdir -p /var/lib/toolbox/postgres
uuid=$(blkid -s UUID -o value "$device")
if ! grep -q "UUID=$uuid " /etc/fstab; then
  printf 'UUID=%s /var/lib/toolbox ext4 defaults,nofail 0 2\n' "$uuid" >> /etc/fstab
fi
# Compose maps the database volume explicitly into this durable mount on the VM.
# App installation and secrets transfer remain explicit operator steps.
