# Backup and recovery

Run `make deploy-backup` to create an age-encrypted PostgreSQL custom dump and a separate encrypted static-key archive in `.deploy/backups`. PostgreSQL snapshots include metadata and encrypted credential generations in one SQL consistency boundary. Provider operations outside SQL cannot be atomically snapshotted. The archive includes key rings, local encryption key, deployment ID, CA/server keys and database configuration. It excludes `backup-identity`; that age identity is the separate recovery secret.

The scheduled encryption process needs only the public `backup-recipient`. Export `backup-identity` to protected offline custody and test access before an incident. Keep it separate from the VM and backups. The one-off static archive process is an operator operation with access to static files. Runtime/API containers cannot read backups or the recovery identity. For production KMS, preserve required key versions and grant restore decryption to an explicitly authorized recovery identity. PostgreSQL backup files alone cannot recover credentials after losing the only local root key or destroying a required KMS version.

Manifests record ciphertext checksums, creation time, artifact kind and image/key resource references. SQL migration checksums and wrapped KMS version references are included inside the dump. Manifests are references, not plaintext secrets. Incomplete artifacts end in `.partial`; a successful SQL dump pipeline is required before publishing the latest database manifest. age authenticates stream contents; verification must succeed before considering a restore usable.

Copy encrypted artifacts and manifests off-host after every backup, for example with your authorized Google Cloud CLI account and the private Terraform bucket:

```sh
gcloud storage cp .deploy/backups/*.age gs://YOUR_BUCKET/checkpoint-UNIQUE/
gcloud storage cp .deploy/backups/latest-*.json gs://YOUR_BUCKET/checkpoint-UNIQUE/
```

On a VM, configure this transfer with the instance identity (object creation only), or transfer encrypted files over IAP to an authorized operator first. Verify uploads independently. The stack creates local backups; off-host delivery and alert routing must be configured and tested in your environment. The bucket denies public access, has versioning and a 90-day lifecycle. Keep referenced KMS versions and key recovery material at least as long as the longest retained copy. Coordinate object retention with legal/operational needs before changing it.

A dump is **not PITR**. A 15-minute schedule gives at best a roughly 15-minute checkpoint interval plus dump/upload duration and missed-run delays. Measure those delays. A strict RPO or PITR requires a separately verified WAL/base-backup solution. This single VM does not provide HA.

## Rehearse without touching live volumes

```sh
make deploy-backup
make deploy-restore-drill
```

The drill creates a uniquely named project/database volume with no published ports, authenticates the age stream, restores into that isolated database, expires sessions, revokes agent credentials and grants, advances active connection epochs, consumes outstanding OAuth callbacks and queues provider cleanup. It verifies those fences with actual SQL and stops the drill database. It never starts HTTP serving. Drill volumes remain for inspection; remove only a specifically identified drill project after review. No cleanup command deletes production volumes.

The drill uses the protected local recovery identity. For offline key custody, provide that identity through a controlled temporary file mount during an authorized rehearsal; remove the temporary copy afterward. Never place it in an image, Terraform, command-line argument or build context.

For disaster recovery, first preserve the damaged/live volumes and disable dispatch. Retrieve off-host artifacts and required static/KMS material. Verify age authentication and manifests, restore in isolation, run `recover-invalidate` before any serving, and review cleanup obligations. Never promote an uncertain pre-revocation snapshot with old authority still active. Signing-key rotation alone does not invalidate credentials, sessions, grants or provider generations.

Invalidation is idempotent and preserves audit history and session/OAuth foreign-key references. Unknown refresh/exchange outcomes remain blocked and retained for reconciliation. Do not resume dispatch merely because a SQL restore succeeded. Complete provider cleanup or reconnect accounts with new approvals and credentials, then pass the independent production release gates and readiness checks.
