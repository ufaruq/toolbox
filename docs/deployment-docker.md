# Docker and GCP deployment

The portable stack uses one application image and PostgreSQL 17 on a VM. Production defaults to GCP KMS envelope encryption. Local verification substitutes a persistent AES-GCM root key and runs the same encrypted SQL/CAS code. OpenBao is used only by the existing regression tests.

**Production HTTP serving is deliberately blocked.** Owner OIDC is unfinished and the real Google client has not passed live validation. `serve` refuses startup; production `preflight` reports those gates and exits nonzero. `preflight-storage` checks storage independently and cannot enable serving. Do not publish fixture login or change a flag to bypass these gates.

## Local: Docker and Compose only

From the repository root:

```sh
make deploy-init       # build image; generate keys, passwords and a deployment CA once
make deploy-up         # provision roles, migrate, check storage, start the fixture UI
make deploy-test       # containerized Go race/integration, Chromium, delayed review, restart
make deploy-backup
make deploy-restore-drill
make deploy-cleanup
make deploy-retention
make deploy-monitor
```

Open <http://127.0.0.1:18080>. Use synthetic documents only. The fixture listener is explicitly enabled inside its container; the host publishes loopback only. PostgreSQL and test dependencies have no published ports. Browser tests share the app's network namespace and enforce the existing loopback request filter. The original `make test`, `make check`, `make dev` and disposable root `compose.yaml` continue to work.

`make deploy-stop` stops containers and preserves volumes. `make deploy-status` shows health. There is no automatic volume deletion. Keys and generated configuration live in `.deploy/secrets` (directory 0700, private files 0600); evidence lives in `.evidence`. Both are ignored by git and excluded from image builds. The restart probe uses a temporary 0600 synthetic checkpoint under `.deploy/verification` and deletes it after checking; it never writes credentials into evidence. Bootstrap preserves existing files and refuses partially missing key sets. Recover the missing originals; do not regenerate a root key for existing ciphertext. `init-backups` and `init-monitor` are explicit independent bootstrap steps so adding operator facilities never rotates existing keys.

The app runs with the invoking user's numeric UID, dropped capabilities and a read-only root filesystem. File ownership must match that UID. Run the workflow as an ordinary user with Docker access. Docker group membership grants host administration; only trusted operators should receive it.

## GCP: Terraform, image, VM preparation

Required on your workstation: Docker, Google Cloud CLI, billing-enabled GCP project, and an account authorized to create the listed resources/IAM grants. The Terraform wrapper uses a native Terraform installation if present, otherwise the pinned Terraform container. Authenticate application-default credentials for the provider; no service-account key is generated.

```sh
gcloud auth login
gcloud auth application-default login
cp infra/gcp/vm/terraform.tfvars.example infra/gcp/vm/terraform.tfvars
# Edit project_id and the globally unique backup bucket name.
make gcp-init
make gcp-validate
make gcp-plan          # inspect resource changes and costs in the saved plan
make gcp-apply         # explicitly apply that reviewed plan; creates billable resources
make gcp-publish       # build linux/amd64, push to Artifact Registry, record immutable digest
export TOOLBOX_ORIGIN=https://toolbox.example.com
make gcp-prepare       # transfer deployment files over IAP; initialize VM storage and KMS
```

Terraform creates a dedicated network/subnet, IAP-only SSH rule, OS Login VM with Shielded VM settings, protected persistent data disk, software KMS key, Artifact Registry and private backup bucket. The VM service identity receives encrypt/decrypt on exactly this key, repository read access and backup object creation. It cannot administer KMS or destroy backups. VM administrators are inside the trust boundary: they can read host files and use the instance identity, as can authorized workloads accessing metadata.

The default is a single `e2-small` VM and a 30 GB standard data disk. This is a small pilot with a single failure domain, not HA. RAM, disk, backup growth and restore time must be measured before sizing production. External IPv4 is enabled for outbound package/image access and has a separate charge; ingress remains limited to IAP SSH. Set `external_ip=false` only with an existing egress path. Inspect current [VM](https://cloud.google.com/compute/all-pricing), [KMS](https://cloud.google.com/kms/pricing), registry, disk and storage prices before applying; this is not a claim of the universally cheapest configuration.

Grant operators `roles/iap.tunnelResourceAccessor` and appropriate OS Login/admin permissions through your organization's access policy. They also need `iam.serviceAccounts.actAs` as required by Compute Engine access. Terraform does not grant arbitrary users project-wide access. Use a protected, shared Terraform backend for multiple operators; local pilot state and plan files are ignored by git. Never put secret payloads into tfvars, metadata or state.

`gcp-prepare` obtains a short-lived registry token from VM metadata over SSH and passes it to Docker through stdin. The host startup script verifies the data mount before starting Docker, and a systemd dependency enforces the same ordering on reboot. Operator traversal is allowed into its own protected release directory. It installs Docker/Compose and mounts the new data disk. Wait for that startup to finish before preparing a new VM; inspect its non-secret installation status if packages are still installing. Without outbound networking, provision package/image access first. The release and PostgreSQL bind volume live under `/var/lib/toolbox`, on the attached data disk. The script never automatically formats a recognized filesystem or deletes production disks.

After the separate authentication and provider work passes review, `make gcp-deploy` uses the same preparation and strict production preflight before starting the image. **Today that target stops at the release gate.** Public TLS/domain routing is not provisioned, and no HTTP firewall ingress is opened. Add a reviewed TLS ingress when serving is implemented; keep the fixture profile disabled on the VM.

Other VM providers can run the same Compose stack with protected files, verified PostgreSQL TLS and an equivalent `KeyWrapper` implementation. Production currently supports GCP KMS; another production KMS needs an adapter. Local-key mode is intentionally rejected in production. Docker portability does not itself add other cloud key providers.

## Key handling and updates

The API mounts its DSN, CA, deployment ID, signing ring and pepper ring individually. Cleanup has a separate DSN and no signing/pepper mounts. Retention can destroy eligible history but cannot change connection pointers or overwrite versions. Monitoring has its own read-only metadata role and no key material. Bootstrap/admin and migration files never enter API mounts. The non-superuser migration role owns the two schemas; runtime roles own none. Actual PostgreSQL tests reject DDL, audit mutation, grant deletion, trigger disabling and runtime history deletion.

Production uses ADC from the VM identity and a full KMS key resource name. There is no plaintext fallback. Every generation gets a random data key; AES-GCM authenticates deployment, schema, path and version. KMS integrity checks validate CRC32C and key identity. Encrypted records occupy a separate schema outside the application snapshot. A database-only compromise or copied database backup lacks the KMS wrapping key; an authorized compromised application can still request decryptions.

Readiness authenticates a persisted sentinel, so changing/losing a local root key fails startup. Successful sentinel decryption is cached for five minutes to bound KMS probe calls; primary SQL is checked on every probe. Actual credential reads always authenticate/decrypt independently. Keep all KMS versions needed by retained ciphertext and backups; changing the primary version does not rewrap old records automatically.

For signing rotation, publish retained public verification keys before changing the active Ed25519 key and retain them through delegation expiry. Pepper rotation retains old keys through session expiry; authenticated agent credentials migrate to the active pepper. Key removal fails closed. Compromise requires explicit revocation/reissue, not just rehashing stored hashes.

Updates and rollback require `TOOLBOX_IMAGE=registry/image@sha256:...` and `make deploy-update` or `make deploy-rollback`. Review migration compatibility before switching an older image. These commands never downgrade schema or roll credential generations backward. Back up and rehearse restoration before migration. The initial GCP publication tags a git revision and records its immutable registry digest in `.deploy/release-image`.

## Operations

See [backup and recovery](recovery-docker.md) for the restore procedure and key custody. Run cleanup every minute, retention daily, backup every 15 minutes, and monitoring every minute under a trusted operator account. Use explicit environment configuration for production (`TOOLBOX_ENV=production`, immutable `TOOLBOX_IMAGE`, `TOOLBOX_KMS_KEY`, `TOOLBOX_ORIGIN`); these values are resource references, not credentials. Schedule absolute paths, and route nonzero exits to your alert receiver. Production cleanup remains blocked until live provider validation is complete.

Cleanup reports processed/succeeded/failed/pending counts and oldest age; retry state is durable with bounded exponential backoff and jitter. Its lease survives worker crashes. Retention scans at most 100 paths with a persisted cursor, keeps current credentials and connection fences, and retains everything for unresolved issuance. Defaults: seven-day resolved credential history, one-hour OAuth grace after expiry. Orphan OAuth paths are retained for operator reconciliation.

Monitoring exits nonzero for a backup older than one hour, cleanup report older than 15 minutes, retention report older than 48 hours, aged pending cleanup, a failed job marker, or filesystem utilization of 90% or greater. It emits numeric JSON without user, token or document labels. No monitoring port is published. Your scheduler must alert on an absent monitor run as well as its nonzero result; a monitor on the VM cannot report total VM loss by itself. Use an external scheduler/uptime receiver for that failure mode.

Locally verified: real PostgreSQL encryption/CAS, runtime permission negatives, key rotation, cleanup/retention, browser flows, restart and isolated dump restore. Cloud apply, actual KMS/IAM, registry publication, public TLS, real OIDC/Google, off-host transfer and alert delivery require environment checks; do not report those as local passes.
