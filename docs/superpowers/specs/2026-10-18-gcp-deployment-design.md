# Portable Docker deployment preparation

Status: approved direction on 2026-10-18. The user's final decision is Docker on a VM, GCP KMS by default in production, and a real local encryption substitute for local verification. This supersedes the intermediate OpenBao-default proposal. Keep the existing document paths so PR references remain stable.

## Intended outcome

Run the same application image, PostgreSQL services locally and on a VM, with repeatable unit, race, integration, browser, restart, permission, and recovery checks. Docker Compose is the deployment interface; GCP Terraform is an optional VM provisioning adapter. Other VM providers can use the same Compose files. Update existing PR #4.

The service still needs production owner OIDC and live Google verification. Preparation must not expose fixture login publicly or claim those gates are complete. Production serve remains blocked until implemented authentication is available. Infrastructure, encrypted storage, maintenance, and local verification can be prepared independently.

## Architecture and scope

Use PostgreSQL 17 for metadata and a separate encrypted credential schema. Each credential generation and OAuth verifier receives a random AES-256-GCM data key. GCP KMS wraps that key in production; a persistent local AES-GCM root key provides the same interface in explicit local fixture mode. Deployment, schema, logical path, and version are authenticated context. Secret plaintext never enters the application state snapshot or logs. Preserve CAS, durable intents, connection locks and uncertain-outcome fencing. OpenBao remains an existing regression fixture only.

The same Docker image runs on a VM or locally. PostgreSQL uses a durable volume, verified TLS and separate migration, API, cleanup and retention identities. Static signing keys and pepper rings are generated once into protected files. Containers mount individual files and run with bounded privileges; database ports are private. Production never creates replacement keys or falls back to local encryption.

Local verification uses synthetic identity and Google, a trusted local CA, real PostgreSQL and real envelope encryption. An explicit container fixture flag allows a container listener with a loopback external origin. Publish the app only on host loopback; browser checks share its network namespace. Keep the original disposable developer Compose stack.

KMS protects the wrapping key from extraction from the database, disk backups and application configuration. A compromised authorized running workload can still request decryption; IAM and application authorization remain necessary. Static signing/pepper files require separate protected recovery storage. Never put secrets in Terraform state or VM metadata. Live KMS IAM/availability checks are external verification, not local passes.

## Database decision

Decision on 2026-10-18: keep PostgreSQL for this deployment. Spanner was considered as an alternative. The deciding factors are compatibility with Toolbox's security controls, the inexpensive pilot, and the absence of an established need for distributed database scaling.

The existing adapter uses PostgreSQL advisory locks to coordinate transactions and provider credential operations. Database triggers enforce append-only audit history, immutable grants and approvals, and monotonic connection epochs. These controls and their regression tests are already part of the implementation. Spanner's PostgreSQL interface is a subset of PostgreSQL; it does not support triggers or transactional DDL. Switching would require a new adapter and a reviewed replacement for the current locking, migration, and database enforcement mechanisms. It would not be a connection-string change. See the [current storage guarantees](../../storage.md), [PostgreSQL adapter](../../../internal/store/postgres.go), [database protections](../../../internal/store/migrations/001_initial.sql), and [Spanner compatibility limits](https://docs.cloud.google.com/spanner/docs/reference/postgresql/overview).

The selected VM deployment runs PostgreSQL in Docker; its compute and storage are part of the VM bill. The following managed-service comparison records why Spanner was not chosen. PostgreSQL also provides the lower managed-service entry price for a private pilot. The following compute estimates use published on-demand rates checked on 2026-10-18, `us-central1`, 730 hours per month, and no commitments or credits. Storage, backups, networking, and other services are additional. These configurations have different capacity and availability characteristics and are not performance equivalents.

| Configuration | Approximate monthly compute | Relevant tradeoff |
| --- | --- | --- |
| PostgreSQL `db-f1-micro`, single zone | $7.67 | Shared CPU and about 0.6 GiB RAM; private pilot only, with no Cloud SQL SLA |
| PostgreSQL Enterprise, 1 vCPU and 3.75 GiB RAM, single zone | $49.31 | Dedicated capacity without regional HA |
| Same PostgreSQL Enterprise configuration with regional HA | $98.62 | Standby capacity and failover at a higher fixed cost |
| Spanner Standard, regional, 100 processing units | $65.70 | Distributed regional replication; requires adapting the application |

Spanner can be competitive with HA PostgreSQL, so cost alone does not rule it out. The compute estimates do not establish which database would be cheaper for a measured production workload. Check current [Cloud SQL pricing](https://cloud.google.com/sql/pricing?hl=en), [Spanner pricing](https://cloud.google.com/spanner/pricing), and [shared-core operating limits](https://docs.cloud.google.com/sql/docs/postgres/instance-settings) when sizing an environment.

Toolbox's immediate storage scaling limit is its full-state snapshot and database-wide transaction lock. Replace that adapter with scoped, indexed queries and explicit transactions before expecting higher throughput. Moving the same access pattern to Spanner would not by itself solve that application bottleneck. Standard PostgreSQL also preserves the option to use other PostgreSQL hosting providers. KMS encryption and least-privilege access remain necessary parts of the selected design; the database choice alone does not establish stronger credential protection.

Revisit Spanner if a concrete requirement calls for multi-region availability or horizontal write scaling, or if measured total cost favors it enough to justify the migration. Such a change requires its own storage design, equivalent authorization and audit protections, and tests for fresh revocation reads, transaction retries, credential CAS, provider-operation fencing, and recovery. Preserve the current security guarantees rather than dropping unsupported protections during migration.

## Keys and secrets

Persist a signing key ring with one active Ed25519 private key and retained public verification keys. Keep issuer and key IDs stable across restarts. During rotation, distribute verification keys before switching signing and retain overlap for the maximum delegation token lifetime. Startup never generates replacement production keys.

Persist a pepper ring. Credentials and browser sessions record the pepper ID used. Successful agent authentication upgrades legacy credential hashes to the active pepper; CSRF derivation uses the session's original pepper until expiry. Missing or retired keys deny authentication. Never store plaintext agent credentials. Emergency compromise requires revocation and reissue, not rehashing stored hashes alone.

Encrypted generations are append-only for API and cleanup roles. An atomic current-version pointer provides CAS and retained creation fences. Wrapping occurs before the short SQL write transaction; reads use the primary and authenticate the complete context. KMS outages deny access without plaintext fallback. Production uses application default credentials and a key-scoped encrypter/decrypter grant; no service-account JSON key is required.

## Storage permissions and migrations

Migrations run explicitly with a schema owner, not during production API startup. The runtime owns no schemas, tables, triggers or functions and has no DDL, replication, role-management, or trigger-disable privileges. Preserve immutable grant and approval rules and append-only audit permissions. Revoke public schema creation. Test forbidden operations with actual restricted PostgreSQL roles.

Use verified TLS for production PostgreSQL connections and a deployment-specific trusted CA. Local verification uses the same verification paths. File secrets must be protected on the host and mounted individually; do not mount operator or migration credentials into the API. No plaintext DSNs, tokens or private keys in logs, CLI arguments, images, or Terraform.

## Cleanup and retention

Disconnect blocks access and advances its epoch immediately. Provider revocation runs from a durable outbox using bounded retries and jitter. Record creation/attempt/due times, retry count, and a fixed error class. Report backlog age and failed jobs instead of silently swallowing errors. Cancellation, overlapping maintenance runs, and uncertain refresh or exchange outcomes retain cleanup material.

A separately permissioned retention command inspects current application state and encrypted SQL history. Destroy old encrypted versions only after safe lifecycle checks and a grace period. Keep current versions, tombstones/creation fences, active cleanup credentials, and all material associated with unresolved issuance. Unknown state means retain and alert. Clear consumed or expired OAuth verifiers only after dependent work is resolved. Defaults are one hour of OAuth safety grace and seven days for eligible retired credential history. Bound each run and test races against real stores.

Audit history remains append-only for runtime identities. Archival and any later approved purge use a separate procedure; do not weaken triggers or add an unrestricted purge API.

## Backups and recovery

Create protected PostgreSQL dumps with manifests containing image digests, schema checksums, times, and key references. A PostgreSQL dump cannot provide PITR; describe the actual dump schedule's loss window. For a 15-minute loss target, schedule at least every 15 minutes and measure completion and off-host upload. Production PITR requires an additional verified WAL/base-backup system. A consistent SQL dump includes encrypted credentials, but cannot be atomic with external Google provider state.

Store backups outside runtime access, encrypted at rest, and copy them off the VM. Retain static key recovery material and required local root keys or KMS versions for every retained backup. Never assume a VM disk snapshot replaces store-level backup verification. Keep operator recovery material separately from runtime volumes. Do not delete production volumes automatically.

Restore into isolated containers with dispatch disabled. Reconcile provider generations and cleanup obligations. If revocations after a backup cannot be proved complete, expire sessions, revoke credentials and grants, advance affected epochs, block connections, and require new approvals and reconnection. Keep OAuth/session references intact. Test this invalidation against a snapshot predating revocation; signing-key rotation alone is insufficient.

## Monitoring and operations

Use separate liveness and readiness checks. Readiness verifies primary SQL, an authenticated encrypted-store round trip, usable KMS credentials, and required key configuration; a missing mount is not healthy. Emit sanitized numeric cleanup, retention, and dependency reports. Include a portable monitoring profile and alerts for unhealthy services, HTTP failures, aged cleanup, failed jobs, disk pressure, and stale backups. Never include cookies, callback query strings, token payloads, document contents, DSNs or private paths as metric labels.

A VM operator wrapper supports bootstrap, preflight, up, test, status, backup, restore drill, update and rollback. Use immutable application image digests for deployed releases. Do not automatically reverse migrations or credential generations during rollback. Optional GCP Terraform provisions only a hardened VM, durable disks, limited network access, restricted service identity and protected backup storage; it does not upload secrets or make fixture services public.

Local verification runs in containers, including Go race/integration tests, browser approval and delayed-review cases, permission negatives, restart persistence, and a synthetic backup/restore drill. Record evidence and failed cases. Cloud KMS, public TLS/domain setup, live OIDC/Google, off-host backup delivery, and GCP provisioning remain explicit external checks rather than being represented as local passes.

## Reference documentation

- [GCP KMS envelope encryption](https://docs.cloud.google.com/kms/docs/envelope-encryption)
- [KMS integrity verification](https://docs.cloud.google.com/kms/docs/data-integrity-guidelines)
- [KMS pricing](https://cloud.google.com/kms/pricing)
