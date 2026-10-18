# GCP deployment preparation

Status: approved direction on 2026-10-18, including the KMS storage revision and a low-cost pilot profile. Implementation planning follows this design.

## Intended outcome

Make Toolbox straightforward to provision and update on GCP with Terraform, persistent credentials, restricted storage access, scheduled cleanup, backups, monitoring, and a tested recovery procedure. Prefer managed services and avoid a separately operated OpenBao cluster. The operator supplies a GCP project with billing, a region, identity configuration, and Google OAuth credentials. Application credentials and secret values must not enter Terraform configuration, plans, state, logs, or build artifacts.

Deployment preparation does not establish that the unfinished owner OIDC integration or live Google OAuth and Picker release gates have passed. Production deployment must refuse to expose the fixture application. Infrastructure provisioning and image building can proceed independently of those gates; opening production traffic cannot.

## Current application constraints

- `cmd/toolbox/main.go` supports only fixture mode, binds loopback, generates a fresh Ed25519 key and credential pepper on every start, and runs migrations using its application database connection.
- `compose.yaml` supplies temporary PostgreSQL storage and development OpenBao with a fixture root token. It remains a local development stack.
- The existing secret-store interfaces require compare-and-set writes. Refresh and cleanup depend on durable intent, generation checks, and uncertain-outcome reconciliation.
- The application snapshot contains authorization metadata and secret references, never provider credentials, OAuth verifiers, or document contents. The new GCP credential adapter stores only KMS-encrypted payloads in a separately permissioned PostgreSQL schema outside that snapshot. The current snapshot adapter serializes application transactions and is suitable only for a small, bounded workload.
- Health and readiness endpoints exist. Cleanup has a durable outbox but lacks retry scheduling, attempt timestamps, and operational metrics. Historical OpenBao version destruction and audit retention are not implemented.

## Deployment approaches

| Approach | Benefit | Cost or limitation |
| --- | --- | --- |
| Cloud Run, Cloud SQL, Cloud KMS, and Secret Manager for static secrets | Fully managed GCP runtime and storage; encrypted credential CAS is a PostgreSQL transaction | Requires an encrypted secret adapter and concurrency, retention, and recovery verification |
| Cloud Run and Cloud SQL with an existing managed KV-v2 endpoint | Smallest change to provider credential storage | Requires a separately provisioned compatible service, workload authentication, and its backup and retention procedures |
| Compute Engine running the existing dependencies with durable disks | Closest to the development stack | Leaves database and OpenBao patching, availability, unsealing, and backups to the operator |

Choose the first approach. Preserve OpenBao and fixture adapters for existing development and regression coverage.

Secret Manager remains appropriate for static configuration secrets. Do not create a Secret Manager version for each provider refresh: retained enabled and disabled versions are billable. KMS protects the encryption keys for credential records without requiring a new KMS key version per refresh.

## Managed resources

Terraform provisions Artifact Registry, Cloud Run, Cloud SQL for PostgreSQL, a software-backed symmetric Cloud KMS key, Secret Manager containers for static secrets, dedicated service accounts and IAM, Cloud Scheduler, Cloud Monitoring policies, and Cloud Storage for Terraform state and protected recovery artifacts. Use separate GCP projects and state prefixes for staging and production.

Provide explicit `pilot` and `production` profiles. The pilot uses request-based Cloud Run billing with zero minimum instances and one maximum instance, and a single-zone `db-f1-micro` database with 10 GB SSD. This shared-core tier has no Cloud SQL SLA and is for testing and a private pilot. The production profile uses Cloud SQL Enterprise with at least one dedicated vCPU and 3.75 GiB RAM, with regional high availability configurable and enabled by default. Both profiles retain IAM restrictions, private database connectivity, encryption, backups, and deletion protection. Specify Enterprise explicitly to avoid a higher-priced default edition. Use Direct VPC egress for private database access, avoiding a permanently provisioned Serverless VPC Access connector. Configure budget notifications without representing them as a spending cap.

Use a private Cloud SQL connection and the Cloud SQL Go connector with IAM database authentication. Configure separate database identities for the API, migrations, cleanup, and recovery administration. The connector integration must cover both pooled transactions and the dedicated physical connections used by advisory locks. Never preserve a plaintext database transport as a shortcut around connector integration.

Start with one API instance and bounded concurrency to match the existing database adapter. Additional instances are not a storage scaling solution. Use a dedicated migration job and scheduled cleanup and retention jobs; correctness must not depend on an in-process ticker running between Cloud Run requests. Scheduler invokes jobs with its service account and OAuth authentication to the Google Run API.

The production service has HTTPS, an explicit external origin, secure cookies, configured owner identity, and no fixture routes. During preparation it remains private and unavailable to general traffic. Cloud Run IAM authentication during preparation does not replace the application's human and agent authentication.

## Persistent signing and credential secrets

Create independent Secret Manager containers for the signing key ring, credential pepper ring, Google OAuth client secret, and owner OIDC client secret when the selected provider requires one. Terraform manages containers and access policies. An idempotent bootstrap command generates initial signing and pepper material once and inserts values through the Secret Manager API. Existing values are reused. Application releases pin numeric versions.

The application loads the signing key ring and pepper ring at startup, validates their format, and fails closed if required material is unavailable. Production startup never generates replacements. Keep a stable issuer and key IDs across restarts and revisions.

Extend delegation verification to accept the active signing key and explicitly retained verification keys by `kid`. Switch signing only after the new verification key has been distributed to all serving revisions. Retain previous public keys for at least the maximum token lifetime and rollout overlap; compromised keys are removed immediately with the corresponding access interruption.

Add a pepper version identifier to credential metadata through a new migration and the domain validator. New credentials use the active pepper. Existing credentials are verified with their recorded version and can be rehashed after successful authentication using the supplied plaintext credential. Old peppers remain available until affected credentials have expired or been replaced. Emergency pepper compromise requires revocation and reissue; stored hashes cannot be rehashed without the credential.

Browser sessions also record the pepper version used to derive their CSRF token. Session responses and CSRF verification continue to use that version until the session expires or is deliberately invalidated. Changing the active credential pepper alone must not break a valid existing session.

No plaintext agent credential is persisted. Provider tokens and temporary OAuth secrets continue to live only in the credential store.

## KMS credential store and atomic version checks

Implement the existing `tokens.SecretStore` and `tokens.JSONStore` interfaces with a separate PostgreSQL credential schema. The main application snapshot and its tables continue to contain no credential ciphertext or plaintext. The credential schema contains current version metadata, encrypted versions, creation and retirement times, and a deletion fence. Neither SQL queries nor logs contain plaintext secrets.

Use envelope encryption: generate a fresh 256-bit data encryption key for each written version, encrypt the payload with standard AES-256-GCM, and wrap that key with Cloud KMS. Authenticate the deployment identity, logical path, envelope format, and record version as additional authenticated data. Store the ciphertext, nonce, wrapped key, and KMS key reference. Use the official KMS client, Application Default Credentials, bounded calls, and integrity checks. Never store plaintext data keys or cache decrypted provider tokens beyond their operation.

Wrap and encrypt before starting a short SQL transaction. Atomically insert the encrypted version and compare and advance its current pointer against the caller's expected version in that transaction. Concurrent writes have one committed winner; a failed CAS persists neither a candidate nor a new pointer. A lost commit response is uncertain and uses existing exact-operation reconciliation. Reads use the primary database and validate the complete authenticated envelope. JSON deletion hides the current pointer and retains the creation fence and encrypted history; a later create-only write cannot recreate that path.

KMS calls never run inside SQL transactions. Ciphertext rows are outside application snapshot synchronization. KMS failure denies secret access without plaintext fallback. Use a small explicitly bounded payload size compatible with existing provider response limits. Separate runtime writes from retirement deletion permissions; use new migrations instead of modifying an applied migration.

Before selecting this adapter in production, verify create-only behavior, concurrent CAS, lost responses, process interruption, hidden pointers, tampered and transplanted ciphertext, unavailable KMS, and the complete refresh/disconnect cleanup regressions. Run a small real-GCP KMS integration check in addition to simulated client tests. Keep production startup blocked if these semantics cannot be demonstrated.

## Access boundaries

Use dedicated application and credential schemas, revoke public schema creation, and ensure runtime identities own no schemas, tables, functions, or triggers. Migrations run separately with the schema owner. Preserve the exact runtime table permissions documented in `docs/storage.md`, including append-only audit access and immutable grant protections. The credential adapter receives the narrow extra rights for encrypted version inserts and current-pointer CAS.

Separate IAM capabilities for static-secret access, KMS encryption and decryption, migrations, deployment, and recovery. The API cannot destroy KMS key versions, static-secret versions, credential history, or backups, change IAM, disable audit protections, or run DDL. The retention job can purge eligible encrypted history through a deliberately narrow database interface after checking live references and lifecycle state. The cleanup job receives only the secrets and SQL permissions it needs; it does not receive the signing or pepper rings.

Use attached service accounts and workload identity federation for CI. Do not create downloadable service-account keys. Terraform state resides in a private bucket with versioning, controlled access, and public access prevention. Avoid secret-value resources and secret-value data sources so plaintext payloads never enter Terraform state.

## Secret cleanup and retention

Keep provider revocation and historical secret destruction as separate operations. On disconnect, deny access and advance the connection epoch immediately, then use durable cleanup to revoke credentials. Provider errors retain the revocation material for retry. An unresolved exchange or refresh is never considered complete merely because a timeout or retention deadline passed.

Add attempt count, creation time, next-attempt time, last-attempt time, and a sanitized error code to cleanup records using a new migration. Apply bounded exponential backoff with jitter. Retry jobs are idempotent and respect connection locks and CAS. Alert on aged pending operations and repeated failures rather than silently discarding them.

Purge consumed or expired OAuth verifier ciphertext after a documented safety grace period and resolution of dependent work. Purge retired provider ciphertext only after reconciling current references, pending operations, revocation obligations, and a recovery grace period. Keep active credentials and unresolved cleanup material regardless of their age. Preserve empty tombstones so purging history never re-enables create-only writes. Do not describe SQL deletion as cryptographic erasure of backups.

Set version retention and grace periods explicitly per environment. Stage with conservative values, measure job behavior, and document the accepted production values. Existing backups retain their historical contents until those backups expire; destroying a live secret version does not erase older recovery copies.

Audit retention needs a separately privileged, deliberate procedure because current triggers reject deletion and truncation. Preserve append-only runtime permissions. Archive and verify records before any approved purge, and define the retention period with the operator. Do not weaken audit triggers to make ordinary application cleanup succeed.

## Backups and recovery

Enable automated Cloud SQL backups and point-in-time recovery explicitly in Terraform; do not rely on console defaults. Set production database deletion protection at both the resource and provider levels. Retain a protected recovery copy outside the runtime identity's control and document its expiry. Protect Terraform state versions and preserve the image digest, configuration, and secret-version references for each release.

The SQL backup includes the credential schema's ciphertext and version metadata in the same database recovery timeline. Maintain an encrypted recovery copy of required static secrets and a manifest of their numeric Secret Manager versions, the deployed image digest, and required KMS key versions. Isolate recovery access from the runtime. Never destroy a KMS version while any retained database backup or encrypted recovery copy still depends on it. GCP KMS keys are not exportable; protect them with deletion restrictions and a tested key-availability and incident procedure rather than promising an exported private key backup. Test access and backup decryption before relying on recovery copies.

Start with a proposed maximum loss of 15 minutes of SQL metadata and a two-hour service recovery target, subject to measurement. End-to-end authorization and credential recovery has stricter consistency constraints than SQL PITR alone; exports and checkpoints do not make database and Google provider state atomically recoverable.

Restore into an isolated environment with provider dispatch disabled. Reconcile committed encrypted generations, available KMS key versions, revocation and cleanup records, and provider-generation state. A database rollback can erase revocations and recover an invalid or already rotated provider token. If post-checkpoint revocations cannot be proved complete, invalidate restored sessions and agent credentials, revoke affected grants, block affected connections, and require new credentials and user reconnection. Signing-key rotation alone does not prevent restored long-lived credentials from being used.

Reopen traffic only after reconciliation or deliberate invalidation, then run the authorization smoke checks. Cover database loss, missing secrets, provider uncertainty, application rollback, compromised credentials, and recovery-export decryption in the runbook. Run a restore drill before production release and on a recurring schedule.

## Monitoring

Retain liveness separately from readiness. Readiness checks primary SQL access, the configured secret store, required static-secret loading, and migration compatibility. It must distinguish a missing configured store from an intentionally missing secret. Expose metrics on a private surface or emit structured metrics without sensitive values.

Create dashboards and actionable alerts for API failures and latency, readiness failures, SQL connection and lock saturation, cleanup backlog and oldest age, uncertain provider operations, refresh and revocation failures, denied secret access, failed or missing job runs, stale backups, and failed restore drills. Include audit persistence failures, which must continue to deny content release.

Logs contain sanitized operation and request identifiers and error classes, never authorization headers, cookies, callback query strings, OAuth codes, raw state, token payloads, private keys, database DSNs, or document contents. Check Cloud Run request-log behavior for the OAuth callback and apply an exclusion or safe callback routing where necessary. Do not assume application redaction also redacts infrastructure logs.

## Operator workflow

Provide a documented wrapper with these stages:

1. `bootstrap`: check tools and permissions, initialize the protected Terraform state backend, and provision foundation resources. Remote-state bootstrap is an explicit idempotent first step.
2. `secrets`: initialize absent key material and import operator-supplied OAuth and OIDC secrets through stdin or protected local input. Never overwrite existing material implicitly.
3. `build`: build and push an immutable container image to Artifact Registry and record its digest.
4. `plan`: produce a reviewable Terraform plan for service and job changes with explicit image and numeric secret versions.
5. `deploy`: apply the selected plan, execute migrations with the migration identity, deploy a private revision, run preflight and smoke checks, and shift traffic only when release gates pass.
6. `status`, `rollback`, and `recover`: inspect readiness and jobs, return to a compatible image and configuration, or invoke the documented isolated recovery procedure. Application rollback never silently reverses database migrations or credential generations.

Terraform application remains an explicit operator action that creates billable resources. Repository preparation and local verification do not provision a project, upload live credentials, or deploy an application.

## Implementation boundaries and verification

Add `infra/gcp` for Terraform, `scripts/gcp` for the operator wrapper, a production container build, separate application commands for serve, migrate, cleanup, and retention, a KMS-encrypted PostgreSQL secret-store adapter, and deployment and recovery documentation. Add migrations instead of editing `001_initial.sql`. Preserve fixture startup and existing integration tests.

Implement in this order: persistent key configuration and migration separation; GCP credential adapter and lifecycle journal; least-privilege SQL and IAM; cleanup scheduling; container and Terraform workflow; monitoring and recovery tooling. Keep owner OIDC and live Google validation visible as prerequisites for production traffic rather than silently marking them complete.

Verify restart persistence and rolling key rotation; pepper version migration and credential replacement; forbidden SQL and IAM operations; real concurrent and uncertain secret writes; all existing provider cleanup races; scheduled retries and retirement exclusions; Terraform formatting and validation; container startup and shutdown; private deployment smoke checks; and a restore drill proving that revoked rights cannot reappear. State clearly which checks ran locally and which require a dedicated GCP project.

## Reference documentation

- [Cloud Run with Cloud SQL and Secret Manager through Terraform](https://cloud.google.com/run/docs/samples/cloudrun-connect-cloud-sql-parent-tag)
- [Cloud KMS envelope encryption](https://docs.cloud.google.com/kms/docs/envelope-encryption)
- [Cloud KMS pricing](https://cloud.google.com/kms/pricing)
- [Secret Manager pricing](https://cloud.google.com/secret-manager/pricing)
- [Cloud SQL shared-core limits](https://docs.cloud.google.com/sql/docs/postgres/instance-settings)
- [Secret Manager secret version Terraform resource and state behavior](https://registry.terraform.io/providers/hashicorp/google/8.6.0/docs/resources/secret_manager_secret_version)
- [Scheduled Cloud Run jobs](https://docs.cloud.google.com/run/docs/execute/jobs-on-schedule)
- [Cloud SQL restore and PITR defaults](https://docs.cloud.google.com/sql/docs/postgres/backup-recovery/restore)
