# Portable Docker Deployment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans inline, task by task. Preserve completed Task 1; the user's Docker VM decision supersedes the earlier managed-service tasks.

**Goal:** Ship a portable container deployment and full local verification loop with persistent keys, PostgreSQL, encrypted credential storage, permissions, maintenance, backup and recovery.

**Architecture:** The same Docker application image runs locally and on a VM. PostgreSQL stores authorization metadata and separately encrypted credential generations with atomic CAS. GCP KMS is the default production key wrapper; an explicit persistent local AES-GCM wrapper supports container verification. Terraform is an optional GCP VM adapter.

**Spec:** [Approved portable Docker design](../specs/2026-10-18-gcp-deployment-design.md).

**Database decision:** [PostgreSQL over Spanner](../specs/2026-10-18-gcp-deployment-design.md#database-decision): preserve existing security controls and prioritize scoped queries over changing engines.

## Global Constraints

- Never generate replacement production signing keys or peppers during startup.
- Keep plaintext provider tokens and OAuth verifiers out of application snapshots and logs; only ciphertext enters the credential schema.
- Preserve all CAS, epoch, immutable grant, audit, and uncertain-outcome guarantees.
- Production owner OIDC and live Google validation remain independent release gates; no boolean can bypass missing authentication code.
- Production connections verify TLS; fixtures are explicit and local-only.
- Local root encryption keys are forbidden in production; database migration credentials never enter API mounts.
- New migrations only; preserve migration 001 unchanged.
- Preserve package-lock.json and update existing PR #4. No live deployment or provisioning.

## Review Focus

1. Pepper rotation must preserve existing browser CSRF and credential validity; Task 1.
2. An unavailable key wrapper or tampered ciphertext must fail readiness; Task 2.
3. Runtime identities must be unable to bypass immutable audit/grant protections or destroy secret history; Tasks 2 and 3.
4. Cleanup and retention overlap must retain uncertain provider material; Tasks 4 and 5.
5. Restoring an older snapshot must not resurrect authority; Task 9.

### Task 1: Persist signing keys and version credential and session peppers

**Files:** Create `internal/security/keyring.go` and `internal/security/keyring_test.go`; modify `internal/security/security.go`, `internal/domain/domain.go`, `internal/server/server.go`, `internal/server/owner.go`, and `internal/store/validate.go`; create `internal/store/migrations/002_key_versions.sql`; add server and storage regression tests.

**Interfaces:** Preserve `NewSigner(issuer, keyID string, key ed25519.PrivateKey) (*Signer, error)`. Add `NewKeyRingSigner(issuer string, config SigningKeyRing) (*Signer, error)` and `NewPepperRing(config PepperConfig) (*PepperRing, error)`, with explicit active IDs and versioned key maps. Add `PepperID string` to `domain.Credential` and `domain.Session`; use an explicit `legacy` mapping for existing fixture records. `server.Config` accepts a pepper ring while preserving the existing fixture `Pepper` entry point.

- [ ] Write `TestSigningRingRotation`, `TestCredentialPepperRotation`, and `TestSessionCSRFUsesOriginalPepper`: old delegation tokens verify during the rotation overlap; successful credential authentication upgrades its hash and version; existing session CSRF remains valid after changing the active pepper.
- [ ] Run `go test ./internal/security ./internal/server ./internal/store` and confirm the new cases fail for the missing behavior.
- [ ] Implement strict key parsing, copied key material, duplicate/unknown key rejection, and versioned authentication. New fixture sessions and credentials receive their pepper ID. Migrate stored legacy payloads and JSON field constraints without changing the first migration.
- [ ] Run the same tests and the existing expiry tests. Verify unknown key IDs, removed peppers, malformed keys, and missing key files fail closed. Test migration upgrade from the original schema with actual PostgreSQL.
- [ ] Review and commit this task alone, preserving unrelated files.

### Task 2: Encrypt PostgreSQL credential generations with KMS and local providers

**Files:** `internal/secretstore`, official GCP KMS client dependencies, application integration tests.

**Interfaces:** Inject `KeyWrapper.Wrap/Unwrap(ctx, data, aad)` into an Envelope; implement GCP KMS with CRC32C integrity checks and local AES-GCM. `PostgresConfig` carries pool, credential schema, envelope. Preserve tokens.SecretStore and JSONStore contracts.

- [ ] Write failing envelope, RPC boundary, CAS and actual PostgreSQL tests.
- [ ] Encrypt every generation with a random data key and authenticated deployment/schema/path/version context; redact dependency errors.
- [ ] Use separate checksummed credential migrations; atomic history/pointer writes and permanent hidden creation fences. No KMS call inside SQL transactions.
- [ ] Verify tampering, context transplant, cancellation, concurrent CAS and full API flow; commit. Live KMS remains an opt-in external check.

### Task 3: Separate migrations and enforce PostgreSQL roles

**Files:** `internal/store/permissions.go`, role and migration tests, `deploy/postgres` bootstrap configuration.

**Interfaces:** Expose safe idempotent role setup using validated identifiers. Keep existing `OpenPostgres` and explicit `Migrate` APIs. Provide independent API, cleanup, retention and migration DSN files.

- [ ] Write and run failing permission tests using actual PostgreSQL roles: no runtime DDL, table ownership, audit updates/deletion/truncate, grant deletion, or role management.
- [ ] Implement dedicated schema grants and revoke public schema creation. Migration role owns objects; runtime roles receive only the required table privileges.
- [ ] Configure verified PostgreSQL TLS and protected password files. Do not publish database ports in the VM stack.
- [ ] Verify fresh bootstrap and migration 001 upgrade, including trigger protections under restricted runtime roles; commit.

### Task 4: Make cleanup durable, bounded and observable

**Files:** `internal/server/cleanup.go`, tests, domain/validator updates and `003_cleanup_retries.sql`.

**Interfaces:** Preserve `CleanupOnce(context.Context) error`; add `RunCleanup(context.Context) (CleanupReport, error)` with processed/succeeded/failed/pending/oldest age. Add retry metadata to `domain.Cleanup`.

- [ ] Write and run failures for transient revocation, due-time scheduling, cancellation, restart, overlapping runs and unresolved refresh or exchange.
- [ ] Implement at most 100 due jobs per run, five-second to one-hour exponential retry with jitter, timestamps, and fixed error classes. Failed cleanup retains blocked access and credentials.
- [ ] Run all token/OAuth races and real-store tests; commit.

### Task 5: Implement separately permissioned encrypted history retention

**Files:** `internal/secretstore/retention.go` and tests, retention command wiring and SQL retention privileges.

**Interfaces:** `RunRetention(ctx context.Context, repo domain.Repository, store RetentionStore, policy RetentionPolicy) (RetentionReport, error)`. Report scanned/deleted/blocked counts; defaults one-hour OAuth grace and seven-day eligible history grace.

- [ ] Write and run failures for active, pending, unknown and complete connection states, consumed/expired OAuth transactions, grace periods, tombstones and cleanup overlap.
- [ ] Read authoritative primary state, use connection locks, inspect current encrypted version and history, and destroy only provably retired versions. Preserve current data, creation fences and unresolved operation material. Bound the batch and fail closed on metadata/read errors.
- [ ] Verify API/cleanup roles cannot destroy history while retention role can destroy only approved paths; test actual retained-version destruction and retry; commit.

### Task 6: Add configuration, maintenance commands and container build

**Files:** `internal/runtimecfg`, `internal/bootstrap`, `cmd/toolbox` command dispatch, `Dockerfile`, `.dockerignore` and command tests.

**Interfaces:** `fixture`, `init`, `preflight`, `migrate`, `cleanup`, `retention`, `healthcheck`, `serve`, `recover-invalidate`. Preserve old fixture invocation. `runtimecfg.Load(lookup)` and command-specific validation separate fixture and maintenance needs. Bootstrap creates protected file secrets and a deployment CA once without overwriting existing keys.

- [ ] Write and run failures for malformed/missing key files, unsafe origins and fixture listeners, unverified TLS, non-root workload checks, unsupported owner authentication, and idempotent bootstrap.
- [ ] Implement persistent key loading, explicit container fixture opt-in with a loopback external origin, non-root runtime, safe shutdown and command-specific mounts. Production serve fails for the unfinished owner authenticator.
- [ ] Build a minimal container with CA certificates. Keep credentials, evidence and git metadata outside build context. Run startup, health and shutdown checks; commit.

### Task 7: Build the durable Compose stack and optional GCP VM adapter

**Files:** `deploy/compose.yaml`, local verification overrides, PostgreSQL TLS and role configuration, optional `infra/gcp/vm`, monitoring profile and tests.

**Interfaces:** Persistent PostgreSQL volume; app-only host loopback publishing for local fixture verification; individual secret file mounts; separate maintenance services; no published database ports. VM runtime uses production mode and stays gated.

- [ ] Add runnable configuration checks for required files, role mounts, persistence and network isolation. Test the actual image and connections, not source-text matching.
- [ ] Provision containers with restricted capabilities, non-root app, read-only configuration, TLS, resource limits, healthchecks and bounded logs. Use explicit migrations and separately held recovery material.
- [ ] Add optional GCP VM Terraform with OS Login/IAP administration, no broad SSH ingress, durable disks protected from deletion, and a restricted backup identity. Do not place secret values in Terraform metadata/state or enable a public fixture route.
- [ ] Run Compose config/build/up tests, restart persistence, Terraform format/validate and no-apply checks; commit.

### Task 8: Provide the local verification and VM operator workflow

**Files:** `scripts/deploy`, verification helpers, Makefile/CI updates, `docs/deployment-docker.md`.

**Interfaces:** `init|up|preflight|test|status|backup|restore-drill|update|rollback`; Docker and Compose are the local runtime prerequisites. Evidence goes into an ignored directory; production image references are immutable digests.

- [ ] Write and run workflow tests for missing prerequisites, repeated initialization, failed migration, release gates, protected recovery output, invalid arguments, and rollback incompatibility.
- [ ] Implement idempotent startup and verified role bootstrap, with no secret CLI arguments or shell tracing. Start jobs only after schema and store checks pass.
- [ ] Containerize the Go race/integration suite and existing Chromium E2E and delayed-review cases. Share the app's network namespace for loopback browser checks; retain redacted evidence and propagate failures.
- [ ] Run the entire local loop twice, including restart persistence, and document VM transfer, TLS, secret handling and off-host backups; commit.

### Task 9: Verify backup, monitoring and recovery fencing

**Files:** `internal/recovery`, tests, backup/restore helpers, monitoring/alert configuration, `docs/recovery-docker.md`, storage/handoff/status updates.

**Interfaces:** `recovery.Invalidate(ctx context.Context, repo domain.Repository) (Report,error)` expires sessions, revokes credentials and grants, advances connection epochs once, queues cleanup and appends audit while preserving OAuth references. Maintenance reports drive job/backlog and backup-age monitoring.

- [ ] Write and observe failure for a restored snapshot predating revocation; implement idempotent invalidation so old sessions, credentials and delegation tokens cannot release content.
- [ ] Back up PostgreSQL with pg_dump to protected files, coordinate quiescence, and include a reference-only manifest. Restore only into isolated volumes, never overwrite live stores automatically. Label dump schedule limits accurately; no untested PITR claims.
- [ ] Add portable health/backlog/stale-backup monitoring and a synthetic restore drill against the actual database. Keep key recovery material separate, backups encrypted and off-host delivery explicit.
- [ ] Run all Go checks and real-store/browser/permission/restart/recovery verification, plus Compose and optional Terraform checks. Distinguish unrun cloud/live-provider checks.
- [ ] Dispatch one independent whole-change security/correctness reviewer, fix important findings with regression tests, update PR #4 and report remaining production gates. Do not merge or deploy.

## Execution record

The user approved inline implementation and selected Docker on a VM, then explicitly corrected encryption to production GCP KMS by default with a real local substitute. This supersedes the intermediate OpenBao choice. No further scope approval is needed. Task 1 is committed as `0d91122` and verified with the full real-store race suite. Resume subsequent tasks from the plan's execution ledger; do not redo completed work. Preserve the existing PR and unrelated package-lock.json.


Implementation completed on 2026-10-18. See [verification evidence and remaining environment checks](../../deployment-verification.md), [operator commands](../../deployment-docker.md), and [recovery](../../recovery-docker.md). The implementation and independent review supersede the original unchecked planning checklist. Production serving remains gated; cloud apply and live provider checks are intentionally unrun.
