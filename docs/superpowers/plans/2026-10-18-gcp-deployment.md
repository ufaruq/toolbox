# GCP Deployment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prepare a reproducible GCP deployment with persistent keys, KMS-encrypted credentials, restricted storage identities, cleanup, backups, monitoring, and recovery commands.

**Architecture:** Deploy a Go container to Cloud Run with Cloud SQL PostgreSQL, static configuration in Secret Manager, and rotating credentials in an independently permissioned SQL schema protected by Cloud KMS envelope encryption. Terraform provisions the resources, and a small operator wrapper coordinates foundation setup, secret initialization, immutable builds, migrations, deployment checks, and recovery.

**Tech Stack:** Go 1.27.2, pgx v5, official Google Cloud KMS and Cloud SQL connector clients, PostgreSQL 17, Terraform with the HashiCorp Google provider, Cloud Run Jobs, Cloud Scheduler, Cloud Monitoring, Cloud Storage.

**Spec:** [Approved GCP deployment design](../specs/2026-10-18-gcp-deployment-design.md), including the KMS revision approved in conversation on 2026-10-18.

**Database decision:** Keep PostgreSQL for compatibility with existing authorization and audit protections and the low-cost pilot. See the [PostgreSQL and Spanner decision](../specs/2026-10-18-gcp-deployment-design.md#database-decision) for cost assumptions, migration tradeoffs, and conditions for reconsideration.

## Global Constraints

- Production startup never generates replacements for missing signing or pepper keys.
- Application credentials and secret values must not enter Terraform configuration, plans, state, logs, or build artifacts.
- KMS calls never run inside SQL transactions.
- The main application snapshot contains neither credential ciphertext nor plaintext.
- Provider errors retain revocation material for retry; unresolved exchanges and refreshes never become complete merely because a timeout or retention deadline passed.
- Add migrations instead of editing `001_initial.sql`.
- Preserve fixture startup, existing strict authorization checks, and existing integration tests.
- The pilot profile uses zero minimum Cloud Run instances, one maximum instance, single-zone `db-f1-micro`, and 10 GB SSD. It is a private pilot and has no Cloud SQL SLA.
- The production profile explicitly uses Cloud SQL Enterprise, at least one dedicated vCPU and 3.75 GiB RAM, with regional HA enabled by default and configurable.
- Both profiles use private SQL connectivity, IAM authentication, encryption, backups, and deletion protection. Budget alerts are notifications, not spending caps.
- Owner OIDC and real Google release gates remain separate unfinished work. Provisioning preparation must not imply a usable public production service. A readiness flag cannot substitute for an implemented owner authenticator.
- Do not apply Terraform, create billable resources, provision real OAuth clients, upload live credentials, or shift external traffic during repository implementation.

## Review Focus

1. Pepper rotation must preserve existing session CSRF behavior, including sessions created before the new fields existed; Task 1 tests this.
2. A ciphertext moved between paths, versions, deployments, or schemas must fail authenticated decryption; Task 2 tests this.
3. Connector refresh and closure must cover dedicated advisory-lock connections as well as the pool; Task 3 tests this.
4. Retry overlap and cancellation must never purge a credential needed for an uncertain provider operation; Tasks 4 and 5 test this.
5. An older restored database must never silently restore revoked authority; Task 9 tests deliberate invalidation and traffic fencing.

## Work Breakdown

The three milestones are runtime and storage foundations (Tasks 1–5), GCP deployment tooling (Tasks 6–8), and recovery verification (Task 9). Each task has a separate verification boundary. Implement inline in the current session only after plan review and the execution/workspace choice.

### Task 1: Persist signing keys and version credential and session peppers

**Files:** Create `internal/security/keyring.go` and `internal/security/keyring_test.go`; modify `internal/security/security.go`, `internal/domain/domain.go`, `internal/server/server.go`, `internal/server/owner.go`, and `internal/store/validate.go`; create `internal/store/migrations/002_key_versions.sql`; add server and storage regression tests.

**Interfaces:** Preserve `NewSigner(issuer, keyID string, key ed25519.PrivateKey) (*Signer, error)`. Add `NewKeyRingSigner(issuer string, config SigningKeyRing) (*Signer, error)` and `NewPepperRing(config PepperConfig) (*PepperRing, error)`, with explicit active IDs and versioned key maps. Add `PepperID string` to `domain.Credential` and `domain.Session`; use an explicit `legacy` mapping for existing fixture records. `server.Config` accepts a pepper ring while preserving the existing fixture `Pepper` entry point.

- [ ] Write `TestSigningRingRotation`, `TestCredentialPepperRotation`, and `TestSessionCSRFUsesOriginalPepper`: old delegation tokens verify during the rotation overlap; successful credential authentication upgrades its hash and version; existing session CSRF remains valid after changing the active pepper.
- [ ] Run `go test ./internal/security ./internal/server ./internal/store` and confirm the new cases fail for the missing behavior.
- [ ] Implement strict key parsing, copied key material, duplicate/unknown key rejection, and versioned authentication. New fixture sessions and credentials receive their pepper ID. Migrate stored legacy payloads and JSON field constraints without changing the first migration.
- [ ] Run the same tests and the existing expiry tests. Verify unknown key IDs, removed peppers, malformed keys, and missing key files fail closed. Test migration upgrade from the original schema with actual PostgreSQL.
- [ ] Review and commit this task alone, preserving unrelated files.

### Task 2: Implement envelope encryption and transactional credential storage

**Files:** Create `internal/secretstore/envelope.go`, `kms.go`, `postgres.go`, and corresponding tests; create `internal/store/migrations/003_encrypted_secrets.sql`; update `go.mod` and `go.sum` only for the official KMS client and its required dependencies.

**Interfaces:** Add `KeyWrapper` with `Wrap(context.Context, []byte, []byte) ([]byte, error)` and `Unwrap(context.Context, []byte, []byte) ([]byte, error)`; add `Envelope.Seal(ctx context.Context, path string, version int64, plaintext []byte) ([]byte, error)` and `Envelope.Open` with the same parameters and ciphertext input. `NewPostgres(ctx context.Context, pool *pgxpool.Pool, envelope *Envelope) (*Postgres, error)` implements the existing `tokens.SecretStore` and `tokens.JSONStore`, plus `Ping(context.Context) error`. Constructor parameters must also carry the validated deployment and schema identifiers; use a typed config rather than unvalidated SQL string concatenation.

- [ ] Write tests for AES-GCM tampering, cross-path/version/deployment substitution, oversized payloads, KMS failure, and error redaction. Use a deterministic test wrapper only in tests.
- [ ] Write PostgreSQL integration tests for create-only writes, one winner from concurrent CAS, atomic version/history updates, rollback, deletion fences, and a committed write with a lost response. Run these cases before implementation and observe failures.
- [ ] Implement fresh 32-byte data keys, standard AES-256-GCM, KMS-wrapped keys, versioned envelopes and authenticated context. Bound plaintext at 1 MiB, consistent with the existing provider response boundary. Verify KMS request/response integrity fields and restrict key references to the configured CryptoKey.
- [ ] Add `toolbox_secrets` current and encrypted-history tables. Encrypt before a short database transaction; atomically insert history and advance the current version by expected CAS. Retain the creation fence after hiding a JSON path. SQL errors expose no paths or payloads.
- [ ] Run the token lifecycle and initial exchange regressions against the new adapter using actual PostgreSQL and the test wrapper. Add an opt-in real KMS integration test using only synthetic data.
- [ ] Review and commit this task alone.

### Task 3: Separate migrations, SQL roles, and Cloud SQL connections

**Files:** Create `internal/gcpdb/connect.go` and tests; modify `internal/store/postgres.go`; add `internal/store/permissions.go`, tests, and a role-bootstrap SQL template; update the Cloud SQL connector dependency.

**Interfaces:** Preserve `OpenPostgres(ctx context.Context, dsn string) (*Postgres, error)`. Add `OpenPostgresConfig(ctx context.Context, config *pgx.ConnConfig) (*Postgres, error)` so a configured connector DialFunc reaches pooled and dedicated connections. Add `gcpdb.ConnectConfig(ctx context.Context, config Config) (*pgx.ConnConfig, func() error, error)`. The closer releases the connector after all repositories and credential pools close. Keep migrations an explicit separate operation.

- [ ] Write tests proving dedicated connection locks use the same configured dialer as the pool, including cancellation and connector closure. Add real PostgreSQL role tests: runtime cannot create tables, modify audit history, delete grants, truncate protected tables, or purge credential history.
- [ ] Run the tests and observe failures for unsupported connector configuration and permissions.
- [ ] Implement IAM database authentication with the official connector and private IP selection. Set explicit application and credential schema search paths. Use safe identifier quoting and fixed schema validation. Preserve the existing physical-session lock release guarantees.
- [ ] Add idempotent role grants for API, migration, cleanup, retention, and recovery access. Revoke public schema creation and avoid ownership or DDL privileges on runtime identities. Bootstrap administrative grants through an explicitly documented operator action rather than an admin password in Terraform.
- [ ] Run store integration tests and the role matrix with actual PostgreSQL. Verify both a fresh schema and upgrade from migration 001.
- [ ] Review and commit this task alone.

### Task 4: Make provider cleanup observable and retryable

**Files:** Modify `internal/domain/domain.go`, `internal/server/owner.go`, and `internal/store/validate.go`; create `internal/server/cleanup.go` and tests, and `internal/store/migrations/004_cleanup_retries.sql`.

**Interfaces:** Preserve `Server.CleanupOnce(context.Context) error`. Add `CleanupReport` with processed, succeeded, failed, pending, and oldest-pending age fields, plus `RunCleanup(context.Context) (CleanupReport, error)` for maintenance commands. Add creation, last-attempt and next-attempt timestamps, attempt count, and a fixed sanitized error class to cleanup metadata.

- [ ] Write tests proving cancellation, transient provider errors, uncertain refreshes, and overlapping job executions preserve blocked access and revocation material. Verify due-time selection and retry after process restart with a deterministic clock.
- [ ] Run the focused tests and observe failures for absent scheduling and reports.
- [ ] Extract cleanup from the owner handler file. Implement bounded exponential backoff from 5 seconds to one hour, with jitter and at most 100 due jobs per run. Keep the existing connection locks and CAS protocol. A successful run reports unresolved and failed jobs accurately instead of silently treating them as completed.
- [ ] Add migration constraints and legacy timestamp handling. Emit only numeric counters, ages, and fixed outcome classes; never provider errors or credential identifiers as metric labels.
- [ ] Run the entire OAuth/token race suite and server cleanup tests. Verify disconnect still blocks immediately before provider cleanup succeeds.
- [ ] Review and commit this task alone.

### Task 5: Retain and purge encrypted history safely

**Files:** Create `internal/secretstore/retention.go` and tests; create `internal/store/migrations/005_secret_retention.sql`; add protected purge SQL functions and permission tests.

**Interfaces:** Add `RetentionPolicy` with OAuth grace and retired-history grace durations, `RetentionReport` with scanned, eligible, deleted and blocked counts, and `Postgres.Retain(ctx context.Context, policy RetentionPolicy) (RetentionReport, error)`. Default to a one-hour OAuth grace and seven-day retired history grace. Reject nonpositive durations. The method rechecks authoritative application lifecycle state before each bounded deletion transaction.

- [ ] Write tests for pending and expired OAuth transactions, completed and failed disconnect cleanup, active connections, unresolved initial exchange/refresh intents, and concurrent cleanup and retention. Assert current rows and creation fences always survive.
- [ ] Run the tests and observe failures for missing retention behavior.
- [ ] Implement selection and deletion under the existing connection-lock protocol with a short atomic final SQL recheck. Purge only expired or consumed OAuth secrets whose dependent issuance is resolved, and retired provider history after confirmed lifecycle completion and the grace period. Default to retaining records whose state cannot be proved safe.
- [ ] Expose purge through fixed, safely scoped permissions. The API role cannot invoke it or delete history directly. Keep runtime audit protections intact; document audit archival separately rather than adding an unrestricted purge route.
- [ ] Run the real PostgreSQL permission and race tests. Verify retained backups remain decryptable and are not represented as erased by live-row deletion.
- [ ] Review and commit this task alone.

### Task 6: Add deployment commands, configuration, and the production container

**Files:** Split `cmd/toolbox/main.go` into command dispatch and fixture startup; create `internal/runtimecfg/config.go`, `internal/runtimecfg/config_test.go`, maintenance command files, a key-generation command, `Dockerfile`, and `.dockerignore`.

**Interfaces:** Support `toolbox fixture`, `keygen`, `preflight`, `migrate`, `cleanup`, `retention`, `serve`, and `recover-invalidate`. Preserve `TOOLBOX_MODE=fixture go run ./cmd/toolbox`. Parse configuration through `runtimecfg.Load(lookup func(string) (string, bool)) (Config, error)` so tests do not depend on process environment. Add `Validate(command string) error` to enforce command-specific dependencies without granting cleanup jobs signing keys.

- [ ] Write command tests for missing static secrets, malformed rings, non-HTTPS origins, unverified database transports, unsupported owner authentication, fixture cloud exposure, and sanitized exit messages.
- [ ] Run the command and config tests and observe the new failures.
- [ ] Implement explicit maintenance commands using Tasks 1–5. `keygen` writes JSON only to stdout when explicitly invoked; normal startup never creates material. Production `serve` must return a specific sanitized release-gate failure while owner OIDC remains unimplemented. No environment boolean bypasses that check. `preflight` reports infrastructure checks separately from application release gates.
- [ ] Build a non-root, minimal production image containing CA certificates and the single binary. Exclude local secrets, Terraform state, test artifacts, and repository metadata. Handle SIGTERM and close pools and connector resources in order.
- [ ] Run local command tests, `go build ./...`, and container startup/shutdown checks. Verify the existing loopback fixture API and browser flow remain available through their original commands.
- [ ] Review and commit this task alone.

### Task 7: Provision GCP with Terraform and explicit cost profiles

**Files:** Create `infra/gcp/bootstrap` and `infra/gcp/platform` with versions, variables, resources, outputs and example configuration; create Terraform validation CI and infrastructure documentation.

**Interfaces:** Foundation inputs are `project_id`, `region` (default `us-central1`), `environment`, `profile` (`pilot` or `production`), and notification destinations. Runtime inputs additionally require an immutable image digest and numeric static-secret versions. Output repository URL, Cloud SQL connection name, service-account identities, KMS key ID, secret resource IDs, job names and runtime endpoint when enabled. Use an explicitly initialized GCS backend; never output secret payloads.

- [ ] Add Terraform assertions for profile values, immutable image digests, numeric secret versions, deletion protection, IAM separation, zero minimum pilot instances, private SQL networking, and absence of secret payloads or service-account keys.
- [ ] Implement Artifact Registry, Cloud SQL Enterprise PostgreSQL 17 with backups and PITR explicitly enabled, Direct VPC egress networking, software-backed symmetric KMS with 90-day rotation, static-secret containers, restricted buckets, IAM SQL users, and distinct runtime/maintenance identities.
- [ ] Add conditional Cloud Run service and maintenance jobs. Keep service rollout disabled by default during preparation; deploy tooling requires application preflight before enabling it. Scheduler uses OAuth to invoke the Run Jobs API with its own service account. Cleanup and retention schedules default to paused until credentials and schema setup pass.
- [ ] Add private monitoring access, standard uptime/error/latency and database alerts, structured-log metrics for maintenance failures and backlog age, and budget notifications. Exclude OAuth callback query strings from persisted request logs without granting runtime log-management rights.
- [ ] Run `terraform fmt -check -recursive`, `terraform init -backend=false`, `terraform validate`, and local Terraform tests with a mock provider. Validate the real provider schema; do not claim a live plan or apply was tested.
- [ ] Review and commit this task alone, including dependency lock files and without local state.

### Task 8: Provide an idempotent operator workflow

**Files:** Create an executable `scripts/gcp` wrapper and focused helpers under `scripts/gcp-lib`; update `Makefile`, `.gitignore`, `README.md`, and create `docs/deployment-gcp.md`; add shell workflow verification using fake `gcloud` and `terraform` executables.

**Interfaces:** Support `scripts/gcp bootstrap|secrets|build|plan|deploy|status|rollback|recover` with explicit `--project`, `--region`, and `--environment`. Persist only non-secret deployment metadata and immutable image/secret version references in ignored local files. Validate project and resource inputs before constructing subprocess arguments.

- [ ] Write workflow tests for an existing secret, missing prerequisites, interrupted setup, failed migration, failed release gate, changed image digest, and hostile argument values. Assert commands never echo or pass secret values on the command line, and do not apply infrastructure when a plan-only command was selected.
- [ ] Run the tests and confirm the workflow is absent before implementation.
- [ ] Implement state-backend bootstrap, foundation provisioning, create-if-absent secret initialization, immutable image build/push, saved Terraform plan creation, explicit deployment of the selected plan, migration job execution, and private smoke checks. Read operator secret input from stdin or a protected file and send it through stdin; use no shell tracing.
- [ ] Implement status reporting and rollback to a recorded compatible image and configuration. Do not automatically reverse migrations, rotate keys, overwrite existing secrets, or enable traffic after failed checks. Explain the current owner OIDC and Google release gates directly in deployment output.
- [ ] Run shell syntax and fake-command tests, command help checks, and container build verification. Document exact local prerequisites and the first-run sequence. Actual resource creation remains unrun.
- [ ] Review and commit this task alone.

### Task 9: Verify recovery and complete release documentation

**Files:** Create `internal/recovery/invalidate.go` and tests, `docs/recovery-gcp.md`, recovery helpers, a synthetic restore-drill runner, and deployment verification records; update `docs/storage.md`, `docs/HANDOFF.md`, and `docs/implementation-status.md` around the resulting behavior.

**Interfaces:** Add `recovery.Invalidate(ctx context.Context, repo domain.Repository) (Report, error)` for an isolated restored database. Atomically expire sessions while preserving their OAuth references, revoke active credentials and grants, advance affected connection epochs, block provider dispatch, schedule required cleanup, and append a recovery audit. Preserve immutable grant/revocation protections and report unresolved provider operations. The CLI requires explicit isolated-recovery configuration and refuses to serve while recovery reconciliation is pending.

- [ ] Write a regression that restores a snapshot predating a revocation, runs recovery invalidation, and proves the old owner session, agent credential, grant and delegation token cannot authorize access. Test cancellation and idempotent retry.
- [ ] Run the test, observe the restored-authority failure before implementation, and implement the invalidation and traffic fence.
- [ ] Document coordinated SQL backups, static-secret recovery copies, KMS version dependency retention, protected backup access, RPO/RTO targets, provider uncertainty, compromised-key response and rollback compatibility. Produce recovery manifests containing references only. Never claim nonexportable KMS keys can be backed up as plaintext.
- [ ] Run a synthetic PostgreSQL backup/restore drill with the test key wrapper. Make a separate opt-in GCP drill for connector, KMS, backup recovery and private deployment checks; clearly mark it unrun until a dedicated project is available.
- [ ] Run `gofmt`, `go vet ./...`, `go test -race -count=1 ./...`, `go build ./...`, existing real PostgreSQL/OpenBao integrations, fixture browser E2E and delayed-review cases, Terraform validation, and operator workflow tests. Report skipped and unavailable checks individually.
- [ ] Perform an independent whole-change security and correctness review, fix actionable findings, rerun affected checks, and commit the completed changes without merging or deploying.

## Plan Review and Execution

The design direction is approved. This written implementation plan still needs review under the writing-plans workflow. Recommended execution is native inline work because the runtime, storage and deployment interfaces are sequential and share security invariants. Use the current checkout if the operator chooses it, preserve the pre-existing untracked `package-lock.json`, and do not create a worktree without their preference. A whole-change independent review follows implementation; a reviewer does not provision or deploy resources.

Terraform and `gcloud` are not currently available on PATH. Docker is installed but its daemon was unavailable during planning. The Go baseline initially hit sandbox restrictions on the build cache; the approved rerun of `go test ./...` passed. This baseline does not prove real PostgreSQL/OpenBao integration or a GCP deployment. The unavailable tools are verification prerequisites to resolve during execution, not reasons to bypass tests or claim deployment readiness.
