# Storage adapters and operating limits

[Project overview](../README.md) · [Current roadmap](ROADMAP.md) ·
[Implementation evidence](implementation-status.md)

This is the technical storage reference. The [roadmap](ROADMAP.md) is the single
pending-work index: **M1** is real owner OIDC; **M2** is live Google/Picker wiring
and acceptance; **M3** is a deployable controlled pilot with persistent/rotatable
keys, least-privilege stores, secret cleanup and operations; **M4** is larger
workload SQL, rate limits and retention. Optional agent clients/MCP (**F1**) and
more tools/providers (**F2**) are future features. The limits and operating
requirements below inform those milestones; adapter implementation alone does
not establish release readiness.

## Supported slice

`internal/store` implements `domain.Repository` with:

- `NewMemory() *Memory` for one-process development and unit tests.
- `NewMemoryWithClock(func() time.Time) *Memory` for deterministic expiry tests.
- `OpenPostgres(ctx, dsn) (*Postgres, error)` for a primary PostgreSQL database.
- `(*Postgres).Migrate(ctx) error` for embedded, checksummed, transactional migrations.
- `(*Postgres).Close()` for shutdown of the transaction pool. Cancel active request contexts before shutdown so dedicated connection-lock sessions also close promptly.

Opening the database does not migrate it. Run migrations explicitly with a migration owner, then start the service with a less-privileged runtime role. Production configuration must require verified database TLS, for example `sslmode=verify-full` and the deployment's trusted CA. The adapter accepts plaintext local-development DSNs; it does not silently upgrade them or certify their security.

The current fixture executable calls `Migrate` at startup when `DATABASE_URL` is
set. That development convenience does not implement the separate production
migration/runtime-role arrangement. It also generates an ephemeral signing key
and credential pepper on every start. Persistent database records therefore do
not establish restart-safe credentials or a deployable pilot; key persistence,
rotation and recovery belong to **M3**.

This is a **low-throughput reference adapter**, not a scale-ready storage engine. Each transaction reads every non-secret record, copies the complete snapshot, validates it, and writes changed records. All application transactions, including reads, take one database-wide advisory transaction lock. Memory and transaction work are proportional to total stored state, including audit history. The connection pool has eight connections; one transaction is active at a time. Adding API replicas does not increase storage throughput. Do not run an unbounded production workload on this adapter.

Before a larger deployment, replace full snapshots with scoped, indexed queries and explicit transaction methods, retaining the same ownership constraints, live primary reads, immutable grants, atomic audit writes, and authorization tests. Add and verify a deliberate audit retention mechanism. This first slice provides no automatic audit retention or pruning.

## Tables and invariants

The migration creates separate `users`, `agents`, `credentials`, `sessions`, `connections`, `resources`, `grants`, `delegation_requests`, `oauth_transactions`, `cleanup_outbox`, and `audit_events` tables. `toolbox_migrations` records the exact checksum of each applied migration. Never edit an applied migration; add a new one.

Each entity has a JSONB payload containing its complete typed domain record. Stored generated columns expose keys and relevant relational fields without allowing payload/key divergence. Payload key allowlists reject accidental new fields such as `AccessToken`; changing the domain model requires a corresponding migration. Resources and approval requests additionally carry an owner key derived by the adapter from their connection or agent.

Database constraints include:

- Unique human issuer/subject identities and stable nonempty opaque identifiers. Session IDs may be hashes; UUID format is not required by storage.
- Agent-owner, connection-owner, session-owner, OAuth-session-owner, OAuth-connection-owner, and cleanup-connection-owner foreign keys.
- Composite grant foreign keys tying the same owner to the agent, connection, and exact selected resource.
- A unique approved-grant reference and composite request-to-grant binding to the exact owner, agent, tool, and file.
- Positive connection/grant epochs and versions, positive request durations, and valid grant time ordering.
- Immutable agent/connection ownership and monotonic connection epochs.
- Grants that cannot be deleted or edited, apart from setting their first revocation timestamp. A revocation cannot subsequently be cleared or changed.
- Immutable approved requests; pending requests cannot be changed into approved requests without a valid matching grant.
- Append-only audit triggers rejecting update, delete, and truncate. Audit references intentionally have no foreign keys: events may describe denied requests for nonexistent IDs and must survive identity lifecycle changes. Service actor names are valid.

The shared Go validator applies these semantic invariants to both adapters before commit. SQL constraints independently enforce the relational boundary even if a buggy writer bypasses that validator. Authorization remains the service's responsibility: a relationally valid record does not itself authorize its creator.

## Transactions and time

`Transact` callbacks receive a private copy. Return an error, cancel the context, or panic and the mutation is rolled back. The memory adapter clones again before committing, preventing retained callback pointers from modifying committed state. Callbacks must remain short, avoid network I/O, and never recursively call `Transact`. Do not retain or concurrently mutate the supplied snapshot.

The PostgreSQL adapter begins a READ COMMITTED transaction, obtains `pg_advisory_xact_lock` in a fixed namespace, loads all tables in one statement, then reads `clock_timestamp()` from the primary. This ordering avoids a snapshot or timestamp captured before waiting for the lock. It serializes all cooperating adapter transactions and prevents lost updates. It is deliberately not PostgreSQL's SERIALIZABLE isolation mode: beginning such a snapshot before waiting would violate the desired fresh post-wait authorization read.

All application writers must use this protocol. Arbitrary direct SQL writers, noncooperating maintenance jobs, and replica reads are unsupported. SQL foreign keys still enforce ownership, but the adapter does not claim serializable interoperation with writers that ignore its advisory lock. Migrations share the same transaction-lock namespace. Synchronization removes deletable dependants first, upserts parents before dependants, and appends new audit events in the same commit. A database or audit write failure fails the whole operation. SQL error details and DSNs are not returned to callers because they can contain record metadata or credentials.

## Distributed connection locks

`LockConnection(ctx, connectionID)` uses a stable SHA-256-derived advisory key and an independent physical PostgreSQL session. It never borrows a pooled session, so a held lock cannot leak back into the pool. The global transaction lock uses a distinct namespace value.

Acquisition is bounded by the caller's context and ten seconds. A held session is closed when its request context is cancelled or after a maximum forty-five-second hold. Unlock has a two-second deadline. Every exit physically closes the underlying socket, including unlock failure and the driver's asynchronous-cancellation path. Unlock is idempotent and reports `ErrLockLost` when the session was cancelled, expired, terminated, or did not confirm unlock.

Always inspect the unlock result before returning success or releasing a provider token. A bare `defer unlock()` that ignores its error is insufficient. Use a named return and override the result on error. The current repository interface cannot asynchronously report session loss to a worker; loss is detected on release. A lost PostgreSQL session also cannot fence an already dispatched Google refresh or OpenBao operation. The token manager must retain epoch checks, CAS writes, uncertain-outcome handling, and post-lock live authorization. This adapter does not claim exactly-once refresh or protection against all cross-system failure races.

## Secret and permission boundary

SQL stores only identity metadata, hashes of agent credentials and CSRF/OAuth state, secret references, grant policy, resource metadata, cleanup state, and audit metadata. It must never store Google access/refresh tokens, OAuth codes, PKCE verifiers, plaintext agent credentials, or document contents. Those belong in their specific request/secret-store boundary. Field allowlists are defense in depth, not a guarantee against application code putting a secret into an ordinary string field.

OpenBao KV-v2 stores provider credential bundles and OAuth transaction secrets.
Durable exchange/refresh intents and cleanup-only responses fence uncertain
provider outcomes; a pending cleanup record is not proof that provider revocation
has completed. Current-version deletion does not erase historical KV versions.
Production needs separately permissioned expiry/orphan cleanup and historical
version destruction, with backup and audit-retention handling reviewed together.
Those **M3** operating requirements are not supplied by the SQL adapter or the
fixture's cleanup loop.

Use a dedicated schema and revoke public `CREATE` rights. The runtime role must not own tables, functions, or the schema, must not be superuser, and must not have DDL, trigger-disable, replication, or unrestricted role-management privileges. It needs SELECT/INSERT/UPDATE/DELETE on mutable tables, SELECT/INSERT/UPDATE on grants, SELECT/INSERT only on audit events, and sequence USAGE for audit ordering. Trigger protections are not a security boundary against a database owner. Separate backups/restore, migration, runtime, and any future retention privileges. Disable statement/parameter logging that would capture metadata or hashes; do not log DSNs.

## Verification

Run ordinary tests:

```sh
go test -race ./internal/store
```

For the disposable Compose stack, start the stores and configure the OpenBao
mount from the repository root:

```sh
docker compose up -d --wait
docker compose exec -T openbao bao write secret/config cas_required=true max_versions=3
```

Check whether the integration database exists:

```sh
docker compose exec -T postgres psql -U toolbox -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname='toolbox_test'"
```

If it returns no row, create the database once. If it returns `1`, use that
database only if it is the intended disposable fixture database; do not drop a
pre-existing database to prepare tests.

```sh
docker compose exec -T postgres createdb -U toolbox toolbox_test
```

Run integration tests against an explicitly disposable database whose test role may create/drop schemas:

```sh
TOOLBOX_TEST_DATABASE_URL='postgres://toolbox:fixture-only@127.0.0.1:5432/toolbox_test?sslmode=disable' go test -race ./internal/store
```

Each integration test creates and drops a unique schema. Backend-termination
testing identifies the exact lease by its database and schema-specific advisory
lock key in `pg_locks`, independent of `application_name` or DSN format. It waits
for that backend to terminate and checks that an unrelated same-application
session survives. Use a dedicated disposable test database, and a role able to
terminate its own backend. No real provider credentials or documents are needed.

Tests cover transactional rollback and cancellation, deep-copy isolation, panic rollback, concurrent updates, immutable grants/revocations/approvals/audits, cross-owner and exact-resource foreign keys, unknown secret-field rejection, migration idempotency, separate-instance advisory contention, cancelled/lost-session cleanup, and database time after lock waiting. The recorded verification at `621fc25` includes the suite under Go's race detector against PostgreSQL 17.11 using synthetic records, within 301 passing Go tests/subtests with real PostgreSQL/OpenBao and Chromium fixture checks. See [implementation evidence](implementation-status.md) for scope and provenance. This documentation update does not rerun those application checks. Adapter and fixture results do not prove production OIDC, live Google/Picker, or production deployment readiness.
