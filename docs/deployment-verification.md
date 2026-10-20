# Deployment verification

The original portable stack was validated locally on 2026-10-18. The 2026-10-19
update integrates merged Okta/Google/MCP code from main while preserving the
production serving gate. Real loopback Workspace/MCP and synthetic persistent
containers are separate entry points; the hosted identity/provider integration is
still required. No GCP resources were applied.

## Main integration and review follow-up (2026-10-19)

- Released migrations001–005 are unchanged. Upgrades from003 and005 preserve owner
  identity, original session/CSRF hash, Google connection generations and saved MCP
  profiles; deployment migrations are appended as006/007. Actual PostgreSQL tests passed.
- Restored MCP approvals and agents are disabled; pending requests and pending or
  exchanging owner sign-ins are cancelled. Provider references remain available for
  reconciliation. Memory and actual PostgreSQL tests passed, including idempotency.
- The CI restart failure was reproduced: Docker created the checkpoint bind source
  as root before the operator could write it. The workflow now creates an
  operator-owned0700 directory before any browser mount, rejects symlinks and
  keeps checkpoint files0600. Command-boundary regressions passed.
- Both old review comments are covered: credential envelope AAD includes the
  credential schema, and standalone cleanup does not load HTTP signing/pepper keys.
- `make check` passed with actual PostgreSQL/OpenBao; Terraform init, format and
  validate passed without plan/apply.
- The rebuilt container passed the full Go race/integration suite, Chromium fixture
  approval/revocation/disconnect and delayed-review cases, Linux host checks and
  PostgreSQL/application restart with the original session, agent credential,
  delegation signature and encrypted provider generation. Encrypted SQL/static
  backups, an actual isolated SQL restore with authority invalidation, and healthy
  monitoring reports also passed. The test project used a separate host port to
  preserve the existing developer stacks.
- Synthetic OIDC, Workspace and Google-probe browser checks passed in Docker.
  These browser checks ran without the race flag because that browser helper
  image has no C compiler; the full application race suite passed separately.
- The independent whole-branch review found one additional retention starvation
  bug: a disconnected OAuth attempt with no issued bundle aborted every scan.
  The regression failed before the fix and passed afterward against PostgreSQL.
  Missing bundles now retain/count uncertain verifier material as blocked and
  advance the cursor; other storage errors still abort. The full `make check`
  passed again after this fix. No other actionable findings were identified.

The real-account tests completed before the #10/#7 merges included four Google
PKCE/scope checks, an owner-approved Google document read, a native Codex MCP read
of that document and denial of another document. Those tests did not exercise GCP
KMS or hosted deployment. Live revocation, disabled-client, disconnect,
second-client isolation and enforced fresh eight-hour authentication remain open.

## Original portable-stack verification (2026-10-18)

| Check | Result |
| --- | --- |
| Go race suite with real PostgreSQL and OpenBao regression fixture | Passed |
| Envelope tampering, context transplant, concurrent CAS, cancelled writes, lost commit responses, unknown refresh fencing | Passed |
| Persistent signing/pepper rotation, original-session CSRF, removed keys | Passed |
| Restricted runtime roles, immutable audit/grants/history, schema-owner migration and compatibility preflight | Passed |
| Cleanup retries/leases/batches, conservative lifecycle retention and creation fences | Passed |
| Containerized Go integration, Chromium approval/revocation/disconnect, all delayed-review cases | Passed |
| PostgreSQL/app restart with original session, credential, delegation signature and encrypted provider generation | Passed |
| age authentication/tampering, actual encrypted SQL backup and isolated restore with authority invalidation | Passed |
| Numeric monitoring, failed/stale job/backup thresholds | Passed |
| VM operator directory traversal and Docker mount ordering | Disposable Linux regressions passed; systemd parsed generated units |
| Terraform init/format/validate, Make target wiring | Passed without plan/apply |
| Actual GCP/IAM/KMS, registry publication, VM reboot, public TLS, off-host upload, external alerts, live identity/Google | Not run; environment verification required |

An independent whole-branch security/correctness review found three workflow defects: operator traversal beneath the mounted data directory, Docker startup ordering relative to that mount, and repeated initialization after moving a backup identity offline. Each was reproduced and fixed with regression checks. No unresolved Important or Critical findings remain from that review.

The architecture decisions remain explicit: PostgreSQL preserves existing security controls and fits the pilot; encrypted credentials use a separate schema; local tests use real encryption; production requires GCP KMS; retention preserves unknown/orphaned issuance; backups use age and separately held recovery material. Off-host delivery and external alert routing require operator setup. The full-state metadata adapter remains a low-throughput boundary, and readiness checks a persisted sentinel rather than scanning every ciphertext on every probe. See [deployment](deployment-docker.md), [database decision](superpowers/specs/2026-10-18-gcp-deployment-design.md#database-decision) and [recovery](recovery-docker.md).
