# Deployment verification

Validated locally on 2026-10-18. Production owner authentication and live Google validation remain release gates; no GCP resources were applied.

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
