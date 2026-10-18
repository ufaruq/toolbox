# Toolbox

Controlled, user-delegated access to external tools and data. This draft implements a first Google Drive document-read slice in Go.

> **WIP: not ready to merge or deploy.** The full implementation is preserved for continuation. The reviewed cleanup defects are fixed and locally verified, including fixture browser E2E. Production human OIDC and live Google verification remain unfinished. See [handoff](docs/HANDOFF.md) and [verification status](docs/implementation-status.md).

## Run the mock-only local service

Requires Go **1.27.2** and a free loopback port. No Google account or credentials are needed.

```sh
git clone https://github.com/ufaruq/toolbox.git
cd toolbox
git switch feat/user-delegated-drive-mvp
TOOLBOX_MODE=fixture go run ./cmd/toolbox
```

Open http://127.0.0.1:8080. For another port, set `TOOLBOX_ADDR=127.0.0.1:18080` and open that exact origin. The executable intentionally refuses unspecified/production mode and non-loopback binding.

1. Sign in as the fixture owner.
2. Connect the fixture Google account.
3. Create an agent. Its independent credential is displayed once, in the local fixture console.
4. Request `doc-A` for a bounded duration.
5. Review the selected connection, verified agent ID, synthetic account, exact document, read-only action and expiry; approve.
6. Read the document. Change the document ID to `doc-B` to exercise denial, then revoke the grant and try again.

The synthetic provider has `doc-A` and `doc-B`. Provider account access to both does not widen a grant to A. The approval UI does not contain real Google Picker. Fixture keys and identity/provider state are ephemeral; a restart invalidates previously issued fixture credentials/tokens. Do not use real data or credentials in this mode.

## Optional real local storage dependencies

```sh
make dev
```

This starts disposable, loopback-bound PostgreSQL and OpenBao dev containers, configures CAS, then runs the Go service on the host with fake identity and Google. Requires Docker Compose and Go. The disposable Compose stack has been exercised locally with synthetic identity and Google providers. OpenBao's committed `fixture-only` token/password are intentionally non-production test values. Never expose this stack publicly. Stopping/recreating its disposable stores loses local fixture data.

## Checks

```sh
go vet ./...
go test -race -count=1 ./...
go build ./...
```

The refresh/disconnect regression and the full race suite now pass locally. PostgreSQL integration tests require the disposable database below. To also run the real local OpenBao KV-v2 cleanup/CAS test, set `TOOLBOX_TEST_OPENBAO_ADDR=http://127.0.0.1:8200` and `TOOLBOX_TEST_OPENBAO_TOKEN=fixture-only` for the disposable Compose instance. Unset integration settings cause those checks to skip locally. CI starts both stores and supplies these settings so the integration checks execute. Fixtures do not validate live Google or production identity.

[Browser E2E instructions](tests/browser/README.md) exercise the actual UI approval and revocation flow in headless Chromium. CI also runs this suite against the fixture executable backed by PostgreSQL and OpenBao. The [screenshot gallery](docs/e2e-evidence/README.md) shows the review, allowed read, denied document and revoked-grant states. Successful and failed CI runs upload their screenshots as the `browser-e2e` artifact.

For a disposable PostgreSQL test database:

```sh
TOOLBOX_TEST_DATABASE_URL='postgres://toolbox:fixture-only@127.0.0.1:5432/toolbox_test?sslmode=disable&application_name=toolbox-lock-test' go test -race ./...
```

The test role needs schema creation/drop and permission to terminate its own test sessions. See [storage limits and test setup](docs/storage.md).

## Layout

- `cmd/toolbox`: explicit fixture-only executable
- `internal/server`: disjoint owner/agent API, trusted approval UI, dispatch gate and final live check
- `internal/security`: agent credential hashing and scoped Ed25519 delegation tokens
- `internal/oauth`: one-use bound OAuth flow, fixed Google adapter and fixture provider
- `internal/connectors`: static manifest, immutable fixed Drive plans and bounded executor
- `internal/tokens`: OpenBao CAS, refresh intent/coordinator, generation-aware retries and cleanup
- `internal/store`: PostgreSQL/memory repositories, relational constraints and audit
- `internal/app`: wiring and full API acceptance tests

The PostgreSQL snapshot adapter is deliberately low-throughput and serializes all application transactions. It needs scoped queries before a larger deployment. No multi-replica production readiness is claimed.

## Design and continuation

- [Design PR #1](https://github.com/ufaruq/toolbox/pull/1)
- [Implementation draft PR #2](https://github.com/ufaruq/toolbox/pull/2)
- [Handoff and exact remaining work](docs/HANDOFF.md)
- [Google configuration and release gates](docs/google-setup.md)
- [Storage guarantees and limitations](docs/storage.md)
- [Proposed MCP service connectors with Docker Gateway](docs/superpowers/specs/2026-10-18-mcp-service-connectors-design.md)
- [MCP service connector validation and implementation plan](docs/superpowers/plans/2026-10-18-mcp-service-connectors.md)

No merge, deployment or live OAuth application provisioning has been performed.
