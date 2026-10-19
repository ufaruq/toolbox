# Toolbox

Controlled, user-delegated access to external tools and data. The current implementation supports one operation: reading an explicitly approved Google document as plain text.

The local fixture simulates owner sign-in and Google. A separate loopback-only mode supports real Okta owner sign-in; see [Okta setup](docs/okta-setup.md). PostgreSQL, OpenBao, the authorization flow and browser UI can be exercised locally. Real Google library adapters exist, but the executable does not wire them. Public production OIDC, Picker, live Google acceptance and deployment work remain pending in the [roadmap](docs/ROADMAP.md).

## Start here

- [Roadmap](docs/ROADMAP.md): completed baseline, remaining milestones, dependencies and acceptance criteria.
- [Implementation status](docs/implementation-status.md): revision-specific verification and its limits.
- [Handoff](docs/HANDOFF.md): how to continue without confusing historical checkpoints with current tasks.
- [Design PR #1](https://github.com/ufaruq/toolbox/pull/1): merged architecture and design artifacts.
- [Implementation PR #2](https://github.com/ufaruq/toolbox/pull/2): merged application baseline.

## Run the local fixture

Requires Go **1.27.2** and a free loopback port. No Google account or credentials are needed. PR #2 has merged; the implementation is available on `main`:

```sh
git clone https://github.com/ufaruq/toolbox.git
cd toolbox
TOOLBOX_MODE=fixture go run ./cmd/toolbox
```

Open http://127.0.0.1:8080. For another port, set `TOOLBOX_ADDR=127.0.0.1:18080` and use that exact origin. The executable refuses unspecified/production mode and non-loopback binding.

1. Sign in as the fixture owner and connect the fixture Google account.
2. Create an agent; save its independent credential when displayed.
3. Request `doc-A` for a bounded duration.
4. Review the selected connection/account, verified agent, exact document, read-only action and expiry; approve.
5. Read the document. Change its ID to `doc-B` to exercise denial, then revoke the grant and try again.

Connecting an account alone does not grant an agent access. The fixture provider has both documents, but a grant to A never authorizes B. The UI has no real Google Picker. Fixture signing keys, credential pepper and provider state are ephemeral; restarting does not preserve valid fixture credentials/connections even when database records survive. Use synthetic data only.

Agents currently use custom HTTP request, token and invocation endpoints. MCP and external client integrations are future work under [F1](docs/ROADMAP.md#f1-agent-client-integrations).

## Optional real local stores

```sh
make dev
```

Requires Docker Compose and Go. This starts disposable, loopback-bound PostgreSQL 17.11 and OpenBao 2.4.1, configures CAS and runs the host fixture service with simulated identity/Google. The committed `fixture-only` values are local development credentials. The stack must remain private; recreating its disposable stores loses fixture data. See [storage guarantees and limits](docs/storage.md).

## Checks

```sh
test -z "$(gofmt -l .)"
go vet ./...
go test -race -count=1 ./...
go build ./...
```

To include PostgreSQL and OpenBao tests, start the disposable stores and create `toolbox_test` as described in [storage test setup](docs/storage.md#verification), then set:

```sh
export TOOLBOX_TEST_DATABASE_URL='postgres://toolbox:fixture-only@127.0.0.1:5432/toolbox_test?sslmode=disable&application_name=toolbox-lock-test'
export TOOLBOX_TEST_OPENBAO_ADDR=http://127.0.0.1:8200
export TOOLBOX_TEST_OPENBAO_TOKEN=fixture-only
go test -race -count=1 ./...
```

Unset integration settings cause those tests to skip locally. CI starts both stores and supplies them. The [browser runner](tests/browser/README.md) covers fixture approval, exact-document access, denials, revocation, disconnect and delayed-review races in Chromium. CI retains masked screenshots in its `browser-e2e` artifact; the [committed gallery](docs/e2e-evidence/README.md) records an earlier capture with its own metadata.

See [implementation status](docs/implementation-status.md) for the actual checked revision and results. Fixture coverage does not establish live Google behavior or production identity/deployment readiness.

## Layout and technical references

- `cmd/toolbox`: explicit fixture and local Okta owner sign-in modes.
- `internal/server`: owner/agent API, approval UI, dispatch and final live authorization checks.
- `internal/security`: agent credential hashing and scoped Ed25519 delegation tokens.
- `internal/oauth`: bound OAuth/PKCE transactions, Google adapter and fixture provider.
- `internal/connectors`: fixed Drive metadata/export plans and bounded executor.
- `internal/tokens`: OpenBao CAS, refresh coordination, generation-aware retries and cleanup.
- `internal/store`: memory/PostgreSQL repositories, constraints and audit.
- `internal/app`: wiring and API acceptance tests.
- [Google setup](docs/google-setup.md): live configuration, protocol decisions and required acceptance checks.
- [Storage](docs/storage.md): permissions, transactional guarantees and the current low-throughput snapshot adapter.

The database adapter serializes application transactions and needs scoped queries before larger workloads. Production startup, durable keys, operational recovery and live validation are tracked in [M1–M4](docs/ROADMAP.md#milestones-and-dependencies). No production deployment is claimed.

## Local Okta owner sign-in

`TOOLBOX_MODE=oidc-local` provides real owner identity through an Okta OIDC Web Application on a loopback-only HTTP origin. It requires PostgreSQL, OpenBao, an exact configured origin and issuer, server-side client credentials, and a stable session pepper. Google connections, document access, agents and delegation are disabled in this mode. The fixture instructions above remain the separate synthetic demo.

Follow [Okta setup](docs/okta-setup.md) for the placeholder-only [.env.example](.env.example), disposable dependency setup, exact app settings and startup command. The code and [synthetic OIDC browser test](tests/browser/README.md#synthetic-oidc-browser-flow) can be verified before creating an Okta tenant; no account or client secret is needed for automated verification. Toolbox logout ends its own session, while an existing Okta browser session can sign in again.

**Real Okta acceptance is unrun.** Live browser login/logout must be recorded separately before M1 is complete. Live Google, agent integration and production deployment remain open.
