# Docker Gateway / GitHub MCP feasibility record

Date: 22 October 2026. Implementation baseline: main
`cac87b6d2d7d1f869c1794a68e63e3f874222aea`.

This record covers the Docker Gateway pilot and shared outbound client from
[plan PR #9](https://github.com/ufaruq/toolbox/pull/9). It supports continuing the
controlled client work. It does **not** open production GitHub rollout: the
plan's live provider scope and immutable repository identity gates remain open.
Follow the [reproduction guide](../mcp-gateway-pilot.md) for exact commands.

## Revisions and observed protocol

| Component | Exact revision |
| --- | --- |
| Toolbox baseline | `cac87b6d2d7d1f869c1794a68e63e3f874222aea` |
| Go | 1.27.2 |
| Official Go MCP SDK | `github.com/modelcontextprotocol/go-sdk v1.8.0` |
| Docker Engine used for the probe | 28.4.0, Linux/amd64 |
| Docker MCP Gateway image | `docker/mcp-gateway@sha256:b0a3876ffbb352813d658cf25c137b8eae29bbe23db5944560a1c9059533bb16` |
| Gateway image release | v0.44.1, upstream prerelease |
| Gateway's observed MCP `serverInfo` | name `Docker AI MCP Gateway`, version `2.0.1` |
| GitHub Official MCP server image | `ghcr.io/github/github-mcp-server@sha256:250bc6ce70788207608ef74cef4397230ff2e8481218da74d6093e4bd9101132` |
| GitHub server release | v2.0.3 |
| Client's pinned MCP protocol | `2025-11-25` |

The gateway's handshake version differs from its image release tag. The client
checks the observed handshake name/version and protocol; the gateway catalog
pins the downstream image separately. Both upstream images are referenced by
immutable digest. Signature verification and TLS verification remain enabled.

## Tool inventory and read shape

The fixed gateway/server configuration exposes only these tools:

| Tool | Observed schema SHA-256 | Use in the pilot |
| --- | --- | --- |
| `get_me` | `efddc7bd8bbcef73a14eb1ace1ffdaec81e518ef1e13c1e9271d0b8acb694a49` | Empty arguments; distinguish each credential's account. |
| `issue_read` | `4129cf817f37afefbc65885a75ba37817ae95f46ab9658b0b9de8c37d6b26c2e` | `method=get`, `owner=fixture`, owner-specific repository, issue 1. |

These hashes are from the SDK-decoded input schemas serialized as JSON during
operator bootstrap. The test takes that reviewed inventory as configuration and
the production client verifies it again before each dispatch. A future image or
schema update requires another review; this test does not make arbitrary new
tools safe for agent use.

The official server receives `GITHUB_HOST=https://fixture:9443`, verifies the
fixture certificate with its mounted CA, and uses the GitHub Enterprise REST
prefix `/api/v3`. `get_me` calls `/api/v3/user`. The issue operation calls
`/api/v3/repos/fixture/{private-a|private-b}/issues/1`. Its arguments remain
locator-based; no immutable repository-ID dispatch is claimed.

The controlled API issue includes ID, number, title, body, owner and repository
URLs. The shared client's accepted result forms are bounded text and structured
JSON. The Docker test requires the expected owner's repository marker across
that returned content and rejects known test credentials in content or errors.
Its final run reports text/structured byte counts without printing content.
Resource-specific projection and provenance checks belong to the later GitHub
policy adapter.

## Credential topology

Each synthetic owner has a separate gateway container, private state directory,
explicit secret file, gateway bearer and official GitHub server credential
context. The two state directories are mounted independently at
`/root/.docker/mcp`. The secret files use mode `0600`, and the harness inspects
the actual gateway command to require exactly one explicit `--secrets` source.
Docker Desktop's default secret source is not used.

The gateway maps its `github.personal_access_token` secret into the server's
`GITHUB_PERSONAL_ACCESS_TOKEN`. Toolbox's outbound client never receives the
provider credential. No inbound Okta token, internal delegation token or Google
credential enters this path. The synthetic tokens are generated per run and
accepted only by the controlled API.

The minimum tested topology uses two gateways and two downstream credential
contexts for two owners. Docker profiles are not the isolation mechanism. Both
contexts share an operator-controlled Docker daemon and bridge; this is not a
hostile-container or daemon-administrator isolation claim. Gateway/server
credential refresh and actual provider revocation have not been validated.

## Evidence and remaining gates

The acceptance test is
[`TestDockerGatewayOwnerIsolation`](../../internal/mcpclient/docker_e2e_test.go).
Its production call path uses `internal/mcpclient`; only the HTTPS provider API
and request-counting proxies are controlled fixtures. The test asserts all of
the following and prints a sanitized summary on success:

| Check | Evidence required by the harness |
| --- | --- |
| Real gateway and existing server | Exact local image digests; successful MCP handshake, tool list and issue read. |
| Concurrent owners | Simultaneous `get_me` calls return separate expected identities. |
| Provider credential routing | Successful issue reads match each credential's private repository in the API audit. |
| Provider scope separation | The controlled API returns 404 for each cross-owner repository attempt. |
| Forged owner / connection / epoch | Client denies each mismatch with zero new gateway HTTP requests. |
| Gateway bearer separation | A's bearer cannot authenticate at B's endpoint; no new provider request. |
| Gateway interruption | A's stopped gateway fails; B remains callable. |
| Gateway restart | Restarted A uses its original explicit secret context and identity. |
| Client closure | Closed restarted-A client makes no provider request; B remains callable. |
| Known credential exposure | No generated provider, gateway or audit token appears in results/errors. |

The first successful actual Docker run on 22 October 2026 completed in **40.68
seconds**, after the images were pulled. Its sanitized provider audit recorded
owner A: four requests (three 200, one 404), and owner B: five requests (four 200,
one 404). The 404s were the expected cross-repository denials. Task containers,
network and temporary fixture image were absent after cleanup; the pinned
upstream images remained cached.

Observed individual calls in that run included concurrent `get_me` at 6.347 /
6.336 seconds and each owner's first issue read at 4.859 / 4.990 seconds. These
are single-run samples including the client's handshake/inventory work, not a
benchmark or a latency distribution. Image pulls and initial compilation are
setup costs. The pilot has not measured production throughput, memory or
multi-tenant capacity; do not derive savings or an operating cost estimate from
this run. The implementation PR records the final race-enabled rerun after
client review fixes.

| Original feasibility requirement | Disposition |
| --- | --- |
| Existing server can read a synthetic issue through Docker Gateway | Covered by the controlled Docker acceptance test. |
| Separate owner credentials and concurrent calls | Covered for the explicit two-gateway topology. |
| Private gateway transport, bounded tools, verified TLS | Covered for local loopback endpoints, fixed catalog and generated provider CA. |
| Stop/restart/client-close separation | Covered by the Docker acceptance test; not application disconnect or provider revocation. |
| Real GitHub authentication and minimum provider permissions | Open: test a dedicated real fine-grained token or installation credential. |
| Stable repository identity enforced at dispatch | Open: verify provider-enforced repository-ID restriction or another accepted route, including rename/transfer, old-locator reuse and resolution/dispatch races. |
| Stable provider account identity and refresh/cleanup | Open for actual provider credentials and connection lifecycle. |
| Agent grant/revocation/final release contract | Tasks 3–5; this client library does not issue or enforce application grants. |

**Decision:** proceed with the reusable client and controlled Docker pilot.
Production GitHub enablement remains blocked until the open provider and
authorization requirements pass. There is no direct-server fallback and no
loosening of Toolbox's resource grants to bypass those gates.

## Reuse versus remaining implementation

The common MCP client, fixed gateway binding, schema inventory checks, JSON
argument validation, transport/result bounds and cancellation can be reused for
another reviewed service. Its existing MCP server provides the provider API
translation. No parallel GitHub issue REST connector was added.

Toolbox still needs provider-specific action/resource policy, immutable resource
identity, persistence, trusted approval, account connection and credential
lifecycle, runtime wiring, UI and live acceptance. Adding another catalog entry
is therefore not sufficient to expose another service safely to agents. The
existing Drive implementation continues through its existing connector.
