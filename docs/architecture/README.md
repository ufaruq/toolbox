# Architecture

[Project overview](../../README.md) · [Development](../development/README.md) · [Security](../security/README.md)

## Components

| Code | Responsibility |
| --- | --- |
| `cmd/toolbox`, `internal/app` | Explicit runtime modes, configuration, dependency wiring, acceptance tests. |
| `internal/server` | Owner UI, HTTP and inbound MCP routes, grant lifecycle, final authorization and dispatch. |
| `internal/ownerlogin` | OIDC state/nonce/PKCE, owner sessions and stable owner resolution. |
| `internal/identity`, `internal/identitylink` | Caller token validation and independently verified migration of upstream identities. |
| `internal/keycloakrealm` | Broker realm generation with upstream-only authentication safeguards. |
| `internal/security` | Independent agent credentials and scoped Ed25519 delegation tokens. |
| `internal/oauth` | Provider consent transactions and bound OAuth/PKCE state. |
| `internal/connectors/gdrive` | Fixed metadata/export plans and bounded document reads. |
| `internal/tokens` | OpenBao CAS, refresh coordination and generation-aware cleanup. |
| `internal/store` | Memory/PostgreSQL records, transactions, grants and audit. |
| `internal/mcpclient` | Pinned outbound MCP protocol, schema and credential-context boundary. |
| `internal/githubapp`, `internal/servicepolicy/github` | Short-lived GitHub installation credentials and fixed capability policies. |

## Identity and access flow

1. Owner login proves the human identity. Okta can be used directly, or Keycloak can broker upstream providers. Migrating an existing owner requires verified identity linkage; matching email alone is insufficient.
2. Google consent creates a provider connection. Its tokens authorize provider API access, but do not themselves authorize an agent to read a document.
3. The owner reviews the agent, connection, exact document, action and expiry. Approval creates a bounded grant.
4. A caller presents the required authentication and independent agent credentials. Toolbox validates the delegated operation and checks live grant state before provider execution.
5. Revocation, expiry and disconnect must prevent subsequent reads. Returned document text remains untrusted data.

Inbound MCP authentication and outbound MCP provider calls are different boundaries. See [MCP setup](../mcp-setup.md) and the [outbound pilot](../mcp-gateway-pilot.md).

[GitHub access](../github-connector.md) uses separate repository connections,
requests and grants. Installation selections only make repositories available
to their configured owner; grants bind an authenticated agent to exact actions,
branches, paths, revisions and expiry. The inbound MCP tool ceiling and owner
repository approval are separate checks.

## Persistence and concurrency

PostgreSQL stores application records and audit state. OpenBao holds provider credentials with compare-and-set and refresh generation checks. The PostgreSQL adapter currently serializes snapshot transactions; it needs scoped queries before larger workloads. See [storage guarantees](../storage.md) for transaction behavior, migrations and test setup.

## Changing the system

New tools should define narrow actions and resource identifiers, preserve live authorization at dispatch, bound provider responses, and add allow/deny/revoke coverage. New identity providers must preserve stable owner identity without trusting user-controlled identity claims. New runtime modes must explicitly define secrets, network exposure, recovery and acceptance requirements.

[Original design artifacts](../design/README.md) explain the broader proposal. [Roadmap](../ROADMAP.md) records future production and connector work; those proposals are not current capabilities.
