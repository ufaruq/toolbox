# Reusing MCP service connectors with Docker Gateway

**Status:** Proposed design for review. This PR changes documentation only; it does not add a client, deploy a gateway, migrate credentials, or replace a connector.

**Goal:** Make adding services to Toolbox cheaper by reusing existing MCP servers while preserving owner-approved, agent-specific access to selected resources.

**Companion:** [Validation and implementation plan](../plans/2026-10-18-mcp-service-connectors.md).

## What we get

An MCP server is a reusable service connector. For example, GitHub's existing server already implements GitHub operations and describes their inputs. Toolbox can call that server using the same protocol it uses for another service's MCP server.

We build one outbound MCP client in Toolbox. Docker's gateway can aggregate the selected servers and manage their configuration, execution and routing. For supported services, adding an integration becomes server configuration plus a reviewed permission mapping and acceptance tests, instead of another complete REST client.

The reusable server supplies the API implementation. Docker supplies a way to discover, configure and operate it. MCP also permits calling compatible servers directly; Docker is an evaluated runtime choice, not a requirement of the protocol.

| Work needed for another service | Proposed responsibility |
| --- | --- |
| Provider API requests, response translation and tool input descriptions | Existing provider MCP server, where suitable |
| Protocol negotiation, tool inventory and tool calls | One shared Toolbox MCP client |
| Container lifecycle, server configuration, routing and tool allowlists | Docker gateway and its operator |
| Provider sign-in, credential storage and refresh | Explicitly selected credential owner: gateway/server or Toolbox; verify support per integration |
| Owner approval, authenticated agent, resource/action/expiry limits, revocation and application audit | Toolbox |
| Mapping approved resources to the server's tools and arguments | Small, provider-specific Toolbox policy adapter |

There is no promised percentage reduction yet. The first pilot measures custom API code avoided, policy code still required, setup work and operational cost.

## Current baseline and related work

At the reviewed `main` commit `6279f3aab67465aadf5b1ee07f50ed8a99d4bcb4`, Toolbox has a fixture-oriented HTTP service, a Google OAuth/token lifecycle, a fixed Drive executor, trusted owner approval, immutable document grants and live checks before content release. Live Google acceptance remains unfinished. See [implementation status](../../implementation-status.md) and [Google setup](../../google-setup.md).

Several changes are separate proposals or unmerged implementations as of this review:

- [PR #3](https://github.com/ufaruq/toolbox/pull/3) consolidates the roadmap.
- [PR #5](https://github.com/ufaruq/toolbox/pull/5) adds local Okta owner login.
- [PR #7](https://github.com/ufaruq/toolbox/pull/7) adds an **inbound MCP endpoint**: agents call Toolbox, with direct Okta authentication and per-client permissions. It does not provide the outbound service-connector client proposed here. Its hosted live Google path is unavailable pending separate work.
- [PR #8](https://github.com/ufaruq/toolbox/pull/8) proposes service-account principals. The first connector pilot here keeps the existing human-owner model.

This documentation PR targets `main` independently. An implementation must reconcile the then-merged authentication, transport and storage changes; it must not assume the other PRs have merged or redo their inbound MCP work.

## Proposed architecture

```mermaid
flowchart TD
    Agent["Authenticated agent"] --> Gate
    Owner["Owner in trusted approval UI"] --> Gate
    subgraph Toolbox["Toolbox: code we maintain"]
        Gate["Agent identity, grant and permission checks"] --> Policy["Reviewed service permission adapter"]
        Policy --> Client["One shared outbound MCP client"]
        Client --> Final["Validate result and recheck live grant"]
    end
    Client --> Gateway["Docker MCP Gateway: private, configured routes"]
    Gateway --> GitHub["Existing GitHub MCP server"]
    Gateway --> Other["Another reviewed MCP server"]
    GitHub --> GitHubAPI["GitHub API"]
    Other --> OtherAPI["Service API"]
    GitHubAPI -. "result returns through server and gateway" .-> Client
    OtherAPI -. "result returns through server and gateway" .-> Client
    Final --> Result["Bounded result to agent"]
```

This is an execution path through Toolbox. The agent receives no separate access to the downstream gateway, its management tools, server credentials or arbitrary provider tools. Discovery supplies inventory for operator review; it does not automatically grant agents new capabilities.

There are two independent MCP roles: Toolbox may be an MCP **server** for incoming agent requests, and a shared MCP **client** for outgoing service calls. Their authentication and sessions are distinct. Never forward an incoming Okta token or internal delegation token as a provider credential.

### Example: read an issue from one repository

The first candidate is GitHub Official, using one read operation on an issue in a dedicated test repository. The current upstream tool is `issue_read` with `method=get`; the pilot must confirm that exact tool/schema against its pinned server inventory.

1. The owner connects a test GitHub identity and approves an authenticated agent to read issues in one selected repository until a specified expiry.
2. Toolbox resolves that repository to the provider's stable repository ID and records the approved connection, action, resource and expiry. The first supported operation reads one requested issue; it does not list/search across repositories or follow links to other resources.
3. The policy adapter validates the issue number and constructs the approved server/tool/method/repository arguments. The agent cannot choose a server URL, credential reference, alternate method or raw forwarded arguments.
4. The shared client makes the MCP call through the selected private gateway route. The existing server performs the GitHub API request.
5. Toolbox checks that the returned issue belongs to the approved repository, validates and bounds the result, rechecks current authorization, records the outcome and releases content as untrusted data.

Repository rename, transfer or an ambiguous identity match must fail closed until the owner reviews the connection/resource again. The selected route must enforce the approved stable repository ID throughout the upstream read, using ID-bound execution or provider-enforced credentials restricted to that repository ID. A separate identity lookup followed by a broadly credentialed, name-based read is insufficient: the old owner/name can be reused between lookup and dispatch. Verify old-locator reuse and identity changes during that interval; response rejection alone is insufficient. If the server/credential route cannot enforce this or establish result provenance without recreating substantial API code, record the incompatibility and reject or narrow the pilot.

## Toolbox integration boundaries

| Existing component | Effect of this proposal |
| --- | --- |
| `internal/connectors`, `internal/app/integration.go` | Add an MCP-backed execution path for a new service; preserve the existing Drive path during the pilot. A suitable provider server may later replace some direct API execution. |
| `internal/oauth`, `internal/tokens` | Candidate for reduced provider-specific work only when the chosen server/gateway demonstrably owns the required consent, refresh, disconnect and cleanup lifecycle. No wholesale deletion is proposed. |
| `internal/security`, `internal/server/delegation.go`, live grant checks | Retain the authorization contract. Adapt it to the new action/resource type with additive persistence; do not reinterpret document IDs as repository IDs. |
| `internal/store` and grant/connection audit | Retain authoritative grants, expiry, revocation and approval evidence. Gateway call logs supplement these records. |
| Owner login and approval UI | Retain trusted owner identity and review. Docker's provider login does not establish a Toolbox owner session. |
| Inbound MCP work in PR #7 | Reuse when integrated; the outbound client is a separate responsibility. |

The future client lives in `internal/mcpclient`; the first permission adapter lives in `internal/servicepolicy/github`. Operator-controlled bindings select an exact server identity, tool/schema revision and connection credential context. Generic transport code does not decide authorization. The service adapter does not implement GitHub's issue REST client.

## Credential and permission requirements

### Owner-to-connection isolation

Docker documents that OAuth credentials are shared across profiles in one installation. **A profile is not an owner credential boundary.** A single shared profile or mutable process-wide token must not select credentials for concurrent Toolbox users.

Start the local feasibility probe with one synthetic owner and one dedicated test credential. Before any multi-user pilot, select and verify either isolated gateway/server credential contexts per connection, or a documented gateway mechanism that binds each authenticated invocation to the correct owner-specific connection. The binding is chosen from trusted persisted state, never agent arguments. Unsupported isolation blocks multi-user use.

Disconnect must invalidate the Toolbox connection and grants before remote cleanup. Credential-context reuse after disconnect/reconnect is forbidden. Verify concurrent owners, refresh, crash/restart and in-flight disconnect behavior before moving any current token-management responsibilities. An allowlisted tool does not automatically narrow the underlying provider credential; provision least-privilege credentials independently.

### A bounded tool surface

- Start with one reviewed read action. Permit only the exact server identity, reviewed tool and method; reject unknown tools, duplicate names from other servers, unknown arguments and changed schemas.
- Construct arguments from the immutable approved resource plus validated action inputs. Reject caller-selected URLs, executable commands, credential selectors and server-management operations.
- Keep server registration, dynamic server addition, code execution, prompt retrieval, resource subscriptions and automatic linked-resource fetching unavailable to the agent in this pilot. Deny unsupported server-to-client requests, including elicitation and sampling.
- Apply a 20-second total invocation deadline and a 1 MiB application-result limit, including protocol framing/decoding bounds. Propagate cancellation. Recheck live rights immediately before dispatch and before result release; discard results after revocation or connection invalidation.
- Treat tool descriptions, annotations and returned content as untrusted. A server's `readOnly` annotation is not proof of the permitted action. No automatic call retry after dispatch; a timeout is not evidence that a call never executed.
- Audit the authenticated agent, approving owner, connection, immutable grant/resource, selected server/tool revision and outcome. Exclude provider credentials and raw sensitive results from logs.

### Docker governance is a separate decision

The baseline evaluates the open-source gateway with a fixed operator-managed inventory. It does not require Docker's enterprise or Sandboxes organization-governance offering.

Docker's documented Sandboxes Cedar policies can inspect JSON tool arguments, so Docker policy may overlap resource restrictions. Its `@requireApproval` asks the originating MCP client for confirmation; an autonomous client can answer programmatically. That is not a substitute for Toolbox's independently authenticated owner review. Verify the chosen product's availability, identity model and enforcement surface before proposing any policy replacement. Gateway rules apply only to traffic passing through it; isolate its endpoint and credentials so agents cannot bypass Toolbox.

## Alternatives and decision

| Approach | Benefit | Cost or condition |
| --- | --- | --- |
| Continue custom provider API connectors | Full control of narrowly defined behavior | Reimplement and maintain each provider's API work |
| Shared MCP client calling selected servers directly | Reuse connectors with fewer runtime components | Toolbox/operator handles more connection and lifecycle configuration |
| Shared MCP client through Docker gateway | Reuse connectors plus catalog, container lifecycle and centralized routing | Additional runtime, credential-isolation work and a product/version decision |

Evaluate Docker with the GitHub read pilot and compare a direct-MCP route using the same server. Keep policy and domain types independent of Docker, so its operational benefit can be measured without committing the authorization model to it. The result may favor Docker, direct MCP, or the existing narrow connector for a particular service.

## Rollout and acceptance

Follow the [companion plan](../plans/2026-10-18-mcp-service-connectors.md) in order: record a pinned-server feasibility result, implement the shared client against synthetic servers, add the resource-specific policy/grant extension, and then run an isolated live GitHub acceptance test. A second reviewed service tests whether the client is actually reusable. Candidate services such as Notion or Slack require their own permission mapping and server suitability review; this document does not claim they are already supported.

Keep the new route opt-in and preserve the current Drive executor and its regression suite. Roll back by disabling the new route and revoking its grants/connections. Never fall back from a denied MCP request to a broader connector or shared credential. Existing Google live-release gates remain unchanged.

Success means the GitHub API implementation is reused, the same client operates two fixture service servers without provider branches, and the owner/agent/resource/expiry/revocation checks still hold under failure. Record custom code added/avoided, setup steps, runtime resources, supported operations and limitations before expanding the provider list. No multi-user or production-readiness claim follows from a single-owner local demonstration.

## Primary references

Reviewed on 2026-10-18; pin actual versions and recheck these evolving interfaces in the feasibility task.

- [Docker MCP Gateway](https://docs.docker.com/ai/mcp-catalog-and-toolkit/mcp-gateway/) and [open-source implementation](https://github.com/docker/mcp-gateway).
- [Docker MCP Toolkit setup and OAuth](https://docs.docker.com/ai/mcp-catalog-and-toolkit/toolkit/).
- [Docker profiles and shared OAuth credentials](https://docs.docker.com/ai/mcp-catalog-and-toolkit/profiles/).
- [GitHub Official catalog entry](https://hub.docker.com/mcp/server/github-official/overview) and [GitHub MCP server tools/configuration](https://github.com/github/github-mcp-server).
- [Docker MCP policy reference](https://docs.docker.com/ai/sandboxes/governance/reference/mcp-policy/) and [confirmation trust model](https://docs.docker.com/ai/sandboxes/governance/access-controls/mcp/).
- [Docker organization governance scope and availability](https://docs.docker.com/ai/sandboxes/governance/).
