# MCP Service Connectors Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Status:** Proposed future work. All steps are unchecked; this documentation PR executes none of them.

**Goal:** Validate that existing MCP servers reduce provider integration work, then add one opt-in GitHub read action while retaining Toolbox's owner-approved delegation contract.

**Architecture:** A shared outbound MCP client calls reviewed servers directly or through an operator-managed Docker gateway. Provider-specific policy maps an immutable grant to a bounded call; Toolbox retains identity, approval, current-state authorization and final result release.

**Tech Stack:** Existing Go 1.27.2 application, PostgreSQL and current secret-store boundary; official Go MCP SDK where compatible; optional Docker MCP Gateway and GitHub Official server. Task 1 records exact SDK, gateway, protocol and server revisions before implementation depends on them.

**Spec:** [Reusing MCP service connectors with Docker Gateway](../specs/2026-10-18-mcp-service-connectors-design.md).

## Global constraints

- The first pilot supports one reviewed read action; no provider writes, arbitrary tool forwarding or agent-controlled server registration.
- Preserve the existing Drive path, exact-document rights, independent agent identity, trusted owner review and live authorization checks.
- Apply a 20-second total invocation deadline and a 1 MiB application-result limit, including protocol framing/decoding bounds.
- Keep provider credentials, inbound Okta tokens and internal delegation tokens in separate trust contexts. Never pass the latter two to downstream servers.
- Docker profiles are not owner credential isolation. Multi-user operation requires verified owner-to-connection credential binding.
- No automatic call retry after dispatch, silent permission fallback or automatic authorization of discovered tools.
- Reconcile then-merged PR #5/#7 authentication and inbound transport work before implementing server integration. This plan does not merge those branches.

## Review focus

| Failure/input class | Required behavior | Task |
| --- | --- | --- |
| Concurrent owners use the same service; disconnect races a result | Correct credential context for each owner; no result released after invalidation | 1, 3, 4 |
| Tools share names or change schemas; `issue_read` offers multiple methods | Match server plus pinned schema; allow only the reviewed read method | 2, 3 |
| Repository is renamed/transferred, its old locator is reused, or arguments reference another repository | Immutable identity enforced through the upstream read; no authorized cross-repository read or released result | 1, 3, 4 |
| Server streams excessive frames, hangs, errors or asks for client-side actions | Enforce limits/cancellation; deny unsupported callbacks and automatic retries | 2 |
| Agent loses rights during execution; a server returns credentials or linked resources | Recheck before release; filter/reject unsupported result forms; never auto-fetch links | 3, 4 |

## Task 1: Establish the feasibility and credential boundary

**Files:** Create `docs/experiments/mcp-github-feasibility.md` and `work/mcp-github-probe/` for ignored, disposable probe assets. Do not commit credentials or probe state.

**Consumes:** The spec's GitHub issue-read scenario and existing `internal/app/integration.go` credential/execution boundary.

**Produces:** A decision record with exact image digests, gateway/SDK/protocol versions, tool/schema inventory, credential ownership, single-owner limits, direct-MCP comparison and a go/no-go decision. This is a prerequisite for Tasks 2–4, not evidence of a production integration.

- [ ] Inventory the selected GitHub Official server's pinned `issue_read` schema and supported credential method. Verify `method=get`, repository identity lookup/provenance and result fields. Record unsupported requirements explicitly.
- [ ] Prove the upstream read is bound to the approved immutable repository ID through dispatch, using ID-bound execution or provider-enforced credentials restricted to that repository ID. Test rename/transfer, reuse of the old owner/name by a different repository, and identity changes between resolution and dispatch. A preflight lookup plus a broadly credentialed name-based read is insufficient; failure to prevent an authorized read of the replacement repository is **no-go**.
- [ ] Configure one local private gateway/server context with a dedicated test credential. Enable only the needed read tools; keep management/discovery capabilities inaccessible to the agent. Record how credentials enter, refresh and leave that context without committing values.
- [ ] Read one synthetic issue through both the gateway and a direct MCP connection using the same server. Record setup steps, tool inventory, result shape, latency and runtime overhead; write no new GitHub issue REST client.
- [ ] Verify provider-scope limits independently of tool allowlists. Identify whether the selected credential model supports owner-specific connections, cleanup and stable provider account identity.
- [ ] Probe two isolated synthetic-owner contexts and concurrent calls using distinguishable test credentials. Record evidence that no credential, session, refresh or disconnect state crosses contexts. A single installation with different profiles does not satisfy this test.
- [ ] Document gateway/server crash, restart and disconnect outcomes and the minimum isolation topology required. If multi-user isolation remains unproven, mark multi-user use blocked and keep subsequent live work single-owner only.
- [ ] Record **go** only if the read operation, schema, resource provenance and isolated credential route can satisfy the contract. On **no-go**, stop this implementation sequence and document direct MCP or the existing connector as the alternative; do not loosen Toolbox's grants.

**Verify:** Another engineer can reproduce the recorded synthetic issue read with private test credentials, understand all limits and find an explicit pass/fail for each requirement. Record code that would be reused versus code still needed; do not invent a savings percentage.

## Task 2: Implement the shared outbound client against synthetic servers

**Files:** Create `internal/mcpclient/{client.go,transport.go,client_test.go,transport_test.go}` and `internal/testutil/mcpserver/server.go`; modify `go.mod`/`go.sum` only for the selected SDK. Keep this package independent of GitHub, grants and HTTP handlers.

**Interfaces:** Define `Binding` as an immutable, operator-resolved server identity plus pinned inventory/schema revision and isolated credential-context reference. Define `Tool` as an exact name and input-schema description, and `Result` as bounded returned content. The package exposes:

```go
type Client interface {
    ListTools(ctx context.Context, binding Binding) ([]Tool, error)
    CallTool(ctx context.Context, binding Binding, tool string, arguments json.RawMessage) (Result, error)
    Close() error
}
```

`json` is `encoding/json`. The credential-context reference is internal, not raw provider credentials and not agent input. Transport implementations resolve it using the topology accepted in Task 1. Discovery is an operator function; public invocation code receives only approved bindings and calls.

- [ ] Write table-driven tests named `TestClientNegotiation`, `TestClientInventoryPin`, `TestClientBindingIsolation`, `TestClientResultLimits`, `TestClientCancellation`, `TestClientNoRetry`, and `TestClientRejectsCallbacks`. Cover negotiated protocol mismatch, duplicate tool names across servers, schema drift, malformed/error results, excessive framing/chunked output, hanging calls and unsupported server requests.
- [ ] Run `go test ./internal/mcpclient -count=1` and observe the new behavior fail before implementation.
- [ ] Implement the interface through the selected SDK and bounded transport. Apply the total deadline and protocol/result limits before unrestricted allocation. Treat server error results as failures, close invalid sessions and retain connection separation. Do not follow links, accept sampling/elicitation requests or retry a dispatched call.
- [ ] Exercise two different synthetic service schemas through the exact same client implementation. Assert the returned content and recorded calls match each binding, with no provider-specific client branches.
- [ ] Run `go test -race -count=1 ./internal/mcpclient/...` and commit the independently verified client and tests.

**Done when:** Both fixture services work through one implementation and every negative case above fails closed. Live provider accounts are unnecessary for this task.

## Task 3: Add GitHub policy and explicit resource/grant persistence

**Files:** Create `internal/servicepolicy/github/{policy.go,policy_test.go}`. Add resource-aware types/validation to `internal/domain/domain.go`, `internal/store/{memory.go,postgres.go,validate.go}`, and a new numbered SQL migration chosen after rebasing onto merged work. Update scoped token claims/validation in `internal/security/security.go`, request/approval checks in `internal/server/delegation.go` and invocation handling in `internal/server/invoke.go`. Add tests beside those components. Do not rewrite historical migrations.

**Interfaces:** Define a GitHub `ApprovedRead` value containing an immutable `Binding`, owner/agent/connection/grant IDs, stable repository ID, reviewed repository locator, action `github.issue.read`, expiry and connection generation. `BuildIssueRead(approved ApprovedRead, issueNumber int64) (Call, error)` produces the exact pinned tool and constructed arguments using Task 1's verified identity-enforcing route. `ValidateIssueResult(approved ApprovedRead, issueNumber int64, result mcpclient.Result) (Issue, error)` verifies returned repository/issue identity and a bounded text projection; this post-call check does not replace upstream identity enforcement. `Call` and `Issue` are defined in `policy.go`; neither contains credentials.

Use an explicit tagged resource kind (`google_drive.document` or `github.repository`) in new authorization state and token checks. Preserve existing document-grant meanings; new GitHub grants cannot be represented as a Drive `FileID`. Additive migration and legacy compatibility tests must be reviewed before enabling issuance. The external GitHub request schema contains only connection ID, requested repository, issue number and duration; it never accepts raw MCP tool names/arguments or a server URL. Resolve and review stable identity before granting access.

- [ ] Write failing policy tests for the approved repository/read method, unknown arguments/tools, write methods, repository mismatch, renamed/transferred identity, old-locator reuse during dispatch, invalid issue number, malformed/wrong-resource results and schema revision mismatch. Assert invalid caller inputs never reach the MCP client; for concurrent provider identity changes, verify the accepted route prevents an authorized read of a different repository, not merely result release.
- [ ] Write grant/storage/token tests proving cross-owner/agent/resource-kind denial, immutable resource binding, expiry, connection invalidation and unchanged Drive grants. Include real PostgreSQL migration/constraint checks and snapshot validation.
- [ ] Implement the policy adapter and additive domain/storage changes. Require trusted resource resolution/provenance from Task 1's accepted route. Reject incompatible server behavior rather than adding arbitrary API passthrough.
- [ ] Extend trusted approval UI/review data to show provider account, verified agent, repository, read action and expiry. Bind the reviewed request digest to all those values; test stale review and cross-owner attempts.
- [ ] Integrate the policy-built call with existing live checks before dispatch and before release. Apply current credential/grant/connection checks again after network I/O; cancel work and discard results after invalidation. Preserve application-level approval, denial, revocation and result audit.
- [ ] Run the new policy tests, existing authorization/browser regressions and `make check` with the repository's disposable PostgreSQL/secret-store integrations enabled; commit only after they pass.

**Done when:** The opt-in synthetic GitHub read flow enforces the same owner/agent/action/resource/expiry contract as Drive without weakening or replacing Drive behavior.

## Task 4: Wire an opt-in runtime and record live acceptance

**Files:** Modify `internal/app/integration.go` and `cmd/toolbox/{main.go,config.go}` (or their then-merged equivalents); add acceptance tests in `internal/app/mcp_integration_test.go`, placeholder-only configuration in `.env.example`, and `docs/mcp-service-setup.md`. Keep existing default routes unchanged.

**Consumes:** `mcpclient.Client`, the GitHub policy adapter, resource-aware persisted grants and Task 1's verified credential topology. Runtime configuration resolves bindings; agents cannot change endpoints, profiles, images or credential references.

**Produces:** A disabled-by-default service route plus exact operator instructions and sanitized acceptance evidence. If the accepted topology requires multiple gateway/server instances, document their real resource/operational cost rather than assuming one shared profile is sufficient.

- [ ] Write failing runtime tests for missing or conflicting configuration, unreachable/incorrect server identity, inventory drift, direct gateway access, connection mismatch and dependency failure. Enabling a route must not enable arbitrary MCP forwarding.
- [ ] Wire the client and reviewed bindings into execution. Verify the private gateway boundary, connection lifecycle and provider secret ownership. Do not move existing Google credentials or remove token cleanup code.
- [ ] Write exact setup steps for the pinned Docker/server versions, private endpoints, required provider permissions, secret injection, read allowlists, owner approval and cleanup. Keep real tenant values and credentials outside committed files and test artifacts.
- [ ] Run the isolated live GitHub scenario: approved read; other-repository denial; different-agent denial; expiry; grant revocation; disconnect during execution; reconnect requiring fresh approval; server failure; wrong credential context; and absence of secrets in agent responses/logs. Verify actual upstream requests remain scoped, not just that the final UI hides denied results.
- [ ] Repeat the two-owner concurrency/isolation cases before enabling multi-user use. Record multi-user use as blocked if those cases have not passed.
- [ ] Disable the new route, revoke its grants and verify that the existing Drive fixture still operates. This is the rollback acceptance test.
- [ ] Run `make check` and the repository's browser regressions with disposable store integrations. Record commit, image digests, test mode and actual outcomes; separate synthetic tests from live acceptance.

**Done when:** A reproducible opt-in read succeeds with negative cases and rollback evidence. A missing tenant or unsuccessful live probe remains an open acceptance item, not a passing fixture result.

## Task 5: Decide whether expansion is cheaper

**Files:** Update `docs/experiments/mcp-github-feasibility.md` and `docs/mcp-service-setup.md`; propose a separate provider adapter only after this evaluation.

- [ ] Compare the direct-MCP and Docker paths for setup, private credential contexts, server/version maintenance, runtime cost and supported calls. Choose the simpler acceptable topology from measured evidence.
- [ ] Select a second service with a suitable maintained MCP server. Inventory its real tools and credential model; draft its resource/action permission mapping. Keep its provider API implementation external and verify the shared client needs no provider branches.
- [ ] Record which code is reused, which policy and lifecycle code remains, and whether its maintenance cost is lower than a custom connector. If the mapping recreates most of the connector, keep the narrow custom path instead.
- [ ] Propose any removal of existing OAuth/token/connector code separately, with equivalent identity, refresh, revocation, cleanup and final-release evidence. Do not infer equivalence from a successful read.

**Decision:** Expand only when reusable server coverage and the measured setup/maintenance savings justify the runtime and permission-mapping work. Docker is optional; the owner-approved authorization contract is the acceptance criterion.
