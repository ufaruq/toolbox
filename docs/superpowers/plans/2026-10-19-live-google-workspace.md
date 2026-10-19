# Live Google Workspace implementation plan

> **For agentic workers:** Use the execution, TDD and verification skills task by task. The user authorized implementation; keep the new PR draft until real acceptance passes.

**Goal:** Connect a real Workspace account and demonstrate exact-document agent approval/read/revocation in the local app.

**Architecture:** Compose the existing owner-login, OAuth, token manager, Drive executor and grant engine in explicit `workspace-local` mode. Add a narrow owner-only Picker credential boundary and a focused connector UI; retain both existing modes.

**Tech stack:** Go 1.27.2, PostgreSQL 17.11, OpenBao 2.4.1, existing OIDC/OAuth libraries, Google Picker, vanilla browser UI and Chromium acceptance.

**Spec:** [Live Google Workspace design](../specs/2026-10-19-live-google-workspace-design.md).

## Constraints and review focus

- Loopback only, explicit configuration, no fixture fallback, no provider credentials in logs/agent responses/browser storage.
- Keep owner and provider accounts independent by default; corporate matching requires a trusted resolver.
- Recheck owner/session/connection at Picker release, callback activation and final document release.
- Preserve cleanup for known rejected or uncertain provider outcomes and the actual-client PKCE gate.
- Distinguish synthetic verification, real provider acceptance and future MCP/public deployment work.

## Tasks

- [ ] **1. Runtime composition.** Add failing configuration and route-isolation tests in `cmd/toolbox/config_test.go` and `internal/server/auth_test.go`; implement explicit live config, separate crypto inputs and combined verified-owner/tool routes in `config.go`, `main.go`/`workspace.go`, `server.go`, `auth.go`, `owner.go`. Verify both existing modes and startup failures.
- [ ] **2. Google contract and callbacks.** Add signed-response tests for an explicitly independent email-scoped service, documented email scope normalization, denial/replay/known callback fields and credential cleanup. Implement the narrow additions in `internal/oauth/{google,service,linking}.go` and `internal/server/owner.go`; preserve old defaults. Supply a live PKCE probe and exact configuration instructions.
- [ ] **3. Owner-only document selection.** Test cross-owner/session/connection denial and no refresh-token exposure. Extend token lease expiry and add the optional Picker integration/owner endpoints with real provider construction. Reuse the fixed Drive plans and existing resource/grant checks.
- [ ] **4. Connector product flow.** Implement the connector/connect/policy/document/request UI in separate workspace assets. Keep the supported policy explicit and put agent test controls/expiry under Advanced. Add browser acceptance using controlled signed providers and Picker, including cancellation, denied requests, revocation and disconnect.
- [ ] **5. Real acceptance.** Configure the user's test project/client privately, run the actual-client PKCE/scope gate, then run consent/Picker/read/deny/revoke/disconnect/restart with a real Workspace document. Record revision-specific sanitized evidence. Run independent review, full local/container checks and CI. Keep unperformed gates visible; move out of draft only after live acceptance passes.
