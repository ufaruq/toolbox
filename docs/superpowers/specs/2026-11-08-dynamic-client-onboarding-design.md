# Dynamic MCP clients with dashboard approval

Status: proposed; not implemented. Based on `715d7bf` from `origin/main`.

## Intent and agreed boundaries

Allow compatible MCP applications to obtain OAuth registrations automatically.
New callers remain Pending, with no tool permissions, until a human signs into
the existing Toolbox dashboard, configures their permissions, and approves them.
Registration, MCP user login, owner dashboard login, and document grants remain
separate authorization boundaries. An MCP credential cannot approve itself or
increase its permissions.

The user prefers dashboard-managed admission over editing a static client list
for every new application. Reuse the existing caller approval panel and API;
do not introduce a second permission administration interface.

## Approval scope

The user selected per-owner approval for this version. The existing dashboard
is owner-scoped: each owner manages callers for their own account. It has no
global administrator role. Reuse this boundary: no owner can view or approve
another owner's candidates, and approving a client for one owner does not
approve it for anyone else. Central administration is outside this change.

## Approaches considered

1. Keep manual Keycloak registration and the deployment allowlist. This is the
   current behavior and preserves explicit admission, but does not reduce setup.
2. Automate registration, but require adding each new ID to deployment config.
   This reduces one setup step while retaining the operational bottleneck.
3. Automate registration and place verified new callers in the dashboard for
   explicit approval. This is the user's selected workflow. The policy is still
   human-controlled; pending records do not confer access.

## Current code and constraints

- `internal/identity/keycloak.go` verifies signature, exact issuer/audience,
  `azp`, user subject, token type, session, scope, and expiry. It also rejects
  clients absent from the configured map before returning verified claims.
- `internal/server/agent_auth.go` resolves a caller using verified issuer,
  subject, and client ID, and requires an active approved profile. Grant checks
  recheck live profile and agent state.
- `internal/server/callers.go` exposes owner-session-protected list, approve,
  enable, disable, and rename operations. Mutations require Origin and CSRF
  validation. Create/enable also consult the configured client map.
- `internal/server/web/workspace.js` renders the existing permissions panel.
  It currently lists configured clients and approved/disabled/expired profiles.
- `caller_profiles` only permits active/disabled rows, with an Agent and nonzero
  approval/expiry timestamps. Do not weaken this approved-profile invariant to
  accommodate unapproved candidates.
- Keycloak realm generation currently creates explicit client registrations.
  Runtime support is local-only; this change does not add hosted deployment.

## Proposed owner-scoped flow

1. An operator explicitly enables dynamic onboarding for the pinned Keycloak
   realm and configures restricted OIDC dynamic registration there. Existing
   static registrations continue to work. Direct Okta behavior stays static in
   this initial change.
2. A compatible MCP application discovers Keycloak's registration endpoint and
   obtains its own registration. Registration is not Toolbox permission.
3. The application runs authorization-code/S256 PKCE login for the user and
   obtains a token for the exact Toolbox MCP audience and `mcp` scope.
4. On its first authenticated MCP attempt, Toolbox validates that token fully.
   In onboarding mode, a previously unknown eligible client can produce only a
   pending candidate. It cannot dispatch a tool, create an active Agent, grant
   itself access, or obtain owner management authority.
5. Resolve the verified realm subject to an existing active Toolbox owner using
   the existing identity binding. Never accept a caller-supplied owner ID or
   email match. If no owner exists yet, deny and direct the human to sign into
   the Toolbox dashboard first, then retry the connection.
6. The owner sees the pending client in the existing dashboard. Show its exact
   client ID and issuer, when first seen, and an explicit statement that no
   permissions have been granted. The owner sets a label, tool ceiling, and
   duration, then explicitly approves or rejects it.
7. Approval atomically creates the existing Agent/CallerProfile binding and
   consumes the candidate. Subsequent requests resolve the active profile.
   Document access still requires the existing separate document grant flow.
8. Disable/revoke, expiry, and permission updates retain the existing live checks
   and grant invalidation behavior. A retry or new token must never reactivate
   a disabled profile or turn it into a new pending application automatically.

The pending row appears after a verified user login and connection attempt, not
anonymous OAuth registration alone. Before login, a registration cannot be
safely assigned to a particular owner's dashboard. This is explicitly not an
inventory of all registrations in the Keycloak realm.

## Data and authentication changes

Add a separate owner-scoped candidate record/table with immutable issuer,
subject, client ID, resolved owner ID, ID, first-seen time, and decision state.
Use an additive migration and equivalent memory/PostgreSQL validation. Deduplicate
by verified identity tuple. Rejected candidates retain a bounded decision record
so routine retries do not reset the decision; an owner can deliberately reopen
review. Candidates contain no tokens, credentials, or grants.

Separate token verification from admission explicitly in the API. Verification
must still reject wrong issuers/audiences, invalid signatures, missing user
claims, expired tokens, owner-login client IDs, reserved administrative clients,
and client-credentials tokens. Onboarding is opt-in, Keycloak-only, and cannot
turn the ordinary verifier into an unrestricted authorization success path.
Only configured clients or explicitly approved database bindings can execute.

Extend the existing owner-authenticated caller endpoints to expose and decide
candidates. Client-controlled requests can only propose a candidate derived from
verified claims. Approval inputs must not allow identity/owner rebinding. A
candidate must belong to the session owner and remain pending at commit time.
Approval/rejection races and repeated requests must have deterministic outcomes.

Do not authenticate owner routes using MCP bearer tokens. Existing owner session,
CSRF, Origin, and owner-scope checks remain mandatory. A shared upstream SSO
session may simplify human login, but it does not replace the distinct Toolbox
owner session or the explicit approval action.

Display client-supplied names only as unverified labels, if displayed at all.
Use verified issuer/client ID for identity; use the human's chosen Agent name
for local organization. Do not fetch client-supplied URLs or treat a name such
as “Claude” as vendor verification. Do not add automatic broad permissions.

## Keycloak configuration and abuse limits

Use Keycloak's OIDC registration endpoint; do not create a new OAuth authorization
server in Toolbox. The proposed bootstrap is opt-in anonymous OAuth client
creation under operator-controlled registration policies and quotas. It does not
require handing an initial access token to each application. Anonymous creation
only registers OAuth metadata; it cannot add an owner dashboard candidate until
the client presents a fully verified user token, and cannot approve that
candidate. This choice supports the selected automatic onboarding experience;
initial-access-token registration remains a possible future deployment option.

Registration policy must constrain callback URLs, flows,
scope assignment, and client metadata changes, require S256 PKCE, and prevent
clients from selecting owner/admin privileges or arbitrary protocol mappers.
The server-controlled `mcp` scope supplies the exact Toolbox audience; applicants
must not control the subject, issuer, audience, or client-ID claims.

The pinned Keycloak release must be tested for registration and registration-token
updates as well as initial creation. Preserve restricted defaults and require
explicit operator opt-in. Registration quotas and rate limits apply even though
Toolbox approval is separate. Toolbox also bounds per-owner candidate counts,
request frequency, strings, and total retained rows. Invalid or unauthenticated
requests cannot populate the queue; repeated valid requests are idempotent.

Concrete config names, quota values, additive API fields, and compatible policy
encoding are implementation choices, to be verified against the pinned image.
If built-in policies cannot enforce the required boundaries, stop and report the
specific gap rather than enable permissive registration.

## Validation and rollout

- A dynamically registered client can log in and become Pending, but no MCP tool
  executes before dashboard approval.
- MCP bearer tokens, cross-owner sessions, missing CSRF, and cross-site mutation
  attempts cannot approve, enable, relabel, or change permissions.
- The owner can approve with explicit tools/expiry; an approved profile can request
  a document but cannot read it until the separate grant is approved.
- Two clients and two owners remain isolated across candidate lists, approvals,
  document requests, grants, and audit attribution.
- Reject, disable, expire, reconnect, and concurrent approval/revocation cannot
  restore access or bypass final dispatch/release checks.
- Invalid token claims and reserved clients cannot even create candidates.
- Static mode and existing caller profiles retain their behavior after migration;
  turning onboarding off denies dynamically admitted clients unless explicitly
  configured for the static mode. Document this rollback behavior.
- Browser coverage verifies Pending → configure → approve and reject flows in
  the existing panel. Real disposable Keycloak tests verify registration, token
  shape, PKCE, metadata-update restrictions, and the complete permission flow.
- Run focused tests while building, then the full repository `scripts/test-all`
  gate before pushing. Live-provider/client compatibility is reported separately.

No live Keycloak configuration is changed by writing this design or implementing
repository support. Deployment enablement is an explicit later operation.

## Primary references

- [Keycloak client registration](https://www.keycloak.org/securing-apps/client-registration):
  OIDC registration, initial/registration tokens, and registration policy controls.
- [MCP authorization and client registration](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization):
  authorization-server discovery and supported client-registration mechanisms.
