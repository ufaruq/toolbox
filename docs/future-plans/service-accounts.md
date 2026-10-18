# Service accounts and autonomous remote agents

**Status:** Proposal for discussion. Service-account support is not implemented
by this document. Authentication, organization ownership, downstream identity
boundaries, and rollout remain open decisions.

[Future plans](README.md) · [Project](../../README.md)

## Purpose

Support remote agents in two authorization modes:

| Mode | Whose authority is used? | Who authorizes it? |
| --- | --- | --- |
| User-delegated agent | A user's authority, narrowed by an explicit delegation to the agent | The user, within applicable organization policy |
| Autonomous service | A service principal's own explicit Toolbox grants | An authorized organization administrator or service owner, under a defined administrative policy |

Autonomous execution should work without an active human session. Initial
provisioning and grants still require an accountable administrator. Creating a
service must not give it the creator's permissions automatically.

One remote application could support both modes, but the authority used for a
request must be explicit. An unattended process using a user's OAuth grant still
has that user's downstream consent and account dependencies.

## Existing model and required changes

The implementation on `main` separates owner sessions, agent credentials,
user-owned provider connections, and exact-document grants. Its runnable
executable uses fixture identity and Google; real provider adapters are library
components. Agents already have independent credentials, but their ownership and
grants remain tied to a human owner. That is not yet an organization-owned
service-account model.

Related work includes [owner Okta sign-in](https://github.com/ufaruq/toolbox/pull/5)
and [hosted MCP with per-client permissions](https://github.com/ufaruq/toolbox/pull/7).
Those are separate proposals/implementation branches, not evidence that this
service-account flow is available. MCP or another transport does not itself
establish a service's authority.

The extension needs service-principal lifecycle management, trusted workload
authentication, service grants, and explicit ownership of connections that
outlive an individual user. Current `OwnerID` constraints and storage migrations
need a reviewed organization/administration model before implementation. Preserve
existing user ownership and exact-resource grants throughout that migration.

## Proposed identity and execution model

Keep three separate concepts:

1. **Toolbox service principal:** the identity receiving grants, scoped to one
   customer organization, with a stable ID, owner, status, and lifecycle.
2. **Workload authentication:** proof that the caller may act as that principal.
   Candidates include Okta machine-to-machine OAuth or a trusted cloud workload
   issuer. The issuer, token audience, client authentication method, identity
   claims, and principal mapping require an explicit decision. An OAuth client
   registration alone does not grant Toolbox permissions.
3. **Downstream connection:** the approved account, app installation, or other
   provider authorization and its secret reference. It can be shared by several
   Toolbox principals or dedicated to a particular purpose.

An administrator provisions the principal and grants. At runtime, the service
authenticates with a token intended for Toolbox. Toolbox verifies the trusted
issuer, signature, audience, lifetime, and identity-to-principal mapping. It then
checks current principal status and grants for the specific tool, operation,
resource, and connection, and executes the permitted provider call.

Incoming Toolbox tokens and downstream credentials are separate. Provider
credentials stay within the credential broker/executor boundary; remote services
receive results. Possession of a service credential or a connection ID must not
grant access to an unapproved operation, resource, or organization.

Effective access requires both a Toolbox grant and sufficient downstream
permissions. The downstream credential may be broader than a Toolbox grant;
Toolbox must still enforce the narrower grant on every execution. Preserve fixed
tool contracts and validated resource bindings rather than introduce an arbitrary
authenticated HTTP proxy.

## Shared versus separate downstream identities

There is no requirement for one downstream account per agent. A shared downstream
identity within a customer organization is a valid option when Toolbox mediates
all calls and keeps its credentials private. A compromised service remains
limited by its Toolbox grants while that enforcement holds.

Identity sharing and credential scope are separate decisions. One identity can
sometimes issue multiple short-lived tokens with different provider-enforced
permissions. Two API keys belonging to the same account may still represent the
same identity and have identical authority.

| Consideration | Shared downstream identity | Separate downstream identities |
| --- | --- | --- |
| Operations | Fewer installations, consents, accounts, and rotations | More provisioning, configuration, and opportunities for drift |
| Enforcement | A broad shared credential relies on Toolbox for narrower service permissions | Distinct, restricted grants can add provider-side enforcement |
| Attribution | Toolbox identifies callers; provider records may show one shared actor | Provider records can distinguish identities, depending on authentication mode |
| Revocation | Toolbox can disable one service; revoking a shared provider grant affects all its consumers | Provider access can be revoked independently |
| Credential exposure | A leaked broad credential exposes all authority it carries | A leaked restricted credential exposes less authority |

For example, a repository indexer should only read. If Toolbox accidentally
forwards a write using a shared write-capable credential, the provider can accept
it. The same request made with a read-only provider token is rejected. Audit logs
help investigate the mistake; they do not provide that additional enforcement.

Separate identities only provide this permission boundary when their grants are
actually restricted and the appropriate credential is used. If a fully
compromised Toolbox process can access every credential, it can select a stronger
one. Stronger containment also needs restricted credential access or isolated
execution components; multiplying equally privileged accounts does not supply it.

**Proposed starting direction, still open for discussion:** allow shared
connections per customer organization and provider, narrow execution tokens where
supported, and split connections at meaningful permission or operational
boundaries. Document reading, sensitive mailbox access, directory administration,
and production deployment may warrant different boundaries. Do not make a
provider-wide administrator identity or a dedicated identity per agent mandatory.

## Provider examples and limits

### Google Workspace

A Google service account does not automatically have access to all Workspace
data. Specific files can be shared directly with it. Access to user data through
domain-wide delegation instead uses authorized scopes and user impersonation.
The provider identity may therefore be an impersonated user rather than a single
visible Toolbox bot. See [Google's credential guidance](https://developers.google.com/workspace/guides/create-credentials).

Domain-wide delegation scopes restrict the types of data/actions, not which users
the service account may impersonate. Giving two service accounts the same
delegation scopes does not isolate them to different users. A single broad
delegated service account therefore concentrates significant authority. Consider
direct resource sharing or user OAuth where suitable, and explicitly decide
scope and impersonation controls before adopting delegation. See
[Google's delegation best practices](https://knowledge.workspace.google.com/admin/apps/domain-wide-delegation-best-practices).

### GitHub

A shared GitHub App can generate installation access tokens restricted to selected
repositories and permissions, within the installation's approved access. These
tokens expire after one hour. This permits a shared app identity with narrower
credentials for read and write execution; separate app identities are optional.
The app's token-issuing authority remains privileged even when individual tokens
are narrow. See [GitHub's installation-token documentation](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app).

These are design examples, not implemented connectors or live acceptance results.
They do not expand the existing Google document-read contract.

## Lifecycle, revocation, and audit

Service disablement and grant revocation should block new authorization and
execution even while a previously issued authentication token remains valid.
Specify how credential rotation, queued jobs, in-flight calls, retries, and final
result release interact with those changes. Revoking a Toolbox grant, removing a
connection, and revoking the provider credential are distinct operations.

Record the authenticated service principal, authority mode, organization, grant
and policy version, connection, tool/action, resource, invocation correlation, and
outcome. Record the downstream identity or impersonated subject and provider
request identifier where available. Keep tokens, secrets, document contents, and
sensitive raw arguments out of audit records.

Toolbox attribution can distinguish services sharing a provider identity, but it
only covers requests Toolbox observes. Direct use of a leaked provider
credential can bypass both Toolbox authorization and its audit. Retention,
restricted audit writers, independent log export, and correlation with provider
records need an operating policy. A provider-side action with an uncertain
completion must not be recorded as a proven success or automatically replayed if
it could have side effects.

## Suggested delivery sequence

1. Resolve organization ownership and administrative authority, choose the first
   workload authentication method, and document its threat model and trusted
   identity mapping.
2. Define the service-principal lifecycle and service grants, then review the
   additive schema/API changes and compatibility with current user grants.
3. Integrate one autonomous service with the existing execution boundary,
   including live authorization, revocation, credential isolation, and audit.
4. Validate one provider connection model with synthetic resources, then perform
   controlled live acceptance. Cover wrong issuer/audience, expired credentials,
   cross-organization/service/resource denial, revocation with cached tokens,
   shared-connection continuity, and provider credential non-disclosure.
5. Add dedicated connections or stronger execution isolation for selected risk
   boundaries, based on provider capabilities and customer requirements.

This sequence is a discussion outline, not an approved implementation plan.
Transport, identity, and provider rollout work can be scoped separately without
requiring a new downstream identity for every remote agent.

## Decisions to continue discussing

- What owns a service and its connections, and which administrators can create,
  grant, disable, transfer, and delete it?
- Should the first version use Okta machine-to-machine authentication or workload
  federation? What token audience and trusted claims identify a service?
- Which downstream permissions can share a connection, and which need independent
  revocation, provider limits, or isolated credential access?
- For Google, is direct file sharing sufficient, or is domain-wide delegation
  necessary? If delegated, how are impersonated users and scopes constrained?
- Which guarantees must the provider enforce, and which are intentionally
  enforced only by Toolbox? What evidence do customers need beyond Toolbox logs?
- Which service/provider combination should be the first supported slice, and
  what are its grant lifetimes, quotas, retention, and acceptance gates?
