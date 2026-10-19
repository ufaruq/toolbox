# MVP delivery and PR boundaries

The immediate goal is a real agent client calling scoped Google tools after the
owner signs in with Okta and connects Google. A browser test console alone does
not complete that goal. The first tool can remain the existing approved Google
Doc read while the reusable policy model and write tools are added separately.

The broader product must support reusable read and write policies: allow all,
allowlist, or all except a blocklist, with document-level selection available as
an option. Exact-document grants are the current working slice, not the intended
product's permanent limit.

## Delivery order

| PR / work | Scope | Completion gate |
|---|---|---|
| #5 — owner identity | Real Okta owner login/session lifecycle. Already merged. | Existing live one-user verification and automated identity/session tests; retain the recorded second-user limitation. |
| #6 — optional corporate matching | Opt-in exact-person Google account matching and fixture session/UI fixes. Ready for review/merge; it does not provide live Google wiring. | Its existing checks and review. #10 currently includes its branch history. |
| #10 — real Google tool foundation | Verified owner session plus real Google connection/Picker, exact-document approval/read, revocation and persistent local stores. | Real Google Picker and document read/denial/revoke/disconnect/restart acceptance, plus CI. The actual-client PKCE/scope check has passed. |
| #7 — first real MCP agent client | Integrate Streamable HTTP MCP and approved per-client identity with the shared owner/Google runtime and permission engine. | A real selected client discovers the tool, requests access, receives owner approval and reads an actual Google Doc. Other-document/other-client denial, revocation and disabled-client denial must pass. |
| New policy PR — reusable permissions | Persisted policies with independent read/write resource rules, agent assignments, policy UI, versioning and live evaluation. Extend the read path first; do not display unsupported write capabilities as usable. | All/allowlist/blocklist cases, conflicting deny rules, agent/owner isolation, changes during a call, token invalidation and old-grant compatibility. |
| New write PR — actual edits | Named write operations, provider adapter/API scopes, bounded inputs, revision/conflict handling, audit and recovery for uncertain outcomes. | Real edit and denied-edit cases under each supported policy. Deletion/sharing require their own explicit actions rather than an implicit interpretation of “write.” |
| #4 — deployment | Portable Docker deployment, GCP/Terraform, durable crypto/secrets, storage permissions and operations. | Integration conflicts and failing deployment CI resolved, then the deployment/backup/recovery gates. Needed before a public hosted client demo. |

## First client demonstration

The client choice is pending: the user was asked to choose the existing Claude
Code path, Codex, or a hosted Claude.ai custom connector. A local client can be
tested without first provisioning a cloud VM. A hosted connector needs a reachable
HTTPS endpoint and its separately configured OAuth registration.

The user should be able to:

1. Sign in as the owner with Okta and connect the actual Google Workspace account.
2. Approve one registered client/agent with an explicit tool ceiling and lifetime.
3. Ask that client to request a Google document read. The client presents the
   trusted owner approval link and handles a pending/denied request correctly.
4. Approve the resource in the owner UI. The client obtains the document through
   Toolbox's tool API/MCP adapter, with Google credentials remaining server-side.
5. Demonstrate another document's denial, revoke access and confirm another call
   fails. Disabling one client must not grant it another client's permissions.

Owner login is management authentication; it is not by itself an agent credential
or a grant. The agent authenticates independently, and every tool call still
passes the shared authorization and provider boundary. MCP is a transport for
those calls, not a separate permissions implementation.

## #7 integration work still required

The current #7 head predates the merged owner login and #10. It conflicts with
current main and explicitly installs an unavailable Google provider. Its existing
synthetic SDK tests therefore do not prove a live Google client demo.

- Rebase/integrate the shared owner login, migrations, session/revocation behavior,
  Google runtime and token manager without replacing them with the older duplicate
  owner-auth implementation.
- Reconcile the existing organization-issuer owner identity with #7's custom Okta
  authorization-server `uid`/`cid` access-token/profile model. Preserve owner and
  Google-connection ownership; never infer that binding from an unverified email.
- Reuse the same Google adapter and grant checks for MCP and HTTP.
- Verify the chosen client's actual callback, scopes, audience and supported
  transport/authentication. Start with one real client, then add the others.
- Keep synthetic SDK coverage, and add real-client/live-provider acceptance before
  reporting the integration ready for merge.

## Policy expansion: impact and boundaries

This is a permissions-layer extension. Today the persisted request/grant, signed
delegation token, fixed read manifest and invocation checks each bind one exact
file ID. New reusable policies must change all those relevant boundaries together;
adding dropdown options alone would not enforce the requested behavior.

The proposed owner controls are independent read and write rules, each allowing
none, all, an allowlist or all except a blocklist. Assign policies to selected
agents/clients rather than automatically authorizing every authenticated client.
An explicit deny takes precedence; effective rights cannot exceed either the
owner's policy or Google's permission for the connected account. A one-document
approval remains a valid narrow option. Rules must also govern listing/search
and metadata tools if those are introduced.

The current `drive.file` grant covers app-authorized selected files. All-Drive
modes in the current Drive-based connector need a reviewed broader OAuth scope
profile and fresh consent; no policy toggle may silently widen the provider grant.
Changes to scope profiles require refreshed exact-scope/PKCE acceptance. Native
Google Docs are the current supported format; Sheets, PDFs and other formats need
their own supported operations.

Before implementing writes, define which edits are supported, how “all” treats
shared/current/future files, and whether folders and their descendants participate
in resource rules. Keep these design decisions separate from finishing the first
read-only client demonstration.

Sources: [Google Drive scopes](https://developers.google.com/workspace/drive/api/guides/api-specific-auth),
[Google Docs batch updates](https://developers.google.com/workspace/docs/api/reference/rest/v1/documents/batchUpdate).
Live evidence: [Workspace verification](workspace-verification.md).
