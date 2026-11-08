# Optional Keycloak broker with verified account continuity

User-selected architecture: Toolbox trusts one Keycloak OIDC realm; Keycloak
authenticates people through the existing Okta tenant or Google Workspace. The
existing direct-Okta runtime remains the default. The user explicitly chose to
preserve existing Toolbox accounts and grants through verified identity linking.

## Scope and decisions

- Add `TOOLBOX_IDENTITY_PROVIDER=okta|keycloak`, default `okta`.
- Reuse the strict owner OIDC authorization-code/PKCE implementation.
- Add a separate Keycloak MCP access-token verifier. Its issuer is exactly the
  owner realm, audience exactly the Toolbox MCP resource, user ID is `sub`,
  client ID is `azp`, token type is `Bearer`, and `scope` includes `mcp`.
- Preserve all existing Okta token and issuer checks in the default backend.
- Add immutable, unique identity aliases pointing to existing internal owners.
  An alias never changes a user's primary issuer/subject or reassigns ownership.
- Provide a trusted operator migration command with dry-run as its default.
  It verifies each legacy owner's exact Okta subject against Keycloak's Admin
  API federated-identity record for a pinned Okta provider and realm. It never
  matches users by email, mutable usernames, or Google claims. Apply is explicit,
  atomic, audited, idempotent, and rejects collisions/stale ownership.
- Resolve owner login and approved MCP caller identity through primary identities
  or verified aliases. Existing records retain their internal owner/agent IDs.
- A changed agent issuer/client requires fresh caller approval. Existing caller
  approvals are not silently reassigned to another issuer.
- Generate a private realm-import file: confidential owner client, allowlisted
  public MCP clients with exact redirects and S256 PKCE, optional Okta and Google
  providers, no password grants or service accounts for application clients.
- Keep upstream identities distinct even when emails match. Disable automatic
  account linking and use provider-prefixed usernames; Google Workspace access
  requires an explicitly configured hosted domain.

## Alternatives considered

The discussion considered direct provider integrations, retaining Okta as a
broker, and self-hosted Keycloak. The user selected Keycloak. Starting a fresh
identity namespace is simpler but was rejected because existing Toolbox data
must remain accessible. Copying upstream IDs from editable claims or matching
email addresses was rejected because it can transfer another owner's grants.
The operator-verified alias migration is the implementation choice for this PR;
it avoids introducing a general self-service account-merging UI.

## Deployment and trust

Keycloak and its identity-provider configuration are trusted authentication
infrastructure. Migration uses a temporary least-privilege read-only Keycloak
Admin API client over verified TLS. Credentials and generated realm files are
private, never committed or printed. Runtime flags remain loopback-only as on
main. Keycloak production deployment/HA is documented separately from the local
demo. No fixture endpoints or insecure TLS switches enter hosted configuration.

Existing users must first establish their Okta federation in Keycloak. Run the
dry-run and verified migration before switching Toolbox's configured issuer.
Old login sessions expire/re-authenticate; connections, agents and resource
grants stay attached to the same internal owner. Rollback to direct Okta keeps
the primary identity intact. Existing agent clients need Keycloak registration
and a fresh caller approval after cutover.

## Validation

Use the real pinned Keycloak image with two controlled OIDC upstreams to prove
brokering, stable repeat login, same-email separation, verified account linking,
MCP approval/read/revocation and denial cases. This is not live Okta or Google
acceptance. Provide exact external tenant setup and acceptance instructions.
Run the whole race suite, real PostgreSQL/OpenBao integration checks and browser
acceptance. Record sanitized evidence and remaining live-provider limits in PR
comments. New GitHub PR targets main and stays unmerged.

## Follow-ups

mTLS, IAP, general multi-tenancy, automatic cross-provider account linking, and
production hosting are separate work. Google login does not grant Drive access;
the existing independent Google consent/Picker/token boundary remains intact.
