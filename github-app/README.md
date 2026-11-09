# Toolbox GitHub App

Status: registration scaffolding for the expanded GitHub MCP connector. Creating
this App does not enable GitHub operations in Toolbox yet. The existing runtime
only has the isolated outbound MCP pilot; grants, UI, token rotation and write
policies still need implementation and acceptance.

## Register and install

Run from the repository root:

```sh
make github-app-setup
```

Open the printed URL in a browser signed into the `ufaruq` account. It preselects
[registration.json](registration.json). GitHub App names are globally unique; if
the suggested name is taken, choose a distinct name on the form.

- Contents: read/write for file updates, task branches and commits.
- Pull requests: read/write for creating and managing PRs.
- Issues: read/write for issue operations and PR conversation comments.
- Metadata: read-only; Actions and Checks: read-only for CI inspection.
- No administration, secrets or workflow write permission.
- Private App for the account-owned pilot. Other owners cannot install it until
  its visibility is explicitly changed and multi-owner onboarding is validated.
- Webhooks disabled until a verified receiver exists. No fabricated webhook or
  OAuth callback endpoint is configured by this initial registration.

Create the App and generate a private key from its settings when GitHub prompts
you to do so. Then install it on **Only select repositories** and choose the repositories you
want available for future Toolbox connections, including `ufaruq/toolbox`.
Keep those selections: Toolbox independently authorizes every agent operation.
Record its App ID, client ID, slug and installation ID. Store the download in an operator-controlled private directory
outside tracked source (for local development, an ignored `work/` directory is
acceptable). Restrict the directory to mode 0700 and key to 0600. Never paste the
key into chat, commit it, or expose it to an agent. `.gitignore` is a convenience,
not secret storage or protection against force-adding files.

Registration and installation require GitHub account authentication. A local
subfolder cannot create an installed GitHub App by itself. The helper only prints
a URL; it creates no GitHub resource and reads or writes no secrets.

## Intended credential lifecycle

A protected service signs a short-lived App JWT and requests an installation token
for an explicit repository ID and permission subset. Installation tokens expire
after one hour; Toolbox applies its own shorter grants and live revocation checks.
The gateway/server receives only that installation token. Agents receive scoped
Toolbox authorization and never receive the GitHub token or App key.

App registration permissions are the maximum possible authority, not automatic
agent approval. Branch/path controls, protected-branch handling, merge approval,
concurrency checks and all other operation policies remain Toolbox obligations.
Token refresh must replace isolated downstream credential contexts; merely
writing a new secret file is not proof that running servers use the new token.

For the account-owned pilot, independently verify the authenticated App and its
installation with GitHub before issuing any token. Future multi-owner onboarding
must bind installation ownership to the authenticated connecting GitHub user;
never trust a callback's installation ID as ownership proof.

See the [expanded design](../docs/superpowers/specs/2026-11-08-github-mcp-operations.md)
and [current pilot limits](../docs/mcp-gateway-pilot.md). Live calls and token
rotation are not yet validated by this registration scaffolding.

## References

- [GitHub registration URL parameters](https://docs.github.com/en/apps/sharing-github-apps/registering-a-github-app-using-url-parameters)
- [Installation token issuance](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app)

## Live setup status

The AI Toolbox App is registered and installed on `ufaruq/toolbox`. Short-lived
token issuance and revocation were verified. A live negative probe showed that
the token could also read an unselected public repository; selected-repository
token scope alone does not enforce exclusive read access. See the [acceptance
record](../docs/experiments/github-app-live-acceptance.md) before enabling any
connector operation. No MCP operation is enabled by this registration alone.
