# Provider and runtime setup

[Overview](../../README.md) · [Architecture](../architecture/README.md) · [Development](../development/README.md)

The supported executable modes are local and loopback-bound. These guides do not constitute a public production deployment recipe.

| Task | Guide |
| --- | --- |
| Direct Okta owner login | [Okta setup](../okta-setup.md) |
| Keycloak with Google/Okta and verified migration | [Keycloak setup](../keycloak-setup.md) |
| Google API credentials and optional corporate account policy | [Google setup](../google-setup.md) |
| Real Google consent, Picker and document flow | [Workspace demo](../workspace-demo.md) |
| Inbound MCP caller configuration | [MCP setup](../mcp-setup.md) |
| GitHub App and scoped repository connector | [Runtime and approval setup](../github-connector.md) · [App registration](../../github-app/README.md) |
| Outbound Docker MCP isolation pilot | [Gateway pilot](../mcp-gateway-pilot.md) |
| PostgreSQL/OpenBao guarantees and tests | [Storage](../storage.md) |

Use the placeholder [.env.example](../../.env.example) to understand settings; keep actual secrets outside version control. A Google login client and a Google Drive authorization client have different purposes. Changing a broker does not automatically migrate existing accounts or change existing realms: follow the relevant migration/cutover procedure and verify owner continuity.
