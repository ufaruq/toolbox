# Toolbox handoff

`main` includes Okta owner sign-in, real local Google Workspace document access
and the Okta-authenticated Streamable HTTP MCP interface (PRs #5, #6, #10 and #7).
Use [Workspace setup](workspace-demo.md) and [MCP setup](mcp-setup.md) for the real
account flow; `make workspace` preserves that runtime. Keep local secrets in the
ignored `.env`; do not commit credentials or generated evidence.

PR #4 adds the [portable container and GCP preparation workflow](deployment-docker.md).
It preserves released metadata migrations 001–005 and appends deployment migrations
006 and 007. Upgrades preserve owner IDs, sessions, Google connections and MCP
profiles. Disposable databases made from earlier, unmerged #4 revisions used
conflicting migration numbers; use fresh disposable state for those tests. Do not
rewrite a deployed migration ledger or delete an existing database to make it fit.

The persistent container verification uses synthetic providers, PostgreSQL and an
encrypted SQL credential schema. The real local Workspace runtime continues to use
OpenBao. These are distinct supported entry points; production serving is deliberately
blocked until the real identity/provider runtime is wired into the hosted deployment.
No GCP apply, image publication or public endpoint is part of this update.

[Deployment verification](deployment-verification.md) records the current checks,
including backup/recovery fences for MCP clients and unfinished sign-ins. Broader
allow/block policies, write tools and larger-workload SQL changes remain future work.
The [roadmap](ROADMAP.md) and [historical implementation ledger](history/implementation-checkpoints.md)
retain the larger delivery plan and earlier checkpoints.
