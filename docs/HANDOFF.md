# Toolbox handoff

Read [implementation status](implementation-status.md) for verification evidence and [ROADMAP.md](ROADMAP.md) for the current backlog. The roadmap is the single pending-work list; the [historical ledger](history/implementation-checkpoints.md) preserves earlier failures and limitations without making them current tasks.

## Baseline and branch state

The reviewed application checkpoint is `f6e9c7cbb0aaeed07ee9eaaf84a70fa9246a8536` on `feat/user-delegated-drive-mvp`, [PR #2](https://github.com/ufaruq/toolbox/pull/2). The user marked that PR ready for review; preserve its current status. [Design PR #1](https://github.com/ufaruq/toolbox/pull/1) has merged. This documentation follow-up is based on PR #2 and adds no application behavior.

At that checkpoint, the refresh/disconnect regression and all six later review findings were fixed. The recorded local checks and hosted CI passed; see the status page for exact scope. GitHub API access was blocked in the working environment, so the code fixes did not reply to or resolve review threads. Check remote state before treating a recorded PR status as current.

## What can run today

The Go fixture service provides separate owner/agent authentication, an approval UI, exact-document grants, short-lived tokens, live authorization, revocation, disconnect and audit. It can use actual local PostgreSQL/OpenBao. Google OAuth/Drive adapters are implemented as libraries; the executable uses simulated owner identity and Google, ephemeral signing keys and credential pepper, and loopback binding.

Follow the [README](../README.md#run-the-local-fixture) to run it and the [browser instructions](../tests/browser/README.md) to verify the UI. Use fresh disposable fixture state: provider state and fixture cryptographic material do not survive process restarts. Existing database records do not make old fixture connections usable.

## Continue the work

1. Inspect the checkout, branch and existing changes before editing. Preserve user work and review history.
2. Read the roadmap's [milestone dependencies](ROADMAP.md#milestones-and-dependencies). Start production identity work at M1; the isolated M2 Google protocol/configuration spike can run independently. The complete live flow requires both.
3. Use [Google setup](google-setup.md) and [storage](storage.md) as technical constraints. Do not repeat fixed lifecycle bugs or completed fixture browser/CI setup as pending work.
4. Scope each implementation PR to a roadmap deliverable and its acceptance checks. Keep optional MCP/client or additional-provider work distinct from the initial pilot gates.
5. Update the roadmap, current verification evidence and this entry point when a milestone changes. Record passed, failed, blocked and unrun checks against the tested revision; maintain a separate record for fixture and live-provider results.

No live Google account/app provisioning, production human OIDC acceptance, hosted pilot, merge or deployment is evidenced by the fixture checkpoint. Production operation still depends on M1–M3; larger workloads and multiple replicas need the applicable M4 work.
