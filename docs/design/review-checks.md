# Design review checks

Status as of 18 October 2026. These checks were completed before the initial draft PR. They are recorded here rather than represented as invented earlier commits.

This is a historical design-validation record. PR #2 has since merged application code; use [implementation status](../implementation-status.md) for its checks and the [roadmap](../ROADMAP.md) for the current backlog. The application requirements below are not a current report that all those checks remain unrun.

## Initial draft checks completed

- Reviewed the current official Google Drive, Picker, OAuth and OpenID Connect documentation, OpenBao KV v2 documentation, Go OAuth2 documentation, OPA documentation and OAuth/JWT RFCs linked in the design.
- Confirmed that `drive.file` with Picker is the proposed per-file authorization route, that the scope is not read-only, that `files.export` accepts it, that Google Docs supports `text/plain` export, and that the API export limit is 10 MB.
- Checked that the design separates human identity, agent identity, provider connection and explicit delegation.
- Added the trusted approval flow, short-lived delegation JWT, independent agent authentication, action/resource authorization, connector manifest contract and online versus offline revocation tradeoff.
- Specified refresh coordination and the failure windows across Google, OpenBao and Postgres without claiming cross-system atomicity.
- Rendered the editable document to PDF and inspected all 18 pages for clipping, overlap, missing glyphs, table breaks, diagram labels and page numbering.
- Re-rendered after the final two wording/diagram changes, verified that the other page images were unchanged by checksum, and visually checked the two changed pages.
- Verified the DOCX package structure, five embedded diagrams, nine tables, and absence of a decorative border beneath the title.
- Exported the same design text, tables, links and diagrams to reviewable Markdown. The initial PDF was the verified 18-page rendition.

## Review revision v0.2 checks completed

- Read all five inline review findings on PR #1 and reconciled the branch head before editing.
- Added the explicit final live grant/connection/epoch check and buffered-result discard path to the rendered read sequence.
- Persisted `approved_connection_epoch` in the grant contract and required equality at token issuance, execution, dispatch and final response. Added same-account reconnect and approval-race acceptance cases.
- Added `rejected_generation` handling for 401 recovery: reuse only a newer valid bundle or force one refresh regardless of recorded expiry. Updated the visible refresh diagram and bounded-retry contract.
- Added durable pre-dispatch refresh intent, unresolved-operation uniqueness and recovery without blind redispatch. Expanded crash and database-session-loss acceptance cases; retained the explicit no-exactly-once caveat.
- Added OpenBao's role, replaceable versioned `SecretStore` contract and proposed deployment topology. Verified the official OpenBao installation/storage references: both Raft and PostgreSQL are production-ready choices, and the documentation recommends PostgreSQL for new operators. No cloud or storage backend was selected or deployed.
- Checked in the actual document/diagram generator, Markdown exporter, render command, dependency requirements and font prerequisites. No original-machine path or private rendering service is required.
- Ran the checked-in `source/render.py` pipeline and a separate clean out-of-tree rebuild. The Markdown and all five SVGs matched byte for byte.
- Independently rendered the DOCX for visual QA, inspected all 21 pages, then re-rendered after final wording changes. Confirmed the other 18 page images were unchanged and re-inspected the three changed pages.
- Compared every PDF page's raster between the checked-in generator, clean rebuild and independent QA render: all 21 were pixel-identical in this environment. PDF metadata byte identity across environments is not claimed.
- Validated the DOCX archive, five embedded diagrams, nine tables and absence of title borders. Checked Python source syntax.

## Application checks outside this design record

- No Toolbox application implementation or provider integration tests have run as part of this design work.
- The Google client/Picker/backend account and project configuration still needs a real integration spike.
- S256 PKCE enforcement for the selected Google web client must be demonstrated with wrong-verifier and missing-verifier negative tests.
- Plain-text multi-tab fidelity, download restrictions and resource-key cases need integration validation.
- The acceptance, concurrency, revocation, SSRF, refresh-failure and logging tests in the design are implementation requirements, not reported test results.

## Review history

The first draft commit contains this coherent design, its PDF, diagrams and this accurate check record. Subsequent review fixes and new checks should be separate commits. Do not squash or force-rewrite the review branch to manufacture a different history.
