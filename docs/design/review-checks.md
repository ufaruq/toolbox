# Design review checks

Status as of 18 October 2026. These checks were completed before the initial draft PR. They are recorded here rather than represented as invented earlier commits.

## Completed

- Reviewed the current official Google Drive, Picker, OAuth and OpenID Connect documentation, OpenBao KV v2 documentation, Go OAuth2 documentation, OPA documentation and OAuth/JWT RFCs linked in the design.
- Confirmed that `drive.file` with Picker is the proposed per-file authorization route, that the scope is not read-only, that `files.export` accepts it, that Google Docs supports `text/plain` export, and that the API export limit is 10 MB.
- Checked that the design separates human identity, agent identity, provider connection and explicit delegation.
- Added the trusted approval flow, short-lived delegation JWT, independent agent authentication, action/resource authorization, connector manifest contract and online versus offline revocation tradeoff.
- Specified refresh coordination and the failure windows across Google, OpenBao and Postgres without claiming cross-system atomicity.
- Rendered the editable document to PDF and inspected all 18 pages for clipping, overlap, missing glyphs, table breaks, diagram labels and page numbering.
- Re-rendered after the final two wording/diagram changes, verified that the other page images were unchanged by checksum, and visually checked the two changed pages.
- Verified the DOCX package structure, five embedded diagrams, nine tables, and absence of a decorative border beneath the title.
- Exported the same design text, tables, links and diagrams to reviewable Markdown. The PDF is the verified 18-page rendition.

## Not yet run

- No Toolbox application implementation or provider integration tests have run as part of this design work.
- The Google client/Picker/backend account and project configuration still needs a real integration spike.
- S256 PKCE enforcement for the selected Google web client must be demonstrated with wrong-verifier and missing-verifier negative tests.
- Plain-text multi-tab fidelity, download restrictions and resource-key cases need integration validation.
- The acceptance, concurrency, revocation, SSRF, refresh-failure and logging tests in the design are implementation requirements, not reported test results.

## Review history

The first draft commit contains this coherent design, its PDF, diagrams and this accurate check record. Subsequent review fixes and new checks should be separate commits. Do not squash or force-rewrite the review branch to manufacture a different history.
