# Patched vendor images for PR 26

Status: implemented; local integration and image scans pass. Committed-revision
pre-push validation and hosted CI remain required. This is the design record,
not a claim that hosted checks have passed.

## Accepted design

Build narrowly patched images from immutable upstream releases and minimal,
pinned runtime bases. Preserve upstream functionality used by Toolbox. Record
source checksums, dependency changes and image IDs; produce SBOMs and scan the
same images used in integration tests. Do not suppress unresolved findings.
Keep checking upstream so local patches can be retired.

## Tasks and completion gates

1. OpenBao: rebuild 2.7.2 including its UI, upgrade CAP, JOSE v4 and x/net,
   migrate the remaining Okta SDK JOSE caller to the maintained API. Verify
   JWT signing/verification and reject malformed inputs; inspect linked modules
   and scan the final binary/image. Keep upstream version/provenance visible.
2. Keycloak: preserve the pinned 26.8.2 distribution, replace Guava with the
   checksum-verified fixed artifact and use a pinned minimal Java runtime
   without unused SQLite. Verify library metadata, runtime startup, TLS and the
   real broker suite. Preserve the Quarkus classpath and upstream licenses.
3. Integrate image builds with Compose, local acceptance and hosted scanners.
   Use immutable local image IDs for tests and scans, isolated build contexts,
   SBOM artifacts and upstream-release monitoring. Update authoritative setup
   and security documentation.
4. Run scanner gates, actionlint, docs-check and the complete integration gate.
   Review the final diff, commit, push through the required pre-push full suite,
   and inspect hosted CI before marking the PR ready. No merge is authorized.

## Baseline and review focus

Official OpenBao has three HIGH findings and Keycloak four. The existing full
Toolbox suite passes before custom image changes. Check that replacements
actually change executable contents rather than scanner metadata; no missing
services, silently skipped suites, mutable shared tags or blanket exclusions.
Synthetic provider tests do not establish live Google or Okta behavior.
