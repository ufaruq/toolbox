# GitHub execution runtime

This adapter binds one configured owner to one configured App installation. Owner
repository discovery validates App JWT metadata and uses an independently revoked
metadata-only installation token; that token is never sent to MCP. Operation
credentials always select exactly one trusted repository ID and the policy action's
permission set. A separate read token supplies metadata preflight.

StateDirectory must be an absolute clean path to a service-owned real 0700
directory. Existing unsafe permissions, symlinks and untrusted ancestry are
rejected; they are never silently repaired. Ancestors must be owned by the service
user or root and not writable by other principals, except root-owned sticky
temporary directories whose sticky protection prevents replacement of owned
children. The runtime checks this before credentials and again before launch.

Each operation runs inside a 20 second context, creates a disposable private state
directory, Docker bridge and gateway, uses one explicit 0600 installation secret
file, and removes its own containers/network/state afterward. Cleanup failure suppresses
the result and reports unavailable (or unknown outcome for dispatched writes). Independent bounded
cleanup revokes both credentials even when the operation context is canceled.
Docker Engine is trusted; no arbitrary operator image, URL or provider host is
accepted. The two images are digest pinned in `docker.go`. The gateway identifies
as Docker AI MCP Gateway 2.0.1 with MCP protocol 2025-11-25.

`testdata/tools.json` is the exact inventory obtained from the pinned official
GitHub MCP server (version 2.0.3, upstream revision
b98d115bbb080e9555466a96656ec4df605aea21). It was reviewed against the ten policy
calls: file read/push/update, branch create, PR read/create/update/review/merge and
issue read. The full input schemas are pinned, including required fields and
constraints. Runtime inventory cannot redefine these expectations. Only the one
selected tool is enabled per gateway. Embedded text resources are permitted only
for the reviewed file-read tool; links are never fetched and projection strips
resource URIs and provider metadata.

Metadata preflight checks repository numeric ID and exact owner/name before and
after execution; PR reads and writes require same-repository head/base and approved
refs/revision. File reads walk Git tree modes and ancestors, reject symlinks and
submodules, and pin the MCP read to the resolved commit SHA. Multi-file writes require an existing exact target branch and valid commit/tree
metadata before launch. They also inspect every submitted path and ancestor at
that tree, rejecting existing directories, symlinks, submodules and non-tree
ancestors while allowing missing paths for new files. Tree reads are cached
within the operation. File updates verify
existing regular-file blob SHA and retain the upstream SHA condition. Multi-file
writes rely on policy authority over complete replaceable subtrees and ancestors;
the upstream push tool offers no expected-head condition and remains explicitly
unconditional. The pinned create/update PR tools return minimal `id` and `url` text. Projection
validates the exact HTTPS github.com owner/repository pull URL and emits only its
positive canonical PR number, without returning or fetching the URL. Creation
results without a valid number fail closed. No operation is retried. `ErrOutcomeUnknown` means a mutation was
dispatched but its result cannot be released or confirmed.

## Release limits

Keep production enablement disabled. Metadata preflight and postflight cannot
prove an atomic owner/name locator binding during a concurrent repository rename
or transfer. Revocation cannot undo a mutation already accepted upstream. A crash
can prevent best-effort cleanup; installation tokens then expire at GitHub. Docker
startup acceptance proves the real pinned gateway/server inventory handshake fits
the deadline on the tested host, not live GitHub write behavior. Live App/provider
acceptance and security review remain required.

Focused checks:

```sh
make test TEST_PACKAGES='./internal/githubruntime ./internal/githubapp ./internal/mcpclient'
TOOLBOX_TEST_DOCKER_MCP=1 make test TEST_PACKAGES=./internal/githubruntime TEST_RUN=TestDockerReviewedRuntimeStartup
```

The Linux Docker acceptance fixture uses the existing private-bridge test mode to
forward the inspected disposable gateway address through a test-only loopback
proxy. Docker Desktop publishes host loopback ports outside the Linux runner's
network namespace. This forwarding is internal to the test: `New` and the default
production launcher keep fixed published loopback endpoints, with no operator URL
or resolver configuration. Production state-directory checks remain unchanged.
