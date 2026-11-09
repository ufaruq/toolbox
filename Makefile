.DEFAULT_GOAL := help
PYTHON ?= python3
TEST_PACKAGES ?= ./...
TEST_RUN ?= .
BUILD_OUTPUT ?= bin/toolbox
ENV_FILE ?= .env
COMPOSE ?= docker compose
BROWSER_VENV ?= $(CURDIR)/work/browser-venv
BROWSER_PYTHON ?= $(BROWSER_VENV)/bin/python
# Browser harnesses invoke python3; use the selected environment consistently.
BROWSER_PATH = $(dir $(BROWSER_PYTHON)):$(PATH)
SEMGREP_REPORT_DIR ?= $(CURDIR)/work/semgrep
KEYCLOAK_REALM_FILE ?= work/keycloak/realm.json

help: ## List supported development, testing and check commands
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z0-9_-]+:.*## / {printf "  make %-26s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

run: ## Start the in-memory synthetic fixture (Ctrl-C stops it)
	TOOLBOX_MODE=fixture go run ./cmd/toolbox

run-configured: ## Start using exported settings without reloading .env
	go run ./cmd/toolbox

deps: ## Start disposable PostgreSQL/OpenBao and configure CAS
	$(COMPOSE) up --build -d --wait
	$(COMPOSE) exec -T openbao bao write secret/config cas_required=true max_versions=3

deps-test: deps ## Create the disposable integration-test database if absent
	@set -eu; exists="$$( $(COMPOSE) exec -T postgres psql -U toolbox -d postgres -v ON_ERROR_STOP=1 -tAc "SELECT 1 FROM pg_database WHERE datname='toolbox_test'" )"; \
	if [ "$$exists" != 1 ]; then $(COMPOSE) exec -T postgres createdb -U toolbox toolbox_test; fi

dev: deps ## Start stores and the synthetic fixture in the foreground
	TOOLBOX_MODE=fixture DATABASE_URL='postgres://toolbox:fixture-only@127.0.0.1:5432/toolbox?sslmode=disable' OPENBAO_ADDR='http://127.0.0.1:8200' OPENBAO_TOKEN='fixture-only' go run ./cmd/toolbox

dev-down: ## Stop/remove this Compose project's disposable dependencies
	$(COMPOSE) down

dev-status: ## Show this Compose project's dependency status
	$(COMPOSE) ps

dev-logs: ## Follow this Compose project's dependency logs
	$(COMPOSE) logs --follow

# ENV_FILE is private trusted shell configuration, not untrusted input.
oidc: ## Start owner-only OIDC login using ENV_FILE (default .env)
	@test -f "$(ENV_FILE)" || (echo 'Create a private .env using docs/okta-setup.md first.'; exit 1)
	@set -eu; set -a; . "$(abspath $(ENV_FILE))"; set +a; TOOLBOX_MODE=oidc-local go run ./cmd/toolbox

workspace: ## Start the real Google workspace flow using ENV_FILE
	@test -f "$(ENV_FILE)" || (echo 'Create .env from .env.workspace.example first.'; exit 1)
	@set -eu; set -a; . "$(abspath $(ENV_FILE))"; set +a; TOOLBOX_MODE=workspace-local go run ./cmd/toolbox

google-pkce-check: ## Check the configured live Google client's PKCE support
	@test -f "$(ENV_FILE)" || (echo 'Create .env from .env.workspace.example first.'; exit 1)
	@set -eu; set -a; . "$(abspath $(ENV_FILE))"; set +a; go run ./cmd/toolbox google-pkce-check

keycloak-config: ## Render a private realm from exported environment settings
	@set -eu; umask 077; mkdir -p "$(dir $(KEYCLOAK_REALM_FILE))"; go run ./cmd/toolbox keycloak-config "$(KEYCLOAK_REALM_FILE)"

keycloak-link: ## Dry-run verified identity migration using exported settings
	go run ./cmd/toolbox keycloak-link

keycloak-link-apply: ## Apply verified identity migration (explicit state change)
	go run ./cmd/toolbox keycloak-link --apply

fmt: ## Format Go source files
	gofmt -w .

fmt-check: ## Fail if Go source formatting differs
	@files="$$(gofmt -l .)" || exit $$?; test -z "$$files" || (printf '%s\nRun make fmt to fix Go formatting.\n' "$$files"; exit 1)

vet: ## Run Go static checks
	go vet ./...

build: ## Build all Go packages
	go build ./...

build-binary: ## Build the executable at BUILD_OUTPUT (default bin/toolbox)
	@mkdir -p "$(dir $(BUILD_OUTPUT))"
	go build -o "$(BUILD_OUTPUT)" ./cmd/toolbox

test: ## Run race tests; TEST_PACKAGES and TEST_RUN select focused tests
	go test -race -count=1 $(TEST_PACKAGES) -run '$(TEST_RUN)'

test-integration: ## Run Go tests with explicitly configured disposable stores
	@test -n "$$TOOLBOX_TEST_DATABASE_URL" && test -n "$$TOOLBOX_TEST_OPENBAO_ADDR" && test -n "$$TOOLBOX_TEST_OPENBAO_TOKEN" || (echo 'Set all three TOOLBOX_TEST store variables; see docs/storage.md, or use make test-all.'; exit 1)
	go test -race -count=1 -p 1 $(TEST_PACKAGES) -run '$(TEST_RUN)'

test-json: ## Run every Go test serially with race detection and JSON output
	@go test -json -race -count=1 -p 1 -timeout=15m ./...

test-results-check: ## Reject skipped/missing acceptance suites in TEST_RESULTS
	@test -n "$(TEST_RESULTS)" || (echo 'Set TEST_RESULTS to the Go JSON result file.'; exit 1)
	$(PYTHON) tests/runner/check_results.py "$(TEST_RESULTS)"

docs-check: ## Check maintained documentation link targets
	$(PYTHON) tests/docs/check_links.py

test-tools: ## Test push-hook installation/enforcement and result validation
	$(PYTHON) tests/hooks/pre_push_test.py
	$(PYTHON) tests/runner/check_results_test.py

check: ## Quick fmt/vet/race/build/docs/tooling checks (opt-ins may skip)
	$(MAKE) fmt-check
	$(MAKE) vet
	$(MAKE) test
	$(MAKE) build docs-check test-tools

vuln-check: ## Check reachable Go vulnerabilities with pinned govulncheck
	go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...

semgrep-check: ## Run pinned Semgrep CE and write SARIF to SEMGREP_REPORT_DIR
	@mkdir -p "$(SEMGREP_REPORT_DIR)"
	docker run --rm --user "$$(id -u):$$(id -g)" -e HOME=/tmp \
	  -v "$(CURDIR):/src:ro" -v "$(abspath $(SEMGREP_REPORT_DIR)):/reports" -w /src \
	  semgrep/semgrep:1.184.0@sha256:cc1b68266f267878b39739373ea9985b9a78e5d64497dd875c8de100b22695ed \
	  semgrep scan --config p/ci --metrics=off --disable-version-check \
	  --error --strict --sarif --output /reports/semgrep.sarif .

browser-install: ## Install pinned Playwright and Chromium in BROWSER_VENV
	$(PYTHON) -m venv "$(BROWSER_VENV)"
	"$(BROWSER_VENV)/bin/python" -m pip install -r tests/browser/requirements.txt
	"$(BROWSER_VENV)/bin/python" -m playwright install --with-deps chromium

oidc-browser-check: ## Test synthetic OIDC login (no running app required)
	PATH="$(BROWSER_PATH)" TOOLBOX_TEST_PYTHON="$(BROWSER_PYTHON)" TOOLBOX_TEST_OIDC_BROWSER=1 go test -race -count=1 ./internal/server -run '^TestOIDCBrowserFlow$$'

workspace-browser-check: ## Test synthetic Workspace and probe browser flows
	PATH="$(BROWSER_PATH)" TOOLBOX_TEST_WORKSPACE_BROWSER=1 go test -race -count=1 ./internal/app ./cmd/toolbox -run 'Test(Workspace|Probe)BrowserFlow'

browser-fixture-check: ## Test approval/revocation against a running fresh fixture
	"$(BROWSER_PYTHON)" tests/browser/fixture_e2e.py

browser-review-check: ## Test delayed-review races against that same fixture
	"$(BROWSER_PYTHON)" tests/browser/review_race.py

browser-check: ## Run all browser flows; needs a fresh running fixture
	$(MAKE) oidc-browser-check workspace-browser-check
	$(MAKE) browser-fixture-check
	$(MAKE) browser-review-check

mcp-gateway-check: ## Run real Docker MCP isolation (pinned images required)
	TOOLBOX_TEST_DOCKER_MCP=1 go test -race -count=1 ./internal/mcpclient -run '^TestDockerGatewayOwnerIsolation$$' -v -timeout=9m

keycloak-check: ## Run real Keycloak acceptance with controlled upstream identities
	TOOLBOX_TEST_KEYCLOAK_IMAGE="$$(scripts/build-vendor-image keycloak)" TOOLBOX_TEST_KEYCLOAK=1 go test -race -count=1 ./internal/app -run '^TestKeycloakBrokerFlow$$' -v -timeout=9m

test-artifacts: ## Reproduce/fix Linux artifact permissions using RUNNER_IMAGE
	@test -n "$(RUNNER_IMAGE)" || (echo 'Set RUNNER_IMAGE to the built acceptance image, or use make test-all.'; exit 1)
	docker run --rm --network none --tmpfs /evidence --tmpfs /scratch -v "$(CURDIR):/source:ro" -w /source "$(RUNNER_IMAGE)" python3 tests/runner/artifacts_test.py

test-all: ## Run complete isolated acceptance; Docker required, skips fail
	./scripts/test-all

install-hooks: ## Install the push gate without replacing custom hooks
	@set -eu; \
	gate_dir="$$(git rev-parse --path-format=absolute --git-common-dir)/toolbox-hooks"; \
	current="$$(git config --get core.hooksPath || true)"; \
	if [ -n "$$current" ] && [ "$$current" != "$$gate_dir" ]; then \
	  echo "Existing hooksPath $$current: integrate the Toolbox pre-push gate before replacing it." >&2; exit 1; \
	fi; \
	mkdir -p "$$gate_dir"; \
	cp .githooks/pre-push "$$gate_dir/pre-push"; \
	chmod +x "$$gate_dir/pre-push"; \
	git config --local core.hooksPath "$$gate_dir"
	@echo 'Installed the mandatory pre-push gate for this clone/worktree group.'

.PHONY: help run deps deps-test dev dev-down dev-status dev-logs oidc workspace google-pkce-check keycloak-config keycloak-link keycloak-link-apply fmt fmt-check vet build build-binary test test-integration test-json test-results-check docs-check test-tools check vuln-check browser-install oidc-browser-check workspace-browser-check browser-fixture-check browser-review-check browser-check mcp-gateway-check keycloak-check test-all install-hooks

.PHONY: test-artifacts

.PHONY: run-configured

.PHONY: semgrep-check
