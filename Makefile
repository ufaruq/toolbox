.PHONY: run test check deps dev
run:
	TOOLBOX_MODE=fixture go run ./cmd/toolbox

test:
	go test -race -count=1 ./...

check:
	test -z "$$(gofmt -l .)"
	go vet ./...
	go test -race -count=1 ./...
	go build ./...

deps:
	docker compose up -d --wait
	# Dev mode's secret mount exists, but require CAS and a small version history.
	docker compose exec openbao bao write secret/config cas_required=true max_versions=3

dev: deps
	TOOLBOX_MODE=fixture DATABASE_URL='postgres://toolbox:fixture-only@127.0.0.1:5432/toolbox?sslmode=disable' OPENBAO_ADDR='http://127.0.0.1:8200' OPENBAO_TOKEN='fixture-only' go run ./cmd/toolbox

# Portable container workflow. All generated state and evidence is git-ignored.
.PHONY: deploy-init deploy-up deploy-test deploy-preflight deploy-status deploy-stop deploy-cleanup deploy-retention deploy-backup deploy-restore-drill deploy-monitor deploy-update deploy-rollback

deploy-init deploy-up deploy-test deploy-preflight deploy-status deploy-stop deploy-cleanup deploy-retention deploy-backup deploy-restore-drill deploy-monitor deploy-update deploy-rollback:
	./scripts/deploy $(patsubst deploy-%,%,$@)

# These targets never apply as part of init/plan/test. Apply uses the reviewed plan.
.PHONY: gcp-init gcp-fmt gcp-validate gcp-plan gcp-apply gcp-publish gcp-prepare gcp-deploy

gcp-init:
	./scripts/gcp-terraform init

gcp-fmt:
	./scripts/gcp-terraform fmt -check

gcp-validate:
	./scripts/gcp-terraform validate

gcp-plan:
	./scripts/gcp-terraform plan -out=toolbox.tfplan

gcp-apply:
	./scripts/gcp-terraform apply toolbox.tfplan

gcp-publish:
	./scripts/gcp-release publish

gcp-prepare:
	./scripts/gcp-release prepare

gcp-deploy:
	./scripts/gcp-release deploy
