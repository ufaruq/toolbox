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
