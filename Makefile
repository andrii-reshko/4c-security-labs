.PHONY: run build test vet fmt tidy

BIN := bin/lab_1

run: ## Run the CLI; pass flags via ARGS, e.g. make run ARGS='-a=2 -e "СЛАВА УКРАЇНІ"'
	go run ./cmd/lab_1 $(ARGS)

build: ## Compile the CLI binary into bin/lab_1
	go build -o $(BIN) ./cmd/lab_1

test: ## Run the full test suite from ./tests/lab_1 (control vectors, reversibility, boundaries, negative, files)
	go test ./tests/...

vet: ## Static analysis
	go vet ./...

fmt: ## Format all Go sources
	gofmt -w .

tidy: ## Sync go.mod/go.sum with imports
	go mod tidy
