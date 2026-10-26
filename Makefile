.PHONY: run build test vet fmt tidy run2 build2

BIN := bin/lab_1
BIN2 := bin/lab_2

run: ## Run the lab_1 CLI; pass flags via ARGS, e.g. make run ARGS='-a=2 -e "СЛАВА УКРАЇНІ"'
	go run ./cmd/lab_1 $(ARGS)

build: ## Compile the lab_1 CLI binary into bin/lab_1
	go build -o $(BIN) ./cmd/lab_1

run2: ## Run the lab_2 CLI; pass flags via ARGS, e.g. make run2 ARGS='-a=3 -lang=lat -e -k "2718" "HELLO WORLD"'
	go run ./cmd/lab_2 $(ARGS)

build2: ## Compile the lab_2 CLI binary into bin/lab_2
	go build -o $(BIN2) ./cmd/lab_2

test: ## Run the full test suite (lab_1 + lab_2: control vectors, reversibility, boundaries, negative, files)
	go test ./tests/...

vet: ## Static analysis
	go vet ./...

fmt: ## Format all Go sources
	gofmt -w .

tidy: ## Sync go.mod/go.sum with imports
	go mod tidy
