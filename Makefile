.PHONY: build run test lint tidy clean

## build: compile binary to ./bin/sme-shield
build:
	@echo "Building..."
	@mkdir -p bin
	CGO_ENABLED=1 go build -o bin/sme-shield ./cmd/server

## run: build and run the server
run: build
	@echo "Starting SME-Shield on http://localhost:8080"
	@./bin/sme-shield

## test: run all tests with coverage
test:
	go test ./internal/... -v -cover

## lint: run golangci-lint (install separately)
lint:
	golangci-lint run ./...

## tidy: clean up go.sum and unused deps
tidy:
	go mod tidy

## clean: remove build artifacts and database
clean:
	@rm -rf bin/ audit.db
	@echo "Cleaned."
