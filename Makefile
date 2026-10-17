.PHONY: build run test lint tidy clean

## build: compile binary to ./bin/sentry
build:
	@echo "Building..."
	@mkdir -p bin
	CGO_ENABLED=1 go build -o bin/sentry ./cmd/server

## run: build and run the server
run: build
	@echo "Starting Sentry on http://localhost:8080"
	@./bin/sentry

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
