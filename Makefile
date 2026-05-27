.PHONY: build run test clean

build:
	go build -o cmd/server/server ./cmd/server

run: build
	./cmd/server/server

test:
	go test ./...

clean:
	rm -f cmd/server/server
