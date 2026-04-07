BINARY := dist/pg-mask-proxy

.PHONY: build lint

build:
	mkdir -p dist
	go build -o $(BINARY) .

lint:
	go vet ./...
	golangci-lint run ./...
