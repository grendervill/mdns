VERSION ?= $(shell git describe --tags --always --dirty)

.PHONY: build test vet fmt race

build:
	go build -ldflags "-X mydns/internal/version.Version=$(VERSION)" -o bin/mdns ./cmd/mdns

test:
	go test ./...

vet:
	go vet ./...

fmt:
	go fmt ./...

race:
	go test -race ./...
