VERSION ?= $(shell git describe --tags --always --dirty)
SHA256 ?= $(shell if command -v sha256sum >/dev/null 2>&1; then echo sha256sum; else echo "shasum -a 256"; fi)

.PHONY: build test vet fmt race dist-linux

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

# dist-linux cross-builds the release binaries for the Linux releases and
# writes their checksums in the standard "sha256sum" format ("hash  name"),
# so `sha256sum -c SHA256SUMS` verifies them on the release host. It runs on
# macOS too: $(SHA256) picks shasum there, sha256sum on Linux.
dist-linux:
	@mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-X mydns/internal/version.Version=$(VERSION)" -o dist/mdns-linux-amd64 ./cmd/mdns
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags "-X mydns/internal/version.Version=$(VERSION)" -o dist/mdns-linux-arm64 ./cmd/mdns
	cd dist && $(SHA256) mdns-linux-amd64 mdns-linux-arm64 > SHA256SUMS
