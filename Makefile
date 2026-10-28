GO ?= go
export CGO_ENABLED ?= 0
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: all build test test-race lint fmt vet cover install demo clean

all: lint test

build:
	$(GO) build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o bin/header-grader ./cmd/header-grader

install:
	$(GO) install -ldflags "-X main.version=$(VERSION)" ./cmd/header-grader

# The race detector needs cgo, which this host's macOS SDK cannot link.
test:
	$(GO) test -count=1 ./...

test-race:
	CGO_ENABLED=1 $(GO) test -race -count=1 ./...

cover:
	$(GO) test -count=1 -coverprofile=coverage.out ./...
	$(GO) tool cover -func=coverage.out | tail -1

lint: fmt vet

fmt:
	@unformatted=$$(gofmt -l . | grep -v '^$$' || true); \
	if [ -n "$$unformatted" ]; then echo "gofmt needed:"; echo "$$unformatted"; exit 1; fi

vet:
	$(GO) vet ./...

## demo: grade a few well-known sites
demo: build
	@for host in github.com example.com; do ./bin/header-grader $$host || true; done

clean:
	rm -rf bin coverage.out
