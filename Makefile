GO ?= go
VERSION ?= 0.1.0-dev
PYTHON ?= python3
CONTAINER_ENGINE ?= docker

.PHONY: build test vet release test-containers test-root-containers

build:
	mkdir -p dist
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "-s -w -X github.com/cowsecurity/emudhraslop/internal/app.Version=$(VERSION)" -o dist/emudhraslop ./cmd/emudhraslop

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

release:
	GO="$(GO)" PYTHON="$(PYTHON)" VERSION="$(VERSION)" ./scripts/build-release.sh

test-containers:
	GO="$(GO)" CONTAINER_ENGINE="$(CONTAINER_ENGINE)" ./scripts/container-smoke.sh

test-root-containers:
	GO="$(GO)" CONTAINER_ENGINE="$(CONTAINER_ENGINE)" ./scripts/root-container-tests.sh
