.DEFAULT_GOAL := help

# ─────────────────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────────────────

VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo v0.0.0-dev)
COMMIT     := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_DATE := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -ldflags "\
	-X 'github.com/mohammad2000/Gmesh/internal/version.Version=$(VERSION)' \
	-X 'github.com/mohammad2000/Gmesh/internal/version.Commit=$(COMMIT)' \
	-X 'github.com/mohammad2000/Gmesh/internal/version.BuildDate=$(BUILD_DATE)' \
	-s -w"

GOFLAGS := -trimpath
BIN     := bin

# ─────────────────────────────────────────────────────────────
# Targets
# ─────────────────────────────────────────────────────────────

.PHONY: help
help: ## Show this help
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.PHONY: build
build: $(BIN)/gmeshd $(BIN)/gmeshctl $(BIN)/gmesh-relay ## Build all binaries

$(BIN)/gmeshd: $(shell find cmd/gmeshd internal -name '*.go') go.mod
	@mkdir -p $(BIN)
	go build $(GOFLAGS) $(LDFLAGS) -o $@ ./cmd/gmeshd

$(BIN)/gmeshctl: $(shell find cmd/gmeshctl internal -name '*.go') go.mod
	@mkdir -p $(BIN)
	go build $(GOFLAGS) $(LDFLAGS) -o $@ ./cmd/gmeshctl

$(BIN)/gmesh-relay: $(shell find cmd/gmesh-relay internal -name '*.go') go.mod
	@mkdir -p $(BIN)
	go build $(GOFLAGS) $(LDFLAGS) -o $@ ./cmd/gmesh-relay

.PHONY: install
install: build ## Install binaries and systemd unit (needs sudo)
	install -m 0755 $(BIN)/gmeshd    /usr/local/bin/gmeshd
	install -m 0755 $(BIN)/gmeshctl  /usr/local/bin/gmeshctl
	install -m 0755 $(BIN)/gmesh-relay /usr/local/bin/gmesh-relay
	install -m 0644 systemd/gmeshd.service /etc/systemd/system/gmeshd.service
	systemctl daemon-reload
	@echo "Installed. Start with: sudo systemctl enable --now gmeshd"

.PHONY: uninstall
uninstall: ## Remove binaries and systemd unit (needs sudo)
	-systemctl disable --now gmeshd
	rm -f /usr/local/bin/gmeshd /usr/local/bin/gmeshctl /usr/local/bin/gmesh-relay
	rm -f /etc/systemd/system/gmeshd.service
	systemctl daemon-reload

.PHONY: test
test: ## Run unit tests
	go test -race -coverprofile=coverage.out ./...

.PHONY: test-integration
test-integration: ## Run integration tests (needs docker)
	cd test/integration && docker compose up --abort-on-container-exit --exit-code-from runner

.PHONY: lint
lint: ## Run linter
	@which golangci-lint >/dev/null || (echo "install golangci-lint: https://golangci-lint.run/usage/install/" && exit 1)
	golangci-lint run ./...

.PHONY: fmt
fmt: ## Format code
	gofmt -s -w .
	go mod tidy

.PHONY: proto
proto: ## Regenerate protobuf code
	bash scripts/gen-proto.sh

.PHONY: deb
deb: ## Build .deb package (needs dpkg-buildpackage)
	bash scripts/build-deb.sh

.PHONY: clean
clean: ## Remove build artifacts
	rm -rf $(BIN) dist coverage.out coverage.html

.PHONY: version
version: ## Print version info
	@echo "version:    $(VERSION)"
	@echo "commit:     $(COMMIT)"
	@echo "build_date: $(BUILD_DATE)"
