# Cenziadah dev toolchain. Every command runs through here; make prints each
# command before running it, and its output is shown as is.

GO      ?= go
PKG     := ./...
CMD     := ./cmd/cenziadah
BIN     := bin/cenziadah

# Version stamping. The SemVer version lives in internal/version (const Version);
# the Makefile only injects build identifiers (commit + date) via -ldflags.
COMMIT  := $(shell git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)$(shell git diff --quiet 2>/dev/null || echo -dirty)
DATE    := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
VPKG    := github.com/paulborile/cenziadah/internal/version
LDFLAGS := -X $(VPKG).Commit=$(COMMIT) -X $(VPKG).Date=$(DATE)

# Packaging (.deb / .rpm via nfpm, a Go tool run on demand; not a module dependency).
VERSION := $(shell sed -n 's/^const Version = "v\(.*\)"/\1/p' internal/version/version.go)
ARCH    ?= amd64
NFPM    := $(GO) run github.com/goreleaser/nfpm/v2/cmd/nfpm@v2.47.0

.DEFAULT_GOAL := all

.PHONY: all
all: fmt vet build test ## fmt + vet + build + unit tests

.PHONY: fmt
fmt: ## fail if any file is not gofmt-clean (lists them)
	out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "$$out"; echo "not gofmt-clean: run make fmt-fix"; exit 1; fi

.PHONY: fmt-fix
fmt-fix: ## rewrite files with gofmt
	gofmt -w .

.PHONY: vet
vet: ## go vet
	$(GO) vet $(PKG)

.PHONY: build
build: ## build the cenziadah binary (version-stamped)
	mkdir -p bin
	$(GO) build -ldflags "$(LDFLAGS)" -o $(BIN) $(CMD)

.PHONY: build-static
build-static: ## static linux binary for packaging (dist/build/cenziadah, for ARCH)
	mkdir -p dist/build
	CGO_ENABLED=0 GOOS=linux GOARCH=$(ARCH) $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o dist/build/cenziadah $(CMD)

.PHONY: deb
deb: build-static ## build the .deb into dist/ (ARCH=amd64|arm64)
	VERSION=$(VERSION) ARCH=$(ARCH) $(NFPM) package -f packaging/nfpm.yaml -p deb -t dist/

.PHONY: rpm
rpm: build-static ## build the .rpm into dist/ (ARCH=amd64|arm64)
	VERSION=$(VERSION) ARCH=$(ARCH) $(NFPM) package -f packaging/nfpm.yaml -p rpm -t dist/

.PHONY: packages
packages: deb rpm ## build .deb and .rpm into dist/

.PHONY: test
test: ## unit tests only (no integration)
	$(GO) test $(PKG)

.PHONY: harness
harness: ## build the vulnerable test victim + exploit
	$(MAKE) -C testharness build

.PHONY: compromise-test
compromise-test: build harness ## THE integration test: run exploit, assert findings
	$(MAKE) -C testharness scenarios

# Public release to GitHub (see scripts/release-production.sh). The git
# commit/tag/push of the GitHub clone between the two steps is done by hand.
PROD_REPO ?= ../../git/Cenziadah

.PHONY: production
production: ## sync the committed tree to the GitHub clone + build the release (DRY_RUN=1 to preview)
	PROD_REPO=$(PROD_REPO) scripts/release-production.sh prepare

.PHONY: github-release
github-release: ## after pushing the tag: create the GitHub release with the packages
	PROD_REPO=$(PROD_REPO) scripts/release-production.sh github-release

.PHONY: clean
clean: ## remove build artifacts (keeps the packages in dist/)
	rm -rf bin dist/build
	$(MAKE) -C testharness clean

.PHONY: help
help: ## list targets
	@grep -E '^[a-zA-Z_-]+:.*## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN{FS=":.*## "}{printf "  %-16s %s\n", $$1, $$2}'
