ID      := tailscale-identity
MODULE  := github.com/1fc0nfig/cliproxy-tailscale
# Single source of truth for the plugin version. Release CI passes
# VERSION=<tag without v>. It must be dotted numeric (CLIProxyAPI rule).
VERSION ?= 0.2.0
BIN     := $(CURDIR)/bin
DIST    := $(CURDIR)/dist
LDFLAGS := -s -w -X $(MODULE)/internal/tsid.Version=$(VERSION)
# Add TAGS=tsid_noembed for a system/headers-only build without tsnet (~7.5 MB instead of ~18 MB).
TAGS    ?=
GO_IMAGE ?= golang:1.26-bookworm
GOBUILD  = go build -trimpath -buildvcs=false -buildmode=c-shared -tags '$(TAGS)' -ldflags '$(LDFLAGS)'

# darwin: native arch by default. DARWIN_ARCH=amd64 cross-compiles on Apple
# silicon with clang -arch x86_64 (cgo needs a matching C compiler).
DARWIN_ARCH ?= $(shell go env GOARCH)
DARWIN_CC   := $(if $(filter amd64,$(DARWIN_ARCH)),clang -arch x86_64,$(if $(filter arm64,$(DARWIN_ARCH)),clang -arch arm64,clang))
# Minimum macOS for the dylib. Set through CGO flags (part of the Go build
# cache key) so cached cgo objects never mix deployment targets.
MACOS_MIN   ?= 12.0
DARWIN_CGO  := -O2 -g -mmacosx-version-min=$(MACOS_MIN)

.PHONY: all test vet check-version build-darwin build-linux-amd64 build-linux-arm64 linux-build \
	build-linux-native dist package clean clean-dist

all: vet test build-darwin

test:
	go test -race -count=1 ./internal/...

vet:
	go vet ./...
	go vet -tags tsid_noembed ./...

check-version:
	@echo '$(VERSION)' | grep -Eq '^[0-9]+(\.[0-9]+)+$$' || \
		{ echo "VERSION '$(VERSION)' must be dotted numeric, e.g. 0.2.0" >&2; exit 1; }

# Output layout matches the CLIProxyAPI plugin dir: plugins/<GOOS>/<GOARCH>/<id>-v<version>.<ext>
build-darwin: check-version
	mkdir -p $(BIN)/darwin/$(DARWIN_ARCH)
	CGO_ENABLED=1 GOOS=darwin GOARCH=$(DARWIN_ARCH) CC='$(DARWIN_CC)' \
		CGO_CFLAGS='$(DARWIN_CGO)' CGO_LDFLAGS='$(DARWIN_CGO)' $(GOBUILD) \
		-o $(BIN)/darwin/$(DARWIN_ARCH)/$(ID)-v$(VERSION).dylib .
	rm -f $(BIN)/darwin/$(DARWIN_ARCH)/*.h

# Linux builds run in the same Debian bookworm image the upstream Dockerfile
# uses, so the .so links against the same glibc (2.36) as the CLIProxyAPI binary.
build-linux-amd64:
	$(MAKE) linux-build ARCH=amd64

build-linux-arm64:
	$(MAKE) linux-build ARCH=arm64

# The Go build cache and temp dir live on the host (DOCKER_CACHE), not in the
# Docker VM: a full tsnet build creates many files and can exhaust VM inodes.
DOCKER_CACHE ?= $(CURDIR)/.cache/docker

linux-build: check-version
	mkdir -p $(BIN)/linux/$(ARCH) $(DOCKER_CACHE)/$(ARCH)/tmp
	docker run --rm --platform linux/$(ARCH) \
		-v $(CURDIR):/src -w /src \
		-v cliproxy-tailscale-gomod:/go/pkg/mod \
		-v $(DOCKER_CACHE)/$(ARCH):/cache \
		-e GOCACHE=/cache/go-build -e GOTMPDIR=/cache/tmp \
		-e GOTOOLCHAIN=auto \
		$(GO_IMAGE) \
		make build-linux-native VERSION=$(VERSION) TAGS='$(TAGS)'

# Runs inside the golang bookworm container (see linux-build).
build-linux-native: check-version
	mkdir -p $(BIN)/linux/$$(go env GOARCH)
	CGO_ENABLED=1 $(GOBUILD) -o $(BIN)/linux/$$(go env GOARCH)/$(ID)-v$(VERSION).so .
	rm -f $(BIN)/linux/$$(go env GOARCH)/*.h

# Local release equivalent: darwin (native arch) + linux/arm64 via docker.
# CI builds all four platforms; see .github/workflows/release.yml.
dist: clean-dist build-darwin build-linux-arm64 package

# Zips every library under bin/ for VERSION and writes dist/checksums.txt.
package: check-version
	scripts/package.sh $(ID) $(VERSION) $(BIN) $(DIST)

clean-dist:
	rm -rf $(DIST)

clean: clean-dist
	rm -rf $(BIN)
