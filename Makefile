GO := go
GO_BUILD = CGO_ENABLED=1 $(GO) build
GO_GENERATE = $(GO) generate
GO_TAGS ?=
TARGET_GOARCH ?= amd64
GOARCH ?= amd64
TARGET=pwru
INSTALL = $(QUIET)install
BINDIR ?= /usr/local/bin
VERSION=$(shell git describe --tags --always)
LIBPCAP_ARCH ?= x86_64-unknown-linux-gnu
# For compiling libpcap and CGO
CC ?= gcc
ARCHS ?= amd64 arm64

TEST_TIMEOUT ?= 5s
.DEFAULT_GOAL := pwru

## Build the GO binary
pwru: libpcap/libpcap.a
	TARGET_GOARCH=$(TARGET_GOARCH) $(GO_GENERATE)
	CC=$(CC) GOARCH=$(TARGET_GOARCH) $(GO_BUILD) $(if $(GO_TAGS),-tags $(GO_TAGS)) \
		-ldflags "-w -s \
		-X 'github.com/cilium/pwru/internal/pwru.Version=${VERSION}'"

## Build libpcap for static linking
libpcap/libpcap.a:
	cd libpcap && \
		CC=$(LIBPCAP_CC) ./configure --disable-rdma --disable-shared --disable-usb --disable-netmap --disable-bluetooth --disable-dbus --without-libnl --host=$(LIBPCAP_ARCH) && \
		make

## Build the GO binary within a Docker container
release:
	docker run \
		--rm \
		--workdir /pwru \
		--volume `pwd`:/pwru docker.io/library/golang:1.24.1 \
		sh -c "apt update && apt install -y make git clang-15 llvm curl gcc flex bison gcc-aarch64* libc6-dev-arm64-cross && \
			ln -s /usr/bin/clang-15 /usr/bin/clang && \
			git config --global --add safe.directory /pwru && \
			make local-release"

## Build a new release
local-release: clean
	ARCHS='$(ARCHS)' ./local-release.sh

## Install the GO Binary to the location specified by 'BINDIR'
install: $(TARGET)
	$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)

## Clean up build artifacts
clean:
	rm -f $(TARGET)
	rm -f kprobepwru_bpf*
	rm -f kprobemultipwru_bpf*
	rm -f kprobepwruwithoutoutputskb_bpf*
	rm -f kprobemultipwruwithoutoutputskb_bpf*
	cd libpcap/ && make clean || true

## Run GO tests
test:
	$(GO) test -timeout=$(TEST_TIMEOUT) -race -cover $$($(GO) list ./...)

# COLORS
GREEN  := $(shell tput -Txterm setaf 2)
YELLOW := $(shell tput -Txterm setaf 3)
WHITE  := $(shell tput -Txterm setaf 7)
RESET  := $(shell tput -Txterm sgr0)

TARGET_MAX_CHAR_NUM=20
## Show this help
help:
	@echo ''
	@echo 'Usage:'
	@echo '  ${YELLOW}make${RESET} ${GREEN}<target>${RESET}'
	@echo ''
	@echo 'Targets:'

	@awk '/^[a-zA-Z0-9_-]+:/ { \
		helpMessage = match(lastLine, /^## (.*)/); \
		if (helpMessage) { \
			helpCommand = substr($$1, 0, index($$1, ":")-1); \
			helpMessage = substr(lastLine, RSTART + 3, RLENGTH); \
			printf "  ${YELLOW}%-$(TARGET_MAX_CHAR_NUM)s${RESET} ${GREEN}%s${RESET}\n", helpCommand, helpMessage; \
		} \
	} \
	{ lastLine = $$0 }' $(MAKEFILE_LIST)

.PHONY: $(TARGET) release local-release install clean test
