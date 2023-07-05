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

TEST_TIMEOUT ?= 5s

$(TARGET): libpcap/libpcap.a
	TARGET_GOARCH=$(TARGET_GOARCH) $(GO_GENERATE)
	CC=$(CC) GOARCH=$(TARGET_GOARCH) $(GO_BUILD) $(if $(GO_TAGS),-tags $(GO_TAGS)) \
		-ldflags "-w -s \
		-X 'github.com/cilium/pwru/internal/pwru.Version=${VERSION}'"

libpcap/libpcap.a:
	cd libpcap && \
		CC=$(LIBPCAP_CC) ./configure --disable-shared --disable-usb --disable-netmap --disable-bluetooth --disable-dbus --without-libnl --host=$(LIBPCAP_ARCH) && \
		make

release:
	docker run \
		--rm \
		--workdir /pwru \
		--volume `pwd`:/pwru docker.io/library/golang:1.20.5 \
		sh -c "apt update && apt install -y make git clang-13 llvm curl unzip gcc flex bison gcc-aarch64* libc6-dev-arm64-cross && \
			ln -s /usr/bin/clang-13 /usr/bin/clang && \
			git config --global --add safe.directory /pwru && \
			make local-release"

local-release: clean
	ARCHS='amd64 arm64' ./local-release.sh

install: $(TARGET)
	$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)

clean:
	rm -f $(TARGET)
	rm -f kprobepwru_bpf*
	rm -f kprobemultipwru_bpf*
	rm -f kprobepwruwithoutoutputskb_bpf*
	rm -f kprobemultipwruwithoutoutputskb_bpf*
	cd libpcap/ && make clean || true

test:
	$(GO) test -timeout=$(TEST_TIMEOUT) -race -cover $$($(GO) list ./...)

.PHONY: $(TARGET) release local-release install clean test
