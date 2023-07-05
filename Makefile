GO := go
GO_BUILD = CGO_ENABLED=1 $(GO) build
GO_GENERATE = $(GO) generate
GO_TAGS ?=
TARGET_GOARCH ?= amd64
TARGET=pwru
INSTALL = $(QUIET)install
BINDIR ?= /usr/local/bin
VERSION=$(shell git describe --tags --always)
LIBPCAP_ARCH ?= x86_64-unknown-linux-gnu
LIBPCAP_CC ?= gcc

TEST_TIMEOUT ?= 5s

$(TARGET): libpcap/libpcap.a
	TARGET_GOARCH=$(TARGET_GOARCH) $(GO_GENERATE)
	$(GO_BUILD) $(if $(GO_TAGS),-tags $(GO_TAGS)) \
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
		sh -c "apt update && apt install -y make git clang-13 llvm curl unzip gcc flex bison && \
			ln -s /usr/bin/clang-13 /usr/bin/clang && \
			git config --global --add safe.directory /pwru && \
			make libpcap.a && \
			make local-release VERSION=${VERSION}"

local-release: clean
	OS=linux; \
	ARCHS='amd64 arm64'; \
	for ARCH in $$ARCHS; do \
		echo Building release binary for $$OS/$$ARCH...; \
		test -d release/$$OS/$$ARCH|| mkdir -p release/$$OS/$$ARCH; \
		env GOARCH=$$ARCH $(GO_GENERATE) build.go; \
		env GOOS=$$OS GOARCH=$$ARCH $(GO_BUILD) $(if $(GO_TAGS),-tags $(GO_TAGS)) -ldflags "-w -s -X 'github.com/cilium/pwru/internal/pwru.Version=${VERSION}'" -o release/$$OS/$$ARCH/$(TARGET) ; \
		tar -czf release/$(TARGET)-$$OS-$$ARCH.tar.gz -C release/$$OS/$$ARCH $(TARGET); \
		(cd release && sha256sum $(TARGET)-$$OS-$$ARCH.tar.gz > $(TARGET)-$$OS-$$ARCH.tar.gz.sha256sum); \
		rm -r release/$$OS; \
	done; \

install: $(TARGET)
	$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)

clean:
	rm -f $(TARGET)
	rm -f kprobepwru_bpf*
	rm -f kprobemultipwru_bpf*
	rm -f kprobepwruwithoutoutputskb_bpf*
	rm -f kprobemultipwruwithoutoutputskb_bpf*
	rm -rf ./release
	cd libpcap/ && make clean

test:
	$(GO) test -timeout=$(TEST_TIMEOUT) -race -cover $$($(GO) list ./...)

.PHONY: $(TARGET) release local-release install clean test
