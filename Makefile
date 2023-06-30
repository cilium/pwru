GO := go
GO_BUILD = CGO_ENABLED=1 $(GO) build
GO_GENERATE = $(GO) generate
GO_TAGS ?=
TARGET=pwru
INSTALL = $(QUIET)install
BINDIR ?= /usr/local/bin
VERSION=$(shell git describe --tags --always)

TEST_TIMEOUT ?= 5s

$(TARGET):
	$(GO_GENERATE)
	$(GO_BUILD) $(if $(GO_TAGS),-tags $(GO_TAGS)) \
		-ldflags "-w -s \
		-X 'github.com/cilium/pwru/internal/pwru.Version=${VERSION}'"

libpcap.a:
	apt update && apt-get install -y curl unzip gcc flex bison make && \
        curl https://github.com/the-tcpdump-group/libpcap/archive/refs/tags/libpcap-1.10.4.zip -OL && \
        unzip -o libpcap-1.10.4.zip && \
        cd libpcap-libpcap-1.10.4/ && \
	./configure --enable-dbus=no && \
	make && \
	make install


release:
	docker run \
		--rm \
		--workdir /pwru \
		--volume `pwd`:/pwru docker.io/library/golang:1.18.3 \
		sh -c "apt update && apt install -y make git clang-13 llvm && \
			ln -s $(which clang-13) /usr/bin/clang && \
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

test:
	$(GO) test -timeout=$(TEST_TIMEOUT) -race -cover $$($(GO) list ./...)

.PHONY: $(TARGET) release local-release install clean test
