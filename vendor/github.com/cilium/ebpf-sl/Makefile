# The development version of clang is distributed as the 'clang' binary,
# while stable/released versions have a version number attached.
# Pin the default clang to a stable version.
CLANG ?= clang-23
STRIP ?= llvm-strip-23
OBJCOPY ?= llvm-objcopy-23
CFLAGS := -O2 -g -Wall -Werror -mcpu=v2 $(CFLAGS)

# Obtain an absolute path to the directory of the Makefile.
# Assume the Makefile is in the root of the repository.
REPODIR := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

IMAGE := $(shell cat ${REPODIR}/testdata/docker/IMAGE)
VERSION := $(shell cat ${REPODIR}/testdata/docker/VERSION)

# Prefer podman if installed, otherwise use docker.
# Note: Setting the var at runtime will always override.
CONTAINER_ENGINE ?= $(if $(shell command -v podman),podman,docker)

# Configure container runtime arguments based on the container engine.
CONTAINER_RUN_ARGS := \
	--env MAKEFLAGS \
	--env HOME=/tmp \
	-v "${REPODIR}":/ebpf -w /ebpf \
	-v "$(shell go env GOCACHE)":/tmp/.cache/go-build \
	-v "$(shell go env GOPATH)":/go \
	-v "$(shell go env GOMODCACHE)":/go/pkg/mod

ifeq ($(CONTAINER_ENGINE), podman)
CONTAINER_RUN_ARGS += --log-driver=none --security-opt label=disable
else
CONTAINER_RUN_ARGS += --user "$(shell stat -c '%u:%g' ${REPODIR})"
endif

.PHONY: all clean container-all container-shell generate

.DEFAULT_GOAL = container-all

HEADERS := $(wildcard testdata/*.h)

TARGETS := \
	testdata/basic

# Make sure Go-related dirs exist before starting containerized builds,
# otherwise podman will fail to start.
godirs:
	mkdir -p $(shell go env GOCACHE) $(shell go env GOPATH) $(shell go env GOMODCACHE)

# Build all ELF binaries using a containerized LLVM toolchain.
container-all: godirs
	+${CONTAINER_ENGINE} run --rm -ti ${CONTAINER_RUN_ARGS} \
		"${IMAGE}:${VERSION}" \
		$(MAKE) all

# (debug) Drop the user into a shell inside the container as root.
container-shell: godirs
	${CONTAINER_ENGINE} run --rm -ti ${CONTAINER_RUN_ARGS} \
		"${IMAGE}:${VERSION}"

clean:
	find "$(CURDIR)" -name "*.elf" -delete
	find "$(CURDIR)" -name "*.o" -delete

all: testdata generate

generate:
	go generate ./cmd/bpf2sl/testdata

testdata: $(addsuffix .o,$(TARGETS)) 

%.o: %.c $(HEADERS)
	$(CLANG) $(CFLAGS) -target bpfel -c $< -o $@
	$(STRIP) -g $@
