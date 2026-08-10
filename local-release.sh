#!/bin/sh

set -uex

OS=linux

for ARCH in ${ARCHS}; do
    # Use clang for libpcap/CGO on every arch (same compiler as BPF builds).
    # --target selects the triple; gcc-*-linux-gnu packages still provide the
    # cross binutils/libc that clang drives when linking.
    if [ "$ARCH" = "arm64" ]; then
        LIBPCAP_ARCH=aarch64-unknown-linux-gnu
        CLANG_TARGET=aarch64-linux-gnu
    elif [ "$ARCH" = "riscv64" ]; then
        LIBPCAP_ARCH=riscv64-unknown-linux-gnu
        CLANG_TARGET=riscv64-linux-gnu
    else
        LIBPCAP_ARCH=x86_64-unknown-linux-gnu
        CLANG_TARGET=x86_64-linux-gnu
    fi

    make clean
    echo "Building release binary for ${OS}/${ARCH}..."
    make pwru TARGET_GOARCH=${ARCH} LIBPCAP_ARCH=${LIBPCAP_ARCH} \
        CC=clang LIBPCAP_CC=clang \
        CFLAGS="--target=${CLANG_TARGET}" \
        CGO_CFLAGS="--target=${CLANG_TARGET}" \
        CGO_LDFLAGS="--target=${CLANG_TARGET}"

    test -d release/${OS}/${ARCH} || mkdir -p release/${OS}/${ARCH}
    tar -czf release/pwru-${OS}-${ARCH}.tar.gz pwru
    (cd release && sha256sum pwru-${OS}-${ARCH}.tar.gz > pwru-${OS}-${ARCH}.tar.gz.sha256sum)
    rm -r release/${OS}
done
