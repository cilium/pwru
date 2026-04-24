ARG BUILDPLATFORM
FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.26.2 AS build

ARG TARGETARCH
RUN gcc_pkg=$(if [ "${TARGETARCH}" = "arm64" ]; then echo "aarch64"; else echo "x86-64"; fi) && \
    apt update && \
    apt install -y make git wget lsb-release gnupg curl gcc flex bison gcc-${gcc_pkg}* libc6-dev-${TARGETARCH}-cross && \
    wget https://apt.llvm.org/llvm.sh && chmod +x llvm.sh && ./llvm.sh 20 && rm llvm.sh && \
    ln -sf /usr/bin/clang-20 /usr/bin/clang

WORKDIR /pwru
COPY . .
RUN ARCHS=${TARGETARCH} make local-release
RUN tar xfv release/pwru-linux-${TARGETARCH}.tar.gz

FROM busybox
COPY --from=build /pwru/pwru /usr/local/bin/
