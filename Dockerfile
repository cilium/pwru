FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.24.4 AS build
ARG TARGETPLATFORM
ARG BUILDPLATFORM
ARG TARGETARCH

RUN gcc_pkg=$(if [ "${TARGETARCH}" = "arm64" ]; then echo "aarch64"; else echo "x86-64"; fi)  && \
    apt update && \
    apt install -y make git clang-15 llvm curl gcc flex bison gcc-${gcc_pkg}* libc6-dev-${TARGETARCH}-cross && \
    ln -s /usr/bin/clang-15 /usr/bin/clang

WORKDIR /pwru
COPY . .
RUN ARCHS=${TARGETARCH} make local-release
RUN tar xfv release/pwru-linux-${TARGETARCH}.tar.gz

FROM busybox
COPY --from=build /pwru/pwru /usr/local/bin/
