FROM docker.io/library/golang:1.23.1 AS build

RUN apt update && \
    apt install -y make git clang-15 llvm curl gcc flex bison gcc-aarch64* libc6-dev-arm64-cross && \
    ln -s /usr/bin/clang-15 /usr/bin/clang

WORKDIR /pwru
COPY . .
RUN make local-release
RUN tar xfv release/pwru-linux-amd64.tar.gz

FROM busybox
COPY --from=build /pwru/pwru /usr/local/bin/
