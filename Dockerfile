FROM ubuntu:22.04 AS build

ENV PATH $PATH:/usr/local/go/bin

RUN apt update -y -q && \
    DEBIAN_FRONTEND=noninteractive apt install --no-install-recommends -y -q \
        curl \
        build-essential \
        ca-certificates \
        wget \
        gnupg2 \
        git && \
    curl -s https://storage.googleapis.com/golang/go1.18.3.linux-amd64.tar.gz| tar -v -C /usr/local -xz && \
    printf "deb http://apt.llvm.org/xenial/ llvm-toolchain-xenial-12 main" | tee /etc/apt/sources.list.d/llvm-toolchain-xenial-12.list && \
    wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add - && \
    apt -y update && \
    apt install --no-install-recommends -y -q \
        llvm-12 \
        clang-12 && \
    ln -s /usr/bin/clang-12 /usr/bin/clang && \
    ln -s /usr/lib/llvm-12/bin/llvm-strip /usr/local/bin/llvm-strip

WORKDIR /pwru
COPY . .
RUN make && \
    chmod a+x /pwru

FROM scratch
COPY --from=build /pwru/pwru /usr/local/bin/
ENTRYPOINT ["/usr/local/bin/pwru"]
