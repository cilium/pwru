FROM ubuntu:22.04 AS build

ENV PATH $PATH:/usr/local/go/bin

RUN apt update -y -q && \
    DEBIAN_FRONTEND=noninteractive apt install --no-install-recommends -y -q \
        curl \
        build-essential \
        ca-certificates \
        wget \
        gnupg2 \
        git \
        llvm \
        clang && \
    curl -s https://storage.googleapis.com/golang/go1.19.1.linux-amd64.tar.gz | tar -v -C /usr/local -xz

WORKDIR /pwru
COPY . .
RUN make && \
    chmod a+x /pwru

FROM scratch
COPY --from=build /pwru/pwru /usr/local/bin/
ENTRYPOINT ["/usr/local/bin/pwru"]
