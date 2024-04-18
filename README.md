# pwru (packet, where are you?)

[![Build and Test](https://github.com/cilium/pwru/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/cilium/pwru/actions/workflows/test.yml)
[![GitHub Release](https://img.shields.io/github/release/cilium/pwru.svg?style=flat)](https://github.com/cilium/pwru/releases/latest)

![logo](logo.png "Detective Gopher is looking for packet traces left by eBPF bee")

`pwru` is an [eBPF](https://ebpf.io)-based tool for tracing network packets in
the Linux kernel with advanced filtering capabilities. It allows fine-grained
introspection of kernel state to facilitate debugging network connectivity issues.

The following example shows where the packets of a `curl` request are dropped
after installing an IP tables rule:

![demo](demo.gif)

## Running

### Requirements

`pwru` requires >= 5.3 kernel to run. For `--output-skb` >= 5.9 kernel is required. For `--backend=kprobe-multi` >= 5.18 kernel is required.

`debugfs` has to be mounted in `/sys/kernel/debug`. In case the folder is empty, it can be mounted with:

```
mount -t debugfs none /sys/kernel/debug
```

The following kernel configuration is required.

|           Option         | Backend      |                   Note                               |
| ------------------------ | -------------|----------------------------------------------------- |
| CONFIG_DEBUG_INFO_BTF=y  | both         | available since >= 5.3                               |
| CONFIG_KPROBES=y         | both         |                                                      |
| CONFIG_PERF_EVENTS=y     | both         |                                                      |
| CONFIG_BPF=y             | both         |                                                      |
| CONFIG_BPF_SYSCALL=y     | both         |                                                      |
| CONFIG_FUNCTION_TRACER=y | kprobe-multi | /sys/kernel/debug/tracing/available_filter_functions |
| CONFIG_FPROBE=y          | kprobe-multi | available since >= 5.18                              |

You can use `zgrep $OPTION /proc/config.gz` to validate whether option is enabled.

### Downloading

You can download the statically linked executable for x86\_64 and arm64 from the
[release page](https://github.com/cilium/pwru/releases).

### Usage

```
$ ./pwru --help
Usage: pwru [options] [pcap-filter]
    Available pcap-filter: see "man 7 pcap-filter"
    Available options:
      --all-kmods                     attach to all available kernel modules
      --backend string                Tracing backend('kprobe', 'kprobe-multi'). Will auto-detect if not specified.
      --filter-func string            filter kernel functions to be probed by name (exact match, supports RE2 regular expression)
      --filter-ifname string          filter skb ifname in --filter-netns (if not specified, use current netns)
      --filter-kprobe-batch uint      batch size for kprobe attaching/detaching (default 10)
      --filter-mark uint32            filter skb mark
      --filter-netns string           filter netns ("/proc/<pid>/ns/net", "inode:<inode>")
      --filter-trace-tc               trace TC bpf progs
      --filter-track-skb              trace a packet even if it does not match given filters (e.g., after NAT or tunnel decapsulation)
      --filter-track-skb-by-stackid   trace a packet even after it is kfreed (e.g., traffic going through bridge)
  -h, --help                          display this message and exit
      --kernel-btf string             specify kernel BTF file
      --kmods strings                 list of kernel modules names to attach to
      --output-file string            write traces to file
      --output-json                   output traces in JSON format
      --output-limit-lines uint       exit the program after the number of events has been received/printed
      --output-meta                   print skb metadata
      --output-skb                    print skb
      --output-stack                  print stack
      --output-tuple                  print L4 tuple
      --timestamp string              print timestamp per skb ("current", "relative", "absolute", "none") (default "none")
      --version                       show pwru version and exit

```

The `--filter-func` switch does an exact match on function names i.e.
`--filter-func=foo` only matches `foo()`; for a wildcarded match, try
`--filter-func=".*foo.*"` instead.

### Running with Docker

Docker images for `pwru` are published at https://hub.docker.com/r/cilium/pwru.

An example how to run `pwru` with Docker:

```
docker run --privileged --rm -t --pid=host -v /sys/kernel/debug/:/sys/kernel/debug/ cilium/pwru pwru --output-tuple 'host 1.1.1.1'
```

### Running on Kubernetes

The following example shows how to run `pwru` on a given node:
```
#!/usr/bin/env bash
NODE=kind-control-plane
PWRU_ARGS="--output-tuple 'host 1.1.1.1'"

trap " kubectl delete --wait=false pod pwru " EXIT

kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: pwru
spec:
  nodeSelector:
    kubernetes.io/hostname: ${NODE}
  containers:
  - image: docker.io/cilium/pwru:latest
    name: pwru
    volumeMounts:
    - mountPath: /sys/kernel/debug
      name: sys-kernel-debug
    securityContext:
      privileged: true
    command: ["/bin/sh"]
    args: ["-c", "pwru ${PWRU_ARGS}"]
  volumes:
  - name: sys-kernel-debug
    hostPath:
      path: /sys/kernel/debug
      type: DirectoryOrCreate
  hostNetwork: true
  hostPID: true
EOF

kubectl wait pod pwru --for condition=Ready --timeout=90s
kubectl logs -f pwru
```

### Running on Vagrant

See [docs/vagrant.md](docs/vagrant.md)

## Developing

### Dependencies

* Go >= 1.16
* LLVM/clang >= 1.12
* Bison
* Lex/Flex >= 2.5.31

### Building

```
make
```

Alternatively, you can build in the Docker container:

```
make release
```

## Contributing

`pwru` is an open source project. The userspace code is licensed under
[Apache-2.0](LICENSE), while the BPF under [BSD 2-Clause](bpf/LICENSE.BSD-2-Clause)
and [GPL-2.0](bpf/LICENSE.GPL-2.0). Everybody is welcome to contribute.
Contributors are required to follow the [Contributor Covenant Code of
Conduct](https://www.contributor-covenant.org/version/1/4/code-of-conduct/) and
must adhere to the [Developer Certificate of
Origin](https://developercertificate.org/) by adding a Signed-off-by line to
their commit messages.

## Community

Join the `#pwru` [Slack channel](https://cilium.herokuapp.com/) to chat with
developers, maintainers, and other users. This is a good first stop to ask
questions and share your experiences.

## Logo Credits

The detective gopher is based on the Go gopher designed by Renee French.
