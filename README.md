# pwru (packet, where are you?)

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

|           Option         |                         Note                         |
| ------------------------ | ---------------------------------------------------- |
| CONFIG_DEBUG_INFO_BTF=y  | available since >= 5.3                               |
| CONFIG_KPROBES=y         |                                                      |
| CONFIG_PERF_EVENTS=y     |                                                      |
| CONFIG_BPF=y             |                                                      |
| CONFIG_BPF_SYSCALL=y     |                                                      |
| CONFIG_FUNCTION_TRACER=y | /sys/kernel/debug/tracing/available_filter_functions |
| CONFIG_FPROBE=y          | --backend=kprobe-multi, available since >= 5.18      |

You can use `zgrep $OPTION /proc/config.gz` to validate whether option is enabled.

### Downloading

You can download the statically linked executable for x86\_64 and arm64 from the
[release page](https://github.com/cilium/pwru/releases).

### Usage

```
$ ./pwru --help
Usage: pwru [options] [pcap-filter]
    Availble pcap-filter: see "man 7 pcap-filter"
    Availble options:
      --all-kmods                 attach to all available kernel modules
      --backend string            Tracing backend('kprobe', 'kprobe-multi'). Will auto-detect if not specified.
      --filter-func string        filter kernel functions to be probed by name (exact match, supports RE2 regular expression)
      --filter-mark uint32        filter skb mark
      --filter-netns uint32       filter netns inode
      --filter-track-skb          trace a packet even if it does not match given filters (e.g., after NAT or tunnel decapsulation)
      --kernel-btf string         specify kernel BTF file
      --kmods strings             list of kernel modules names to attach to
      --output-file string        write traces to file
      --output-limit-lines uint   exit the program after the number of events has been received/printed
      --output-meta               print skb metadata
      --output-skb                print skb
      --output-stack              print stack
      --output-tuple              print L4 tuple
      --timestamp string          print timestamp per skb ("current", "relative", "absolute", "none") (default "none")
      --version                   show pwru version and exit

```

If multiple filters are specified, all of them have to match in order for a
packet to be traced.

The `--filter-func` switch does an exact match on function names i.e.
`--filter-func=foo` only matches `foo()`; for a wildcarded match, try
`--filter-func=".*foo.*"` instead.

### Running with Docker

Docker images for `pwru` are published at https://hub.docker.com/r/cilium/pwru.

An example how to run `pwru` with Docker:

```
docker run --privileged --rm -t --pid=host -v /sys/kernel/debug/:/sys/kernel/debug/ cilium/pwru 'dst host 1.1.1.1'
```

### Running on Kubernetes

The following example shows how to run `pwru` on a given node:
```
NODE=node-foobar
kubectl run pwru \
    --image=cilium/pwru:latest \
    --privileged=true \
    --attach=true -i=true --tty=true --rm=true \
    --overrides='{"apiVersion":"v1","spec":{"nodeSelector":{"kubernetes.io/hostname":"'$NODE'"}, "hostNetwork": true, "hostPID": true}}' \
    -- --output-tuple 'dst host 1.1.1.1'
```

Note: You may need to create a volume for `/sys/kernel/debug/` and mount it for the`pwru` pod.

### Running on Vagrant

See [docs/vagrant.md](docs/vagrant.md)

## Developing

### Dependencies

* Go >= 1.16
* LLVM/clang >= 1.12

### Building

```
make
```

Alternatively, you can build in the Docker container:

```
make release
```

## Contributing

`pwru` is an open source project licensed under [GPLv2](LICENSE). Everybody is
welcome to contribute. Contributors are required to follow the
[Contributor Covenant Code of Conduct](https://www.contributor-covenant.org/version/1/4/code-of-conduct/)
and must adhere to the [Developer Certificate of Origin](https://developercertificate.org/)
by adding a Signed-off-by line to their commit messages.

## Community

Join the `#pwru` [Slack channel](https://cilium.herokuapp.com/) to chat with
developers, maintainers, and other users. This is a good first stop to ask
questions and share your experiences.

## Logo Credits

The detective gopher is based on the Go gopher designed by Renee French.
