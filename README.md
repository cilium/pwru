# pwru (packet, where are you?)

![logo](logo.png "Detective Gopher is looking for packet traces left by eBPF bee")

`pwru` is an [eBPF](https://ebpf.io)-based tool for tracing network packets in
the Linux kernel.

The following example shows where the packets of a `curl` request are dropped
after installing an IP tables rule:

![demo](demo.gif)

## Running

### Requirements

`pwru` requires >= 5.3 kernel to run. For `--output-skb` >= 5.9 kernel is required.

The following kernel configuration is required.

|           Option        |        Note            |
| ----------------------- | ---------------------- |
| CONFIG_DEBUG_INFO_BTF=y | Available since >= 5.3 |
| CONFIG_KPROBES=y        |                        |
| CONFIG_PERF_EVENTS=y    |                        |
| CONFIG_BPF=y			  |                        |
| CONFIG_BPF_SYSCALLS=y   |                        |

You can use `zgrep $OPTION /proc/config.gz` to validate whether option is enabled.

### Permissions 

Running `pwru` as root, or with ``--privileged`` if running as a Docker container
is a straight forward way to get started.

Alternatively, `pwru` requires sufficient capabilities to implement the eBPF based 
tracing functionalities.

`CAP_BPF`,`CAP_TRACING` (>=5.7) and `CAP_SYS_RESOURCE`

### Usage

```
Usage of ./pwru:
  -filter-dst-ip string
        filter destination IP addr
  -filter-dst-port string
        filter destination port
  -filter-mark int
        filter skb mark
  -filter-proto string
        filter L4 protocol (tcp, udp, icmp)
  -filter-src-ip string
        filter source IP addr
  -filter-src-port string
        filter source port
  -output-meta
        print skb metadata
  -output-relative-timestamp
        print relative timestamp per skb
  -output-skb
        print skb
  -output-tuple
        print L4 tuple
```

If multiple filters are specified, all of them have to match in order for a
packet to be traced.

### Run in a container
docker build -t pwru .

docker run --privileged -it pwru [filter1] [filtern]

## Developing

### Dependencies

* Go >= 1.16
* LLVM/clang >= 1.12

### Building

```
go generate .
go build .
```

### Contributing

*pwru* is an open source project licensed under [GPLv2](LICENSE). Everybody is
welcome to contribute. Contributors are required to follow the
[Contributor Covenant Code of Conduct](https://www.contributor-covenant.org/version/1/4/code-of-conduct/)
and must adhere to the [Developer Certificate of Origin](https://developercertificate.org/)
by adding a Signed-off-by line to their commit messages.
