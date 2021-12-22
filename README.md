# pwru (packet, where are you?)

![logo](logo.png "Detective Gopher is looking for packet traces left by eBPF bee")

`pwru` is an [eBPF](https://ebpf.io)-based tool for tracing network packets in
the Linux kernel with advanced filtering capabilities. It allows fine-grained 
introspection of kernel state to facilitate debugging network connectivity issues.

The following example shows where the packets of a `curl` request are dropped
after installing an IP tables rule:

![demo](demo.gif)

## Quick start with Vagrant

If you have [Vagrant](https://www.vagrantup.com/) installed, you can run the
above example with the following commands.

1. In a terminal (terminal 1), bring up the Vagrant box:
   ```console
   $ vagrant up
   ```
   This will take a few minutes to download and provision the box.

2. Connect to the Vagrant box:
   ```console
   $ vagrant ssh
   ```

3. Build `pwru`:
   ```console
   $ cd /pwru
   $ go generate
   $ go build
   ```

4. Run `pwru`:
   ```console
   $ sudo ./pwru --filter-dst-ip=1.1.1.1 --filter-dst-port=80 --filter-proto=tcp --output-tuple
   ```

5. In a new terminal (terminal 2), connect to the Vagrant box:
   ```console
   $ vagrant ssh
   ```

6. In terminal 2, run `curl` to generate some traffic to 1.1.1.1:
   ```console
   $ curl 1.1.1.1
   ```
   Observe the output of `pwru` in terminal 1.

7. In terminal 2, add an `iptables` rule to block traffic to 1.1.1.1:
   ```console
   $ sudo iptables -t filter -I OUTPUT 1 -m tcp --proto tcp --dst 1.1.1.1/32 -j DROP
   ```

8. In terminal 2, run `curl` to generate some traffic to 1.1.1.1:
   ```console
   $ curl 1.1.1.1
   ```
   Observe the output of `pwru` in terminal 1.

9. To clean up, press `Ctrl+C` to terminate `pwru` in terminal 1, exit both
   shells, and run:
   ```console
   $ vagrant destroy
   ```

## Running

### Requirements

`pwru` requires >= 5.5 kernel to run. For `--output-skb` >= 5.9 kernel is required.

The following kernel configuration is required.

|           Option        |        Note            |
| ----------------------- | ---------------------- |
| CONFIG_DEBUG_INFO_BTF=y | Available since >= 5.3 |
| CONFIG_KPROBES=y        |                        |
| CONFIG_PERF_EVENTS=y    |                        |
| CONFIG_BPF=y            |                        |
| CONFIG_BPF_SYSCALL=y    |                        |

You can use `zgrep $OPTION /proc/config.gz` to validate whether option is enabled.

### Downloading

You can download the statically linked executable for x86\_64 arch which includes
the eBPF bytecode from the [release page](https://github.com/cilium/pwru/releases).

### Usage

```
Usage of ./pwru:
      --filter-dst-ip string        filter destination IP addr
      --filter-dst-port uint16      filter destination port
      --filter-func string          filter kernel functions to be probed by name (exact match, supports RE2 regular expression)
      --filter-mark uint32          filter skb mark
      --filter-netns uint32         filter netns inode
      --filter-proto string         filter L4 protocol (tcp, udp, icmp)
      --filter-src-ip string        filter source IP addr
      --filter-src-port uint16      filter source port
      --output-limit-lines uint     exit the program after the number of events has been received/printed
      --output-meta                 print skb metadata
      --output-relative-timestamp   print relative timestamp per skb
      --output-skb                  print skb
      --output-stack                print stack
      --output-tuple                print L4 tuple
```

If multiple filters are specified, all of them have to match in order for a
packet to be traced.

The `--filter-func` switch does an exact match on function names i.e.
`--filter-func=foo` only matches `foo()`; for a wildcarded match, try
`--filter-func=".*foo.*"` instead.

## Developing

### Dependencies

* Go >= 1.16
* LLVM/clang >= 1.12

### Building

```
go generate .
go build .
```

Alternatively, you can build and run in the Docker container:

```
docker build -t pwru .
docker run --privileged -it pwru [filter1] [filtern]
```

## Contributing

`pwru` is an open source project licensed under [GPLv2](LICENSE). Everybody is
welcome to contribute. Contributors are required to follow the
[Contributor Covenant Code of Conduct](https://www.contributor-covenant.org/version/1/4/code-of-conduct/)
and must adhere to the [Developer Certificate of Origin](https://developercertificate.org/)
by adding a Signed-off-by line to their commit messages.

## Logo Credits

The detective gopher is based on the Go gopher designed by Renee French.
