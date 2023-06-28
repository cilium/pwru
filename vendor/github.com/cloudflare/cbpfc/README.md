# cbpfc

[![GoDoc](https://godoc.org/github.com/cloudflare/cbpfc?status.svg)](https://godoc.org/github.com/cloudflare/cbpfc)

cbpfc is a classic BPF (cBPF) to extended BPF (eBPF) compiler.
It can compile cBPF to eBPF, or to C,
and the generated code should be accepted by the kernel verifier.

[cbpfc/clang](https://godoc.org/github.com/cloudflare/cbpfc/clang) is a simple clang wrapper
for compiling C to eBPF.


## Tests

### Dependencies

* `clang`
    * Path can be set via environment variable `$CLANG`


### Unprivileged

* `go test -short`


### Full

* Requires:
    * `root` or `CAP_SYS_ADMIN` to load XDP programs
    * Recent (4.14+) Linux kernel

* `sudo go test`
