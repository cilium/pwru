module github.com/cilium/pwru

go 1.17

replace github.com/cilium/ebpf => github.com/brb/ebpf v0.5.1-0.20210811084231-db593b53a544

require (
	github.com/cheggaaa/pb/v3 v3.0.8
	github.com/cilium/cilium v1.11.0
	github.com/cilium/ebpf v0.7.0
	github.com/mitchellh/go-ps v1.0.0
	github.com/spf13/pflag v1.0.5
	golang.org/x/sys v0.0.0-20211103184734-ae416a5f93c7
)

require (
	github.com/VividCortex/ewma v1.1.1 // indirect
	github.com/fatih/color v1.13.0 // indirect
	github.com/mattn/go-colorable v0.1.11 // indirect
	github.com/mattn/go-isatty v0.0.14 // indirect
	github.com/mattn/go-runewidth v0.0.12 // indirect
	github.com/rivo/uniseg v0.2.0 // indirect
)

replace (
	github.com/miekg/dns => github.com/cilium/dns v1.1.4-0.20190417235132-8e25ec9a0ff3
	github.com/optiopay/kafka => github.com/cilium/kafka v0.0.0-20180809090225-01ce283b732b

	go.universe.tf/metallb => github.com/cilium/metallb v0.1.1-0.20210831235406-48667b93284d

	// Using private fork of controller-tools. See commit msg for more context
	// as to why we are using a private fork.
	sigs.k8s.io/controller-tools => github.com/christarazi/controller-tools v0.6.2
)
