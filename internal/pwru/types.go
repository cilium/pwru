// SPDX-License-Identifier: Apache-2.0
/* Copyright Martynas Pumputis */
/* Copyright Authors of Cilium */

package pwru

import (
	"fmt"
	"os"
	"strings"

	flag "github.com/spf13/pflag"
)

const (
	MaxStackDepth = 50

	BackendKprobe      = "kprobe"
	BackendKprobeMulti = "kprobe-multi"
)

type Flags struct {
	ShowVersion bool
	ShowHelp    bool

	KernelBTF string

	FilterNetns             string
	FilterMark              uint32
	FilterFunc              string
	FilterNonSkbFuncs       []string
	FilterTrackSkb          bool
	FilterTrackSkbByStackid bool
	FilterTraceTc           bool
	FilterTraceXdp          bool
	FilterTrackBpfHelpers   bool
	FilterIfname            string
	FilterPcap              string
	FilterKprobeBatch       uint

	OutputTS         string
	OutputMeta       bool
	OutputTuple      bool
	OutputSkb        bool
	OutputShinfo     bool
	OutputStack      bool
	OutputCaller     bool
	OutputLimitLines uint64
	OutputFile       string
	OutputJson       bool

	KMods    []string
	AllKMods bool

	ReadyFile string

	Backend string
}

func (f *Flags) SetFlags() {
	flag.BoolVarP(&f.ShowHelp, "help", "h", false, "display this message and exit")
	flag.BoolVar(&f.ShowVersion, "version", false, "show pwru version and exit")
	flag.StringVar(&f.KernelBTF, "kernel-btf", "", "specify kernel BTF file")
	flag.StringSliceVar(&f.KMods, "kmods", nil, "list of kernel modules names to attach to")
	flag.BoolVar(&f.AllKMods, "all-kmods", false, "attach to all available kernel modules")
	flag.StringVar(&f.FilterFunc, "filter-func", "", "filter kernel functions to be probed by name (exact match, supports RE2 regular expression)")
	flag.StringSliceVar(&f.FilterNonSkbFuncs, "filter-non-skb-funcs", nil, "filter non-skb kernel functions to be probed (--filter-track-skb-by-stackid will be enabled)")
	flag.StringVar(&f.FilterNetns, "filter-netns", "", "filter netns (\"/proc/<pid>/ns/net\", \"inode:<inode>\")")
	flag.Uint32Var(&f.FilterMark, "filter-mark", 0, "filter skb mark")
	flag.BoolVar(&f.FilterTrackSkb, "filter-track-skb", false, "trace a packet even if it does not match given filters (e.g., after NAT or tunnel decapsulation)")
	flag.BoolVar(&f.FilterTrackSkbByStackid, "filter-track-skb-by-stackid", false, "trace a packet even after it is kfreed (e.g., traffic going through bridge)")
	flag.BoolVar(&f.FilterTraceTc, "filter-trace-tc", false, "trace TC bpf progs")
	flag.BoolVar(&f.FilterTraceXdp, "filter-trace-xdp", false, "trace XDP bpf progs")
	flag.BoolVar(&f.FilterTrackBpfHelpers, "filter-track-bpf-helpers", false, "trace BPF helper functions")
	flag.StringVar(&f.FilterIfname, "filter-ifname", "", "filter skb ifname in --filter-netns (if not specified, use current netns)")
	flag.UintVar(&f.FilterKprobeBatch, "filter-kprobe-batch", 10, "batch size for kprobe attaching/detaching")
	flag.StringVar(&f.OutputTS, "timestamp", "none", "print timestamp per skb (\"current\", \"relative\", \"absolute\", \"none\")")
	flag.BoolVar(&f.OutputMeta, "output-meta", true, "print skb metadata")
	flag.BoolVar(&f.OutputTuple, "output-tuple", true, "print L4 tuple")
	flag.BoolVar(&f.OutputSkb, "output-skb", false, "print skb")
	flag.BoolVar(&f.OutputShinfo, "output-skb-shared-info", false, "print skb shared info")
	flag.BoolVar(&f.OutputStack, "output-stack", false, "print stack")
	flag.BoolVar(&f.OutputCaller, "output-caller", false, "print caller function name")
	flag.Uint64Var(&f.OutputLimitLines, "output-limit-lines", 0, "exit the program after the number of events has been received/printed")

	flag.StringVar(&f.OutputFile, "output-file", "", "write traces to file")

	flag.BoolVar(&f.OutputJson, "output-json", false, "output traces in JSON format")

	flag.StringVar(&f.ReadyFile, "ready-file", "", "create file after all BPF progs are attached")
	flag.Lookup("ready-file").Hidden = true

	flag.StringVar(&f.Backend, "backend", "",
		fmt.Sprintf("Tracing backend('%s', '%s'). Will auto-detect if not specified.", BackendKprobe, BackendKprobeMulti))

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] [pcap-filter]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "    Available pcap-filter: see \"man 7 pcap-filter\"\n")
		fmt.Fprintf(os.Stderr, "    Available options:\n")
		flag.PrintDefaults()
	}
}

func (f *Flags) PrintHelp() {
	flag.Usage()
}

func (f *Flags) Parse() {
	flag.Parse()
	f.FilterPcap = strings.Join(flag.Args(), " ")
	if len(f.FilterNonSkbFuncs) > 0 || f.FilterTrackBpfHelpers {
		f.FilterTrackSkbByStackid = true
	}
}

type Tuple struct {
	Saddr   [16]byte
	Daddr   [16]byte
	Sport   uint16
	Dport   uint16
	L3Proto uint16
	L4Proto uint8
	Pad     uint8
}

type Meta struct {
	Netns   uint32
	Mark    uint32
	Ifindex uint32
	Len     uint32
	MTU     uint32
	Proto   uint16
	Cb      [5]uint32
}

type StackData struct {
	IPs [MaxStackDepth]uint64
}

type Event struct {
	PID           uint32
	Type          uint32
	Addr          uint64
	CallerAddr    uint64
	SkbAddr       uint64
	Timestamp     uint64
	PrintSkbId    uint64
	PrintShinfoId uint64
	Meta          Meta
	Tuple         Tuple
	PrintStackId  int64
	ParamSecond   uint64
	ParamThird    uint64
	CPU           uint32
}
