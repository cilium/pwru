// SPDX-License-Identifier: Apache-2.0
/* Copyright Martynas Pumputis */
/* Copyright Authors of Cilium */

package pwru

import (
	"fmt"
	"os"
	"strconv"
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
	FilterMarkMask          uint32
	FilterFunc              string
	FilterNonSkbFuncs       []string
	FilterTrackSkb          bool
	FilterTrackSkbByStackid bool
	FilterTraceTc           bool
	FilterTraceXdp          bool
	FilterTrackBpfHelpers   bool
	FilterIfname            string
	FilterPcap              string
	FilterTunnelPcap        string
	FilterKprobeBatch       uint

	OutputTS         string
	OutputMeta       bool
	OutputTuple      bool
	OutputSkb        bool
	OutputShinfo     bool
	OutputStack      bool
	OutputCaller     bool
	OutputLimitLines uint64
	OutputSkbCB      bool
	OutputFile       string
	OutputJson       bool
	OutputTCPFlags   bool
	OutputTunnel     bool

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
	flag.Var(newMarkFlagValue(&f.FilterMark, &f.FilterMarkMask), "filter-mark", "filter skb mark (format: mark[/mask], e.g., 0xa00/0xf00)")
	flag.BoolVar(&f.FilterTrackSkb, "filter-track-skb", false, "trace a packet even if it does not match given filters (e.g., after NAT or tunnel decapsulation)")
	flag.BoolVar(&f.FilterTrackSkbByStackid, "filter-track-skb-by-stackid", false, "trace a packet even after it is kfreed (e.g., traffic going through bridge)")
	flag.BoolVar(&f.FilterTraceTc, "filter-trace-tc", false, "trace TC bpf progs")
	flag.StringVar(&f.FilterTunnelPcap, "filter-tunnel-pcap", "", "pcap expression for vxlan/geneve tunnel (l3)")
	flag.BoolVar(&f.FilterTraceXdp, "filter-trace-xdp", false, "trace XDP bpf progs")
	flag.BoolVar(&f.FilterTrackBpfHelpers, "filter-track-bpf-helpers", false, "trace BPF helper functions")
	flag.StringVar(&f.FilterIfname, "filter-ifname", "", "filter skb ifname in --filter-netns (if not specified, use current netns)")
	flag.UintVar(&f.FilterKprobeBatch, "filter-kprobe-batch", 10, "batch size for kprobe attaching/detaching")
	flag.StringVar(&f.OutputTS, "timestamp", "none", "print timestamp per skb (\"current\", \"relative\", \"absolute\", \"none\")")
	flag.BoolVar(&f.OutputMeta, "output-meta", true, "print skb metadata")
	flag.BoolVar(&f.OutputTuple, "output-tuple", true, "print L4 tuple")
	flag.BoolVar(&f.OutputSkb, "output-skb", false, "print skb")
	flag.BoolVar(&f.OutputShinfo, "output-skb-shared-info", false, "print skb shared info")
	flag.BoolVar(&f.OutputTunnel, "output-tunnel", false, "print encapsulated tunnel header data")
	flag.BoolVar(&f.OutputStack, "output-stack", false, "print stack")
	flag.BoolVar(&f.OutputCaller, "output-caller", false, "print caller function name")
	flag.Uint64Var(&f.OutputLimitLines, "output-limit-lines", 0, "exit the program after the number of events has been received/printed")
	flag.BoolVar(&f.OutputSkbCB, "output-skb-cb", false, "print skb->cb")
	flag.BoolVar(&f.OutputTCPFlags, "output-tcp-flags", false, "print TCP flags")

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

type tcpFlag uint8

func (f tcpFlag) String() string {
	tcpFlags := []string{
		"FIN",
		"SYN",
		"RST",
		"PSH",
		"ACK",
		"URG",
		"ECE",
		"CWR",
	}

	var flags []string
	for i, flag := range tcpFlags {
		if f&(1<<uint(i)) != 0 {
			flags = append(flags, flag)
		}
	}

	return strings.Join(flags, "|")
}

type Tuple struct {
	Saddr   [16]byte
	Daddr   [16]byte
	Sport   uint16
	Dport   uint16
	L3Proto uint16
	L4Proto uint8
	TCPFlag tcpFlag
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
	TunnelTuple   Tuple
	PrintStackId  int64
	ParamSecond   uint64
	ParamThird    uint64
	CPU           uint32
}

type markFlagValue struct {
	mark *uint32
	mask *uint32
}

func newMarkFlagValue(mark, mask *uint32) *markFlagValue {
	return &markFlagValue{mark: mark, mask: mask}
}

func (f *markFlagValue) String() string {
	if *f.mask == 0 {
		return fmt.Sprintf("0x%x", *f.mark)
	}
	return fmt.Sprintf("0x%x/0x%x", *f.mark, *f.mask)
}

func (f *markFlagValue) Set(value string) error {
	parts := strings.Split(value, "/")

	mark, err := parseUint32HexOrDecimal(parts[0])
	if err != nil {
		return fmt.Errorf("invalid mark value: %v", err)
	}
	*f.mark = mark
	*f.mask = 0xffffffff

	if len(parts) > 1 {
		mask, err := parseUint32HexOrDecimal(parts[1])
		if err != nil {
			return fmt.Errorf("invalid mask value: %v", err)
		}
		*f.mask = mask
	}

	return nil
}

func (f *markFlagValue) Type() string {
	return "mark[/mask]"
}

func parseUint32HexOrDecimal(s string) (uint32, error) {
	base := 10
	if strings.HasPrefix(strings.ToLower(s), "0x") {
		s = s[2:]
		base = 16
	}

	val, err := strconv.ParseUint(s, base, 32)
	if err != nil {
		return 0, err
	}
	return uint32(val), nil
}
