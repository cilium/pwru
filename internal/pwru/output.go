// SPDX-License-Identifier: Apache-2.0
/* Copyright Martynas Pumputis */
/* Copyright Authors of Cilium */

package pwru

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/jsimonetti/rtnetlink"
	"github.com/tklauser/ps"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"

	"github.com/cilium/pwru/internal/byteorder"
)

const absoluteTS string = "15:04:05.000"

type output struct {
	flags         *Flags
	lastSeenSkb   map[uint64]uint64 // skb addr => last seen TS
	printSkbMap   *ebpf.Map
	printStackMap *ebpf.Map
	addr2name     Addr2Name
	writer        *os.File
	kprobeMulti   bool
	kfreeReasons  map[uint64]string
	ifaceCache    map[uint64]map[uint32]string
}

// outputStructured is a struct to hold the data for the json output
type jsonPrinter struct {
	Skb         string      `json:"skb,omitempty"`
	Cpu         uint32      `json:"cpu,omitempty"`
	Process     string      `json:"process,omitempty"`
	Func        string      `json:"func,omitempty"`
	Time        interface{} `json:"time,omitempty"`
	Netns       uint32      `json:"netns,omitempty"`
	Mark        uint32      `json:"mark,omitempty"`
	Iface       string      `json:"iface,omitempty"`
	Proto       uint16      `json:"proto,omitempty"`
	Mtu         uint32      `json:"mtu,omitempty"`
	Len         uint32      `json:"len,omitempty"`
	Tuple       *jsonTuple  `json:"tuple,omitempty"`
	Stack       interface{} `json:"stack,omitempty"`
	SkbMetadata interface{} `json:"skb_metadata,omitempty"`
}

type jsonTuple struct {
	Saddr string `json:"saddr,omitempty"`
	Daddr string `json:"daddr,omitempty"`
	Sport uint16 `json:"sport,omitempty"`
	Dport uint16 `json:"dport,omitempty"`
	Proto uint8  `json:"proto,omitempty"`
}

func NewOutput(flags *Flags, printSkbMap *ebpf.Map, printStackMap *ebpf.Map,
	addr2Name Addr2Name, kprobeMulti bool, btfSpec *btf.Spec,
) (*output, error) {
	writer := os.Stdout

	if flags.OutputFile != "" {
		file, err := os.Create(flags.OutputFile)
		if err != nil {
			return nil, err
		}
		writer = file
	}

	reasons, err := getKFreeSKBReasons(btfSpec)
	if err != nil {
		log.Printf("Unable to load packet drop reaons: %v", err)
	}

	var ifs map[uint64]map[uint32]string
	if flags.OutputMeta {
		ifs, err = getIfaces()
		if err != nil {
			log.Printf("Failed to retrieve all ifaces from all network namespaces: %v. Some iface names might be not shown.", err)
		}
	}

	return &output{
		flags:         flags,
		lastSeenSkb:   map[uint64]uint64{},
		printSkbMap:   printSkbMap,
		printStackMap: printStackMap,
		addr2name:     addr2Name,
		writer:        writer,
		kprobeMulti:   kprobeMulti,
		kfreeReasons:  reasons,
		ifaceCache:    ifs,
	}, nil
}

func (o *output) Close() {
	if o.writer != os.Stdout {
		_ = o.writer.Sync()
		_ = o.writer.Close()
	}
}

func (o *output) PrintHeader() {
	if o.flags.OutputTS == "absolute" {
		fmt.Fprintf(o.writer, "%12s ", "TIME")
	}
	fmt.Fprintf(o.writer, "%18s %6s %16s %24s", "SKB", "CPU", "PROCESS", "FUNC")
	if o.flags.OutputTS != "none" {
		fmt.Fprintf(o.writer, " %16s", "TIMESTAMP")
	}
	fmt.Fprintf(o.writer, "\n")
}

// PrintJson prints the event in JSON format
func (o *output) PrintJson(event *Event) {
	// crate an instance of the outputStructured struct to hold the data
	d := &jsonPrinter{}

	// add the data to the struct
	d.Skb = fmt.Sprintf("%#x", event.SAddr)
	d.Cpu = event.CPU
	d.Process = getExecName(int(event.PID))
	d.Func = getOutFuncName(o, event, event.Addr)

	o.lastSeenSkb[event.SAddr] = event.Timestamp

	// add the timestamp to the struct if it is not set to none
	if o.flags.OutputTS != "none" {
		switch o.flags.OutputTS {
		case "absolute":
			d.Time = getAbsoluteTs()
		case "relative":
			d.Time = getRelativeTs(event, o)
		case "current":
			d.Time = event.Timestamp
		}
	}

	if o.flags.OutputMeta {
		d.Netns = event.Meta.Netns
		d.Mark = event.Meta.Mark
		d.Iface = o.getIfaceName(event.Meta.Netns, event.Meta.Ifindex)
		d.Proto = byteorder.NetworkToHost16(event.Meta.Proto)
		d.Mtu = event.Meta.MTU
		d.Len = event.Meta.Len
	}

	if o.flags.OutputTuple {
		t := &jsonTuple{}
		t.Saddr = addrToStr(event.Tuple.L3Proto, event.Tuple.Saddr)
		t.Daddr = addrToStr(event.Tuple.L3Proto, event.Tuple.Daddr)
		t.Sport = byteorder.NetworkToHost16(event.Tuple.Sport)
		t.Dport = byteorder.NetworkToHost16(event.Tuple.Dport)
		t.Proto = event.Tuple.L4Proto
		d.Tuple = t
	}

	if o.flags.OutputStack && event.PrintStackId > 0 {
		d.Stack = getStackData(event, o)
	}

	if o.flags.OutputSkb {
		d.SkbMetadata = getSkbData(event, o)
	}

	// Create new encoder to write the json to stdout or file depending on the flags
	encoder := json.NewEncoder(o.writer)
	encoder.SetEscapeHTML(false)

	err := encoder.Encode(d)

	if err != nil {
		log.Fatalf("Error encoding JSON: %s", err)
	}
}

func getAbsoluteTs() string {
	return time.Now().Format(absoluteTS)
}

func getRelativeTs(event *Event, o *output) uint64 {
	ts := event.Timestamp
	if last, found := o.lastSeenSkb[event.SAddr]; found {
		ts = ts - last
	} else {
		ts = 0
	}
	return ts
}

func getExecName(pid int) string {
	p, err := ps.FindProcess(pid)
	execName := fmt.Sprintf("<empty>:(%d)", pid)
	if err == nil && p != nil {
		return fmt.Sprintf("%s:%d", p.ExecutablePath(), pid)
	}
	return execName
}

func getAddrByArch(event *Event, o *output) (addr uint64) {
	switch runtime.GOARCH {
	case "amd64":
		addr = event.Addr
		if !o.kprobeMulti {
			addr -= 1
		}
	case "arm64":
		addr = event.Addr
	}
	return addr
}

func getTupleData(event *Event) (tupleData string) {
	tupleData = fmt.Sprintf("%s:%d->%s:%d(%s)",
		addrToStr(event.Tuple.L3Proto, event.Tuple.Saddr), byteorder.NetworkToHost16(event.Tuple.Sport),
		addrToStr(event.Tuple.L3Proto, event.Tuple.Daddr), byteorder.NetworkToHost16(event.Tuple.Dport),
		protoToStr(event.Tuple.L4Proto))
	return tupleData
}

func getStackData(event *Event, o *output) (stackData string) {
	var stack StackData
	id := uint32(event.PrintStackId)
	if err := o.printStackMap.Lookup(&id, &stack); err == nil {
		for _, ip := range stack.IPs {
			if ip > 0 {
				stackData += fmt.Sprintf("\n%s", o.addr2name.findNearestSym(ip))
			}
		}
	}
	_ = o.printStackMap.Delete(&id)
	return stackData
}

func getSkbData(event *Event, o *output) (skbData string) {
	id := uint32(event.PrintSkbId)
	if str, err := o.printSkbMap.LookupBytes(&id); err == nil {
		skbData = string(str)
	}
	return skbData
}

func getMetaData(event *Event, o *output) (metaData string) {
	metaData = fmt.Sprintf("netns=%d mark=%#x iface=%s proto=%#04x mtu=%d len=%d",
		event.Meta.Netns, event.Meta.Mark,
		o.getIfaceName(event.Meta.Netns, event.Meta.Ifindex),
		byteorder.NetworkToHost16(event.Meta.Proto), event.Meta.MTU, event.Meta.Len)
	return metaData
}

func getOutFuncName(o *output, event *Event, addr uint64) string {
	var funcName string

	if ksym, ok := o.addr2name.Addr2NameMap[addr]; ok {
		funcName = ksym.name
	} else if ksym, ok := o.addr2name.Addr2NameMap[addr-4]; runtime.GOARCH == "amd64" && ok {
		// Assume that function has ENDBR in its prelude (enabled by CONFIG_X86_KERNEL_IBT).
		// See https://lore.kernel.org/bpf/20220811091526.172610-5-jolsa@kernel.org/
		// for more ctx.
		funcName = ksym.name
	} else {
		funcName = fmt.Sprintf("0x%x", addr)
	}

	outFuncName := funcName
	if funcName == "kfree_skb_reason" {
		if reason, ok := o.kfreeReasons[event.ParamSecond]; ok {
			outFuncName = fmt.Sprintf("%s(%s)", funcName, reason)
		} else {
			outFuncName = fmt.Sprintf("%s (%d)", funcName, event.ParamSecond)
		}
	}

	return outFuncName
}

func (o *output) Print(event *Event) {
	if o.flags.OutputTS == "absolute" {
		fmt.Fprintf(o.writer, "%12s ", getAbsoluteTs())
	}

	execName := getExecName(int(event.PID))

	ts := event.Timestamp
	if o.flags.OutputTS == "relative" {
		ts = getRelativeTs(event, o)
	}

	// XXX: not sure why the -1 offset is needed on x86 but not on arm64
	addr := getAddrByArch(event, o)

	outFuncName := getOutFuncName(o, event, addr)

	fmt.Fprintf(o.writer, "%18s %6s %16s %24s", fmt.Sprintf("%#x", event.SAddr),
		fmt.Sprintf("%d", event.CPU), fmt.Sprintf("[%s]", execName), outFuncName)
	if o.flags.OutputTS != "none" {
		fmt.Fprintf(o.writer, " %16d", ts)
	}
	o.lastSeenSkb[event.SAddr] = event.Timestamp

	if o.flags.OutputMeta {
		fmt.Fprintf(o.writer, " %s", getMetaData(event, o))
	}

	if o.flags.OutputTuple {
		fmt.Fprintf(o.writer, " %s", getTupleData(event))
	}

	if o.flags.OutputStack && event.PrintStackId > 0 {
		fmt.Fprintf(o.writer, "%s", getStackData(event, o))
	}

	if o.flags.OutputSkb {
		fmt.Fprintf(o.writer, "%s", getSkbData(event, o))
	}

	fmt.Fprintln(o.writer)
}

func (o *output) getIfaceName(netnsInode, ifindex uint32) string {
	if ifaces, ok := o.ifaceCache[uint64(netnsInode)]; ok {
		if name, ok := ifaces[ifindex]; ok {
			return fmt.Sprintf("%d(%s)", ifindex, name)
		}
	}
	return fmt.Sprintf("%d", ifindex)
}

func protoToStr(proto uint8) string {
	switch proto {
	case syscall.IPPROTO_TCP:
		return "tcp"
	case syscall.IPPROTO_UDP:
		return "udp"
	case syscall.IPPROTO_ICMP:
		return "icmp"
	case syscall.IPPROTO_ICMPV6:
		return "icmp6"
	default:
		return ""
	}
}

func addrToStr(proto uint16, addr [16]byte) string {
	switch proto {
	case syscall.ETH_P_IP:
		return net.IP(addr[:4]).String()
	case syscall.ETH_P_IPV6:
		return fmt.Sprintf("[%s]", net.IP(addr[:]).String())
	default:
		return ""
	}
}

// getKFreeSKBReasons dervices SKB drop reasons from the "skb_drop_reason" enum
// defined in /include/net/dropreason.h.
func getKFreeSKBReasons(spec *btf.Spec) (map[uint64]string, error) {
	if _, err := spec.AnyTypeByName("kfree_skb_reason"); err != nil {
		// Kernel is too old to have kfree_skb_reason
		return nil, nil
	}

	var dropReasonsEnum *btf.Enum
	if err := spec.TypeByName("skb_drop_reason", &dropReasonsEnum); err != nil {
		return nil, fmt.Errorf("failed to find 'skb_drop_reason' enum: %v", err)
	}

	ret := map[uint64]string{}
	for _, val := range dropReasonsEnum.Values {
		ret[uint64(val.Value)] = val.Name
	}

	return ret, nil
}

func getIfaces() (map[uint64]map[uint32]string, error) {
	var err error
	procPath := "/proc"

	ifaceCache := make(map[uint64]map[uint32]string)

	dirs, err := os.ReadDir(procPath)
	if err != nil {
		return nil, err
	}

	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}

		// skip non-process dirs
		if _, err := strconv.Atoi(d.Name()); err != nil {
			continue
		}

		// get inode of netns
		path := filepath.Join(procPath, d.Name(), "ns", "net")
		fd, err0 := os.Open(path)
		if err0 != nil {
			err = errors.Join(err, err0)
			continue
		}
		var stat unix.Stat_t
		if err0 := unix.Fstat(int(fd.Fd()), &stat); err0 != nil {
			err = errors.Join(err, err0)
			continue
		}
		inode := stat.Ino

		if _, exists := ifaceCache[inode]; exists {
			continue // we already checked that netns
		}

		ifaces, err0 := getIfacesInNetNs(path)
		if err0 != nil {
			err = errors.Join(err, err0)
			continue
		}

		ifaceCache[inode] = ifaces

	}

	return ifaceCache, err
}

func getIfacesInNetNs(path string) (map[uint32]string, error) {
	current, err := netns.Get()
	if err != nil {
		return nil, err
	}

	remote, err := netns.GetFromPath(path)
	if err != nil {
		return nil, err
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if err := netns.Set(remote); err != nil {
		return nil, err
	}

	defer netns.Set(current)

	conn, err := rtnetlink.Dial(nil)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	msg, err := conn.Link.List()
	if err != nil {
		return nil, err
	}

	ifaces := make(map[uint32]string)
	for _, link := range msg {
		ifaces[link.Index] = link.Attributes.Name
	}

	return ifaces, nil
}
