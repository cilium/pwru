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
	"strings"
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

const (
	eventTypeKprobe = iota
	eventTypeKprobeMulti
	eventTypeTracingTc
	eventTypeTracingXdp
)

type output struct {
	flags          *Flags
	lastSeenSkb    map[uint64]uint64 // skb addr => last seen TS
	printSkbMap    *ebpf.Map
	printShinfoMap *ebpf.Map
	printStackMap  *ebpf.Map
	addr2name      Addr2Name
	skbMetadata    []*SkbMetadata
	xdpMetadata    []*SkbMetadata
	writer         *os.File
	kprobeMulti    bool
	kfreeReasons   map[uint64]string
	ifaceCache     map[uint64]map[uint32]string
}

// outputStructured is a struct to hold the data for the json output
type jsonPrinter struct {
	Skb         string      `json:"skb,omitempty"`
	Shinfo      string      `json:"skb_shared_info,omitempty"`
	Cpu         uint32      `json:"cpu,omitempty"`
	Process     string      `json:"process,omitempty"`
	Func        string      `json:"func,omitempty"`
	CallerFunc  string      `json:"caller_func,omitempty"`
	Time        interface{} `json:"time,omitempty"`
	Netns       uint32      `json:"netns,omitempty"`
	Mark        uint32      `json:"mark,omitempty"`
	Iface       string      `json:"iface,omitempty"`
	Proto       uint16      `json:"proto,omitempty"`
	Mtu         uint32      `json:"mtu,omitempty"`
	Len         uint32      `json:"len,omitempty"`
	Cb          [5]uint32   `json:"cb,omitempty"`
	Tuple       *jsonTuple  `json:"tuple,omitempty"`
	TunnelTuple *jsonTuple  `json:"tunnel_tuple,omitempty"`
	Stack       interface{} `json:"stack,omitempty"`
	SkbMetadata interface{} `json:"skb_metadata,omitempty"`
}

type jsonTuple struct {
	Saddr string `json:"saddr,omitempty"`
	Daddr string `json:"daddr,omitempty"`
	Sport uint16 `json:"sport,omitempty"`
	Dport uint16 `json:"dport,omitempty"`
	Proto uint8  `json:"proto,omitempty"`
	Flags string `json:"flags,omitempty"`
}

func centerAlignString(s string, width int) string {
	if len(s) >= width {
		return s
	}
	leftPadding := (width - len(s)) / 2
	rightPadding := width - len(s) - leftPadding
	return fmt.Sprintf("%s%s%s", strings.Repeat(" ", leftPadding), s, strings.Repeat(" ", rightPadding))
}

func NewOutput(flags *Flags, printSkbMap, printShinfoMap, printStackMap *ebpf.Map, addr2Name Addr2Name, skbMds, xdpMds []*SkbMetadata, kprobeMulti bool, btfSpec *btf.Spec) (*output, error) {
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
		log.Printf("Unable to load packet drop reasons: %v", err)
	}

	var ifs map[uint64]map[uint32]string
	if flags.OutputMeta {
		ifs, err = getIfaces()
		if err != nil {
			log.Printf("Failed to retrieve all ifaces from all network namespaces: %v. Some iface names might be not shown.", err)
		}
	}

	return &output{
		flags:          flags,
		lastSeenSkb:    map[uint64]uint64{},
		printSkbMap:    printSkbMap,
		printShinfoMap: printShinfoMap,
		printStackMap:  printStackMap,
		addr2name:      addr2Name,
		skbMetadata:    skbMds,
		xdpMetadata:    xdpMds,
		writer:         writer,
		kprobeMulti:    kprobeMulti,
		kfreeReasons:   reasons,
		ifaceCache:     ifs,
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
		fmt.Fprintf(o.writer, "%-12s ", "TIME")
	}
	fmt.Fprintf(o.writer, "%-18s %-3s %-16s", "SKB", "CPU", "PROCESS")
	if o.flags.OutputTS != "none" {
		fmt.Fprintf(o.writer, " %-16s", "TIMESTAMP")
	}
	if o.flags.OutputMeta {
		fmt.Fprintf(o.writer, " %-10s %-8s %16s %-6s %-5s %-5s", "NETNS", "MARK/x", centerAlignString("IFACE", 16), "PROTO", "MTU", "LEN")
		if o.flags.FilterTraceTc || o.flags.OutputSkbCB {
			fmt.Fprintf(o.writer, " %-56s", "__sk_buff->cb[]")
		}
	}
	if o.flags.OutputTuple {
		fmt.Fprintf(o.writer, " %s", "TUPLE")
	}
	fmt.Fprintf(o.writer, " %s", "FUNC")
	if o.flags.OutputCaller {
		fmt.Fprintf(o.writer, " %s", "CALLER")
	}
	if o.flags.OutputTunnel {
		fmt.Fprintf(o.writer, " %s", "TUNNEL")
	}
	fmt.Fprintf(o.writer, "\n")
}

// PrintJson prints the event in JSON format
func (o *output) PrintJson(event *Event) {
	// crate an instance of the outputStructured struct to hold the data
	d := &jsonPrinter{}

	// add the data to the struct
	d.Skb = fmt.Sprintf("%#x", event.SkbAddr)
	d.Cpu = event.CPU
	d.Process = getExecName(int(event.PID))
	d.Func = getOutFuncName(o, event, event.Addr)
	if o.flags.OutputCaller {
		d.CallerFunc = o.addr2name.findNearestSym(event.CallerAddr)
	}

	o.lastSeenSkb[event.SkbAddr] = event.Timestamp

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
		if o.flags.FilterTraceTc || o.flags.OutputSkbCB {
			d.Cb = event.Meta.Cb
		}
	}

	if o.flags.OutputTuple {
		t := &jsonTuple{}
		t.Saddr = addrToStr(event.Tuple.L3Proto, event.Tuple.Saddr)
		t.Daddr = addrToStr(event.Tuple.L3Proto, event.Tuple.Daddr)
		t.Sport = byteorder.NetworkToHost16(event.Tuple.Sport)
		t.Dport = byteorder.NetworkToHost16(event.Tuple.Dport)
		t.Proto = event.Tuple.L4Proto
		t.Flags = event.Tuple.TCPFlag.String()
		d.Tuple = t
	}

	if o.flags.OutputTuple {
		t := &jsonTuple{}
		t.Saddr = addrToStr(event.TunnelTuple.L3Proto, event.TunnelTuple.Saddr)
		t.Daddr = addrToStr(event.TunnelTuple.L3Proto, event.TunnelTuple.Daddr)
		t.Sport = byteorder.NetworkToHost16(event.TunnelTuple.Sport)
		t.Dport = byteorder.NetworkToHost16(event.TunnelTuple.Dport)
		t.Proto = event.TunnelTuple.L4Proto
		d.TunnelTuple = t
	}

	if o.flags.OutputStack && event.PrintStackId > 0 {
		d.Stack = getStackData(event, o)
	}

	if o.flags.OutputSkb {
		d.SkbMetadata = getSkbData(event, o)
	}

	if o.flags.OutputShinfo {
		d.SkbMetadata = getShinfoData(event, o)
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
	if last, found := o.lastSeenSkb[event.SkbAddr]; found {
		ts = ts - last
	} else {
		ts = 0
	}
	return ts
}

func getExecName(pid int) string {
	p, err := ps.FindProcess(pid)
	execName := fmt.Sprintf("<empty>:%d", pid)
	if err == nil && p != nil {
		execName = fmt.Sprintf("%s:%d", p.ExecutablePath(), pid)
		if len(execName) > 16 {
			execName = execName[len(execName)-16:]
			bexecName := []byte(execName)
			bexecName[0] = '~'
			execName = string(bexecName)
		}
	}
	return execName
}

func getTuple(tpl Tuple, outputTCPFlags bool) (tupleData string) {
	var l4Info string
	if tpl.L4Proto == syscall.IPPROTO_TCP && tpl.TCPFlag != 0 && outputTCPFlags {
		l4Info = fmt.Sprintf("%s:%s", protoToStr(tpl.L4Proto), tpl.TCPFlag)
	} else {
		l4Info = protoToStr(tpl.L4Proto)
	}

	tupleData = fmt.Sprintf("%s:%d->%s:%d(%s)",
		addrToStr(tpl.L3Proto, tpl.Saddr), byteorder.NetworkToHost16(tpl.Sport),
		addrToStr(tpl.L3Proto, tpl.Daddr), byteorder.NetworkToHost16(tpl.Dport),
		l4Info)
	return tupleData
}

func getTupleData(event *Event, outputTCPFlags bool) (tupleData string) {
	return getTuple(event.Tuple, outputTCPFlags)
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
	id := uint64(event.PrintSkbId)

	b, err := o.printSkbMap.LookupBytes(&id)
	if err != nil {
		return ""
	}

	defer o.printSkbMap.Delete(&id)

	if len(b) < 4 {
		return ""
	}

	dataLen := byteorder.Native.Uint32(b[:4])
	if dataLen+4 > uint32(len(b)) {
		dataLen = uint32(len(b)) - 4
	}
	return "\n" + string(b[4:dataLen+4])
}

func getShinfoData(event *Event, o *output) (shinfoData string) {
	id := uint64(event.PrintShinfoId)

	b, err := o.printShinfoMap.LookupBytes(&id)
	if err != nil {
		return ""
	}

	defer o.printShinfoMap.Delete(&id)

	if len(b) < 4 {
		return ""
	}

	dataLen := byteorder.Native.Uint32(b[:4])
	if dataLen+4 > uint32(len(b)) {
		dataLen = uint32(len(b)) - 4
	}
	return "\n" + string(b[4:dataLen+4])
}

func getMetaData(event *Event, o *output) (metaData string) {
	metaData = fmt.Sprintf("%-10s %-8s %16s %#04x %-5s %-5s",
		fmt.Sprintf("%d", event.Meta.Netns),
		fmt.Sprintf("%x", event.Meta.Mark),
		centerAlignString(o.getIfaceName(event.Meta.Netns, event.Meta.Ifindex), 16),
		byteorder.NetworkToHost16(event.Meta.Proto),
		fmt.Sprintf("%d", event.Meta.MTU),
		fmt.Sprintf("%d", event.Meta.Len))
	return metaData
}

func getCb(event *Event) (cb string) {
	res := []string{}
	for _, val := range event.Meta.Cb {
		res = append(res, fmt.Sprintf("0x%08X", val))
	}
	return fmt.Sprintf("[%s]", strings.Join(res, ","))
}

func getOutFuncName(o *output, event *Event, addr uint64) string {
	var funcName string

	if ksym, ok := o.addr2name.Addr2NameMap[addr]; ok {
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
	} else if funcName == "sk_skb_reason_drop" {
		if reason, ok := o.kfreeReasons[event.ParamThird]; ok {
			outFuncName = fmt.Sprintf("%s(%s)", funcName, reason)
		} else {
			outFuncName = fmt.Sprintf("%s (%d)", funcName, event.ParamThird)
		}
	}

	if event.Type != eventTypeKprobe {
		switch event.Type {
		case eventTypeTracingTc:
			outFuncName += "(tc)"
		case eventTypeTracingXdp:
			outFuncName += "(xdp)"
		}
	}

	return outFuncName
}

var (
	maxTupleLengthSeen int
	maxFuncLengthSeen  int
)

func fprintWithPadding(writer *os.File, data string, maxLenSeen *int) {
	if len(data) > *maxLenSeen {
		*maxLenSeen = len(data)
	}
	formatter := fmt.Sprintf(" %%-%ds", *maxLenSeen)
	fmt.Fprintf(writer, formatter, data)
}

func (o *output) Print(event *Event) {
	if o.flags.OutputTS == "absolute" {
		fmt.Fprintf(o.writer, "%-12s ", getAbsoluteTs())
	}

	execName := getExecName(int(event.PID))

	ts := event.Timestamp
	if o.flags.OutputTS == "relative" {
		ts = getRelativeTs(event, o)
	}

	outFuncName := getOutFuncName(o, event, event.Addr)

	fmt.Fprintf(o.writer, "%-18s %-3s %-16s", fmt.Sprintf("%#x", event.SkbAddr),
		fmt.Sprintf("%d", event.CPU), fmt.Sprintf("%s", execName))
	if o.flags.OutputTS != "none" {
		fmt.Fprintf(o.writer, " %-16d", ts)
	}
	o.lastSeenSkb[event.SkbAddr] = event.Timestamp

	if o.flags.OutputMeta {
		fmt.Fprintf(o.writer, " %s", getMetaData(event, o))
		if o.flags.FilterTraceTc || o.flags.OutputSkbCB {
			fmt.Fprintf(o.writer, " %s", getCb(event))
		}
	}

	if o.flags.OutputTuple {
		fprintWithPadding(o.writer, getTupleData(event, o.flags.OutputTCPFlags), &maxTupleLengthSeen)
	}

	if o.flags.OutputCaller {
		fprintWithPadding(o.writer, outFuncName, &maxFuncLengthSeen)
		fmt.Fprintf(o.writer, " %s", o.addr2name.findNearestSym(event.CallerAddr))
	} else {
		fmt.Fprintf(o.writer, " %s", outFuncName)
	}

	if event.Type != eventTypeTracingXdp && len(o.skbMetadata) > 0 {
		outputSkbMetadata(o.writer, o.skbMetadata, event.SkbMetadata[:])
	} else if event.Type == eventTypeTracingXdp && len(o.xdpMetadata) > 0 {
		outputSkbMetadata(o.writer, o.xdpMetadata, event.SkbMetadata[:])
	}

	if o.flags.OutputStack && event.PrintStackId > 0 {
		fmt.Fprintf(o.writer, "%s", getStackData(event, o))
	}

	if o.flags.OutputSkb {
		fmt.Fprintf(o.writer, "%s", getSkbData(event, o))
	}

	if o.flags.OutputShinfo {
		fmt.Fprintf(o.writer, "%s", getShinfoData(event, o))
	}

	if o.flags.OutputTunnel {
		fmt.Fprintf(o.writer, " %s", getTuple(event.TunnelTuple, o.flags.OutputTCPFlags))
	}

	fmt.Fprintln(o.writer)
}

func (o *output) getIfaceName(netnsInode, ifindex uint32) string {
	if ifaces, ok := o.ifaceCache[uint64(netnsInode)]; ok {
		if name, ok := ifaces[ifindex]; ok {
			ifname := fmt.Sprintf("%s:%d", name, ifindex)
			if len(ifname) > 16 {
				ifname = ifname[len(ifname)-16:]
				bifname := []byte(ifname)
				bifname[0] = '~'
				ifname = string(bifname)
			}
			return ifname
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

// getKFreeSKBReasons derives SKB drop reasons from the "skb_drop_reason" enum
// defined in /include/net/dropreason.h.
func getKFreeSKBReasons(spec *btf.Spec) (map[uint64]string, error) {
	if _, err := spec.AnyTypeByName("kfree_skb_reason"); err != nil {
		if _, err := spec.AnyTypeByName("sk_skb_reason_drop"); err != nil {
			// Kernel is too old to have either kfree_skb_reason or sk_skb_reason_drop
			// see https://github.com/torvalds/linux/commit/ba8de796baf4bdc03530774fb284fe3c97875566
			return nil, nil
		}
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
