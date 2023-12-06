package pwru

import (
	"bufio"
	"os"
	"sort"
	"strconv"
	"strings"
)

type ksym struct {
	addr uint64
	name string
}

type byAddr []*ksym

func (a byAddr) Len() int           { return len(a) }
func (a byAddr) Less(i, j int) bool { return a[i].addr < a[j].addr }
func (a byAddr) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }

type Addr2Name struct {
	Addr2NameMap   map[uint64]*ksym
	Addr2NameSlice []*ksym
	Name2AddrMap   map[string][]uintptr
}

func (a *Addr2Name) findNearestSym(ip uint64) string {
	total := len(a.Addr2NameSlice)
	i, j := 0, total
	for i < j {
		h := int(uint(i+j) >> 1)
		if a.Addr2NameSlice[h].addr <= ip {
			if h+1 < total && a.Addr2NameSlice[h+1].addr > ip {
				return a.Addr2NameSlice[h].name
			}
			i = h + 1
		} else {
			j = h
		}
	}
	return a.Addr2NameSlice[i-1].name
}

func ParseKallsyms(funcs Funcs, all bool) (Addr2Name, BpfProgName2Addr, error) {
	a2n := Addr2Name{
		Addr2NameMap: make(map[uint64]*ksym),
		Name2AddrMap: make(map[string][]uintptr),
	}
	n2a := BpfProgName2Addr{}

	file, err := os.Open("/proc/kallsyms")
	if err != nil {
		return a2n, n2a, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.Split(scanner.Text(), " ")
		name, isBpfProg := extractBpfProgName(line[2])
		if all || (funcs[name] > 0) {
			addr, err := strconv.ParseUint(line[0], 16, 64)
			if err != nil {
				return a2n, n2a, err
			}
			sym := &ksym{
				addr: addr,
				name: name,
			}
			a2n.Addr2NameMap[addr] = sym
			a2n.Name2AddrMap[name] = append(a2n.Name2AddrMap[name], uintptr(addr))
			if all {
				a2n.Addr2NameSlice = append(a2n.Addr2NameSlice, sym)
			}
			if isBpfProg {
				n2a[name] = addr
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return a2n, n2a, err
	}

	if all {
		sort.Sort(byAddr(a2n.Addr2NameSlice))
	}

	return a2n, n2a, nil
}

func extractBpfProgName(name string) (string, bool) {
	if !strings.HasPrefix(name, "bpf_prog_") || !strings.HasSuffix(name, "[bpf]") {
		return name, false
	}

	// The symbol of bpf prog is "bpf_prog_<tag>_<name>\t[bpf]". We want
	// to get the tag and the name.

	items := strings.Split(name, "_")
	if len(items) > 3 {
		name = strings.Join(items[3:], "_")
		name = strings.TrimSpace(name[:len(name)-5])
	}

	return name, true
}
