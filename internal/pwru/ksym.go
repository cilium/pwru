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

func GetAddrs(funcs Funcs, all bool) (Addr2Name, error) {
	a2n := Addr2Name{
		Addr2NameMap: make(map[uint64]*ksym),
	}

	file, err := os.Open("/proc/kallsyms")
	if err != nil {
		return a2n, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.Split(scanner.Text(), " ")
		name := line[2]
		if all || (funcs[name] > 0) {
			addr, err := strconv.ParseUint(line[0], 16, 64)
			if err != nil {
				return a2n, err
			}
			sym := &ksym{
				addr: addr,
				name: name,
			}
			a2n.Addr2NameMap[addr] = sym
			if all {
				a2n.Addr2NameSlice = append(a2n.Addr2NameSlice, sym)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return a2n, err
	}

	if all {
		sort.Sort(byAddr(a2n.Addr2NameSlice))
	}

	return a2n, nil
}
