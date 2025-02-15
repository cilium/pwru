package tui

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"syscall"

	"github.com/cilium/pwru/internal/byteorder"
	"github.com/cilium/pwru/internal/pwru"
	"github.com/cilium/pwru/tui/draw"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

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

type App struct {
	tapp  *tview.Application
	root  *tview.TreeNode
	stats *tview.TextView
	count uint64

	lastViewed   *pwru.Event
	groupFns     []GroupFn
	groupFnNames []string

	addr2Name pwru.Addr2Name
}

func renderPacketText(e *pwru.Event, addr2Name pwru.Addr2Name) string {
	skbAddr := fmt.Sprintf("0x%016x", e.SkbAddr)
	mark := fmt.Sprintf("0x%08x", e.Meta.Mark)
	masks := decodeMark(e.Meta.Mark)
	ifindex := fmt.Sprintf("%d", e.Meta.Ifindex)
	fname := "[no_data]"
	fn, ok := addr2Name.Addr2NameMap[e.Addr]
	if ok {
		fname = fn.Name()
	}

	portStr := func(n uint16) string {
		return strconv.Itoa(int(byteorder.NetworkToHost16(n)))
	}
	saddr := addrToStr(e.Tuple.L3Proto, e.Tuple.Saddr) + ":" + portStr(e.Tuple.Sport)
	daddr := addrToStr(e.Tuple.L3Proto, e.Tuple.Daddr) + ":" + portStr(e.Tuple.Dport)

	w := 70
	txt := draw.Header(w) + "\n"
	txt += draw.Line(w, " SOCKET BUFFER DATA (SKB):") + "\n"
	txt += draw.Break(w) + "\n"
	txt += draw.Line(w, " skb_addr:"+skbAddr) + "\n"
	txt += draw.Line(w, " mark:"+mark) + "\n"
	for _, mask := range masks {
		txt += draw.Line(w, " *"+mask) + "\n"
	}
	txt += draw.Line(w, " ifindex:"+ifindex) + "\n"
	txt += draw.Line(w, " func_name:"+fname) + "\n"
	txt += draw.Line(w, " saddr:"+saddr) + "\n"
	txt += draw.Line(w, " daddr:"+daddr) + "\n"

	saddr = addrToStr(e.TunnelTuple.L3Proto, e.TunnelTuple.Saddr) + ":" + portStr(e.TunnelTuple.Sport)
	daddr = addrToStr(e.TunnelTuple.L3Proto, e.TunnelTuple.Daddr) + ":" + portStr(e.TunnelTuple.Dport)
	txt += draw.Line(w, " "+draw.Header(w-4)) + "\n"

	txt += draw.Line(w, " "+draw.Line(w-4, "TUNNEL:")) + "\n"
	txt += draw.Line(w, " "+draw.Break(w-4)) + "\n"
	txt += draw.Line(w, " "+draw.Line(w-4, "saddr: "+saddr)) + "\n"
	txt += draw.Line(w, " "+draw.Line(w-4, "daddr: "+daddr)) + "\n"
	for _, mask := range masks {
		txt += draw.Line(w, " "+draw.Line(w-4, " * "+mask)) + "\n"
	}
	txt += draw.Line(w, " "+draw.Footer(w-4)) + "\n"

	txt += draw.Footer(w)
	return txt
}

func New(addr2Name pwru.Addr2Name, groupFnNames []string, kfuncs map[string]int, availableFuncs []string) (*App, error) {
	fns, err := ParseGroupingString(groupFnNames)
	if err != nil {
		return nil, fmt.Errorf("%w: \n%s", err, allFoldFns())
	}
	app := &App{
		addr2Name:    addr2Name,
		groupFns:     fns,
		groupFnNames: groupFnNames,
	}
	tapp := tview.NewApplication()
	tree := tview.NewTreeView()

	// Create the root node
	root := tview.NewTreeNode("traces").
		SetColor(tcell.ColorBlue)
	app.root = root

	// Set the root node in the tree
	tree.SetRoot(root).
		SetCurrentNode(root)

	pktView := tview.NewTextView().SetText(renderPacketText(&pwru.Event{}, addr2Name))
	// Enable selection and set a selection handler
	tree.SetChangedFunc(func(node *tview.TreeNode) {
		if node == nil {
			return
		}
		if node.GetText() == "traces" {
			return
		}
		if len(node.GetChildren()) == 0 {
			e, ok := node.GetReference().(*pwru.Event)
			if !ok {
				return
			}

			pktView.SetText(renderPacketText(e, addr2Name))
			app.lastViewed = e
		}
	})
	tree.SetSelectedFunc(func(node *tview.TreeNode) {
		if node == nil {
			return
		}
		if node.GetText() == "traces" {
			return
		}
		if len(node.GetChildren()) > 0 {
			node.SetExpanded(!node.IsExpanded()) // Toggle expansion
		}
	})

	funcsTree := tview.NewTreeView().SetGraphics(false)
	funcsTree.SetPrefixes([]string{"", "* "})
	root = tview.NewTreeNode("funcs")
	enabled := tview.NewTreeNode(fmt.Sprintf("enabled (%d/%d)", len(kfuncs), len(availableFuncs)))
	enabled.SetExpanded(true)
	available := tview.NewTreeNode(fmt.Sprintf("available (%d)", len(availableFuncs)))
	available.SetExpanded(false)
	var first *tview.TreeNode
	for fname := range kfuncs {
		n := tview.NewTreeNode("[*] " + fname)
		if first == nil {
			first = n
		}
		enabled.AddChild(n)
	}
	for _, fname := range availableFuncs {
		_, ok := kfuncs[fname]
		if ok {
			available.AddChild(tview.NewTreeNode("[*] " + fname))
		} else {
			available.AddChild(tview.NewTreeNode(fname))
		}
	}
	root.AddChild(enabled)
	root.AddChild(available)
	funcsTree.SetCurrentNode(first)

	funcsTree.SetRoot(root)
	funcsTree.SetCurrentNode(root)
	funcsTree.SetBorder(true)
	funcsTree.SetBorderColor(tcell.ColorTeal)
	funcsTree.SetSelectedFunc(func(node *tview.TreeNode) {
		if node == nil {
			return
		}
		txt := node.GetText()
		if txt == "" || strings.HasPrefix(txt, "available") || strings.HasPrefix(txt, "enabled") {
			node.SetExpanded(!node.IsExpanded()) // Toggle expansion
		}
	})

	app.stats = tview.NewTextView()
	w := 70
	statsTxt := draw.Header(w) + "\n"
	statsTxt += draw.Line(w, " RUNTIME STATS:") + "\n"
	statsTxt += draw.Break(w) + "\n"
	statsTxt += draw.Line(w, " group_folds:"+strings.Join(app.groupFnNames, ".")) + "\n"
	statsTxt += draw.Line(w, " trace_count:"+strconv.Itoa(int(app.count))) + "\n"
	statsTxt += draw.Footer(w)
	app.stats.SetText(statsTxt)

	flex := tview.NewFlex().
		AddItem(tree, 0, 1, false). // traces
		AddItem(tview.NewFlex().SetDirection(tview.FlexRow).
			AddItem(pktView, 0, 3, false).
			AddItem(app.stats, 7, 1, false).
			AddItem(funcsTree, 18, 1, false), 0, 2, true)

	app.tapp = tapp.SetRoot(flex, true).SetFocus(flex)
	app.tapp.SetFocus(tree)

	currFocus := 0
	inputPanels := []tview.Primitive{tree, funcsTree}
	flex.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		key := event.Key()
		if key == tcell.KeyTab || key == tcell.Key(tcell.WheelDown) {
			currFocus += 1
			app.tapp.SetFocus(inputPanels[currFocus%len(inputPanels)])
		}
		if event.Rune() == 'f' {
			app.tapp.SetFocus(funcsTree)
		}
		return event
	})
	return app, nil
}

func (a *App) Run(ctx context.Context) {
	go func() {
		a.tapp.Run()
	}()
	go func() {
		<-ctx.Done()
		a.tapp.Stop()
	}()
}

var (
	MARK_MAGIC_HOST_MASK     uint32 = 0x0F00
	MARK_MAGIC_PROXY_INGRESS uint32 = 0x0A00
	MARK_MAGIC_PROXY_EGRESS  uint32 = 0x0B00
	MARK_MAGIC_HOST          uint32 = 0x0C00
	MARK_MAGIC_DECRYPT       uint32 = 0x0D00
	MARK_MAGIC_ENCRYPT       uint32 = 0x0E00
	MARK_MAGIC_IDENTITY      uint32 = 0x0F00
	MARK_MAGIC_TO_PROXY      uint32 = 0x0200
)

func decodeMark(m uint32) []string {
	pre := "(Cilium) MARK_MAGIC"
	hasMark := func(mark uint32) bool {
		return mark&MARK_MAGIC_HOST_MASK&m == mark
	}
	marks := []string{}
	if hasMark(MARK_MAGIC_PROXY_INGRESS) {
		marks = append(marks, pre+"_PROXY_INGRESS")
	}
	if hasMark(MARK_MAGIC_PROXY_EGRESS) {
		marks = append(marks, pre+"_PROXY_EGRESS")
	}
	if hasMark(MARK_MAGIC_HOST) {
		marks = append(marks, pre+"_MAGIC_HOST")
	}
	if hasMark(MARK_MAGIC_DECRYPT) {
		marks = append(marks, pre+"_MAGIC_DECRYPT")
	}
	if hasMark(MARK_MAGIC_ENCRYPT) {
		marks = append(marks, pre+"_MAGIC_ENCRYPT")
	}
	if hasMark(MARK_MAGIC_IDENTITY) {
		marks = append(marks, pre+"_MAGIC_IDENTITY")
	}
	if hasMark(MARK_MAGIC_TO_PROXY) {
		marks = append(marks, pre+"_MAGIC_TO_PROXY")
	}
	return marks
}

type traceTree struct {
	root *tview.TreeNode
}

func revTuple(tpl pwru.Tuple) pwru.Tuple {
	out := tpl
	copy(out.Daddr[:], tpl.Saddr[:])
	copy(out.Saddr[:], tpl.Daddr[:])
	out.Sport = tpl.Dport
	out.Dport = tpl.Sport
	return out
}

type GroupFn func(e *pwru.Event) string

func (a *App) InsertGroup(e *pwru.Event) {
	insertGroup(a.root, e, append(a.groupFns, func(e *pwru.Event) string {
		return "[trace] " + a.addr2Name.Addr2NameMap[e.Addr].Name()
	}))
	a.count++
	w := 70
	statsTxt := draw.Header(w) + "\n"
	statsTxt += draw.Line(w, " RUNTIME STATS:") + "\n"
	statsTxt += draw.Break(w) + "\n"
	statsTxt += draw.Line(w, " group_folds:"+strings.Join(a.groupFnNames, ".")) + "\n"
	statsTxt += draw.Line(w, " trace_count:"+strconv.Itoa(int(a.count))) + "\n"
	statsTxt += draw.Footer(w)
	a.stats.SetText(statsTxt)
	// TODO: Buffer these a bit
	a.tapp.Draw()
}

func insertGroup(curr *tview.TreeNode, e *pwru.Event, groupFns []GroupFn) {
	if len(groupFns) == 0 {
		return
	}

	gfn := groupFns[0]
	id := gfn(e)
	if len(groupFns) == 1 {
		// child fn -> always add without grouping.
		leaf := tview.NewTreeNode(id)
		leaf.SetColor(tcell.ColorPink)
		// leaf.SetReference(id)
		leaf.SetReference(e)
		leaf.SetExpanded(false)
		curr.AddChild(leaf)
		return
	} else {
		groupFns = groupFns[1:len(groupFns)]
	}

	var target *tview.TreeNode

	for _, grpNode := range curr.GetChildren() {
		obj := grpNode.GetReference()
		if obj == nil {
			continue
		}
		gn, ok := obj.(string)
		if !ok {
			continue
		}

		if gn == id {
			target = grpNode
			break
		}
	}
	if target == nil {
		target = tview.NewTreeNode(id)
		target.SetColor(tcell.ColorGreen)
		target.SetReference(id)
		target.SetExpanded(false)
		curr.AddChild(target)
	}

	insertGroup(target, e, groupFns)
}

var groupFnLookup = map[string]GroupFn{
	"tunnel-ip-version": groupByIPversion(true),
	"ip-version":        groupByIPversion(false),
	"tuple":             GroupByTupleConnection(false),
	"tunnel-tuple":      GroupByTupleConnection(true),
	"tunnel":            GroupByTupleConnection(true),
	"dir":               groupByDir(false),
	"tunnel-dir":        groupByDir(true),
	"tun-dir":           groupByDir(true),
	"mark": func(e *pwru.Event) string {
		return fmt.Sprintf("0x%08x", e.Meta.Mark)
	},
}

func groupByDir(tunnel bool) GroupFn {
	return func(e *pwru.Event) string {
		tuple := e.Tuple
		if tunnel {
			tuple = e.TunnelTuple
		}

		dir := "[→] egress"
		if tuple.Sport < tuple.Dport {
			dir = "[←] ingress"
		}
		return dir
	}
}

func allFoldFns() string {
	out := ""
	for k := range groupFnLookup {
		out += "* " + k + "\n"
	}
	return out
}

func ParseGroupingString(fnNames []string) ([]GroupFn, error) {
	out := []GroupFn{}
	for _, fname := range fnNames {
		fn, ok := groupFnLookup[fname]
		if !ok {
			return nil, fmt.Errorf("no such fold fn %s", fname)
		}
		out = append(out, func(e *pwru.Event) string {
			return fmt.Sprintf("[%s] %s", fname, fn(e))
		})
	}
	return out, nil
}

func groupByIPversion(tunnel bool) GroupFn {
	return func(e *pwru.Event) string {
		tuple := e.Tuple
		if tunnel {
			tuple = e.TunnelTuple
		}
		switch tuple.L3Proto {
		case syscall.ETH_P_IP:
			return "ipv4"
		case syscall.ETH_P_IPV6:
			return "ipv6"
		default:
			return "unknown"
		}
	}
}

func GroupByTupleConnection(tunnel bool) GroupFn {
	return func(e *pwru.Event) string {
		tuple := e.Tuple
		if tunnel {
			tuple = e.TunnelTuple
		}

		if tuple.Sport < tuple.Dport {
			tuple = revTuple(tuple)
		}

		return pwru.GetTuple(tuple, false)
	}
}

// Proposal: Fold operation, for a node holding a event ptr, we can fold that by any thing in there
// For example. Event{}.FoldBySource(1234), FoldByTimeChunk(5*time.Minute).
func Insert(root *tview.TreeNode, e *pwru.Event, addr2Name pwru.Addr2Name, groupByTunnel bool) {
	tuple := func(ev *pwru.Event) pwru.Tuple {
		if groupByTunnel {
			return ev.TunnelTuple
		}
		return ev.Tuple
	}

	tuplePairs := root.GetChildren()
	var pairRef *pwru.Event
	// Pair node folds on 4-tuple (todo: make this for both directions).
	var pairNode *tview.TreeNode
	dir := "[→] "
	for _, tpn := range tuplePairs {
		obj := tpn.GetReference()
		if obj == nil {
			continue
		}
		// TODO: just store 4-tuple
		tp, ok := obj.(*pwru.Event)
		if !ok {
			continue
		}

		equals := func(a, b pwru.Tuple) bool {
			return bytes.Compare(a.Saddr[:4], b.Saddr[:4]) == 0 &&
				bytes.Compare(a.Daddr[:4], b.Daddr[:4]) == 0 &&
				a.Sport == b.Sport && a.Dport == b.Dport
		}
		eq := equals(tuple(tp), tuple(e))
		revEq := equals(revTuple(tuple(tp)), tuple(e))
		if revEq {
			dir = "[←] "
		}
		if eq || revEq {
			pairRef = tp
			pairNode = tpn
			break
		}
	}
	// If no such tuple pair, add one.
	if pairRef == nil {
		pairNode = tview.NewTreeNode(pwru.GetTuple(tuple(e), true))
		pairNode.SetColor(tcell.ColorGreen)
		pairNode.SetReference(e)
		pairNode.SetExpanded(false)
		root.AddChild(pairNode)
	}

	fn := addr2Name.Addr2NameMap[e.Addr].Name()
	flowNode := tview.NewTreeNode(fmt.Sprintf(dir+"%s", fn)).SetColor(tcell.ColorPink)
	flowNode.SetReference(e)

	pairNode.AddChild(flowNode)
}
