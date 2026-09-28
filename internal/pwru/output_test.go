// SPDX-License-Identifier: Apache-2.0
/* Copyright Authors of Cilium */

package pwru

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"strings"
	"testing"
	"time"
)

type testWriter struct {
	n   int
	err error
}

func (w testWriter) Write([]byte) (int, error) {
	return w.n, w.err
}

func TestPrintError(t *testing.T) {
	sinkErr := errors.New("sink failed")
	tests := []struct {
		name    string
		writer  io.Writer
		wantErr error
	}{
		{name: "writer error", writer: testWriter{err: sinkErr}, wantErr: sinkErr},
		{name: "short write", writer: testWriter{}, wantErr: io.ErrShortWrite},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := newBenchmarkOutput(tt.writer)
			if err := out.Print(newBenchmarkEvent()); !errors.Is(err, tt.wantErr) {
				t.Fatalf("Print() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestGetAbsoluteTs(t *testing.T) {
	ts := getAbsoluteTs()
	t.Logf("absolute timestamp: %s", ts)

	// ISO 8601 date-time with milliseconds: 2006-01-02T15:04:05.000
	re := regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}$`)
	if !re.MatchString(ts) {
		t.Fatalf("timestamp %q does not match ISO 8601 format", ts)
	}

	if _, err := time.Parse(absoluteTS, ts); err != nil {
		t.Fatalf("failed to parse timestamp %q: %v", ts, err)
	}
}

func TestJSONOutput(t *testing.T) {
	const (
		tcpFlagSYN tcpFlag = 1 << 1
		tcpFlagACK tcpFlag = 1 << 4
		wantFlags          = "SYN|ACK"
	)

	tupleEvent := func() []*Event {
		event := newBenchmarkEvent()
		event.Tuple.TCPFlag = tcpFlagSYN | tcpFlagACK
		event.TunnelTuple = event.Tuple
		return []*Event{event}
	}
	tupleFlags := func(outputTunnel, outputTCPFlags bool) func(*Flags) {
		return func(f *Flags) {
			f.OutputTuple = !outputTunnel
			f.OutputTunnel = outputTunnel
			f.OutputTCPFlags = outputTCPFlags
		}
	}
	checkTuple := func(field, absentField string, wantFlagsPresent bool) func(t *testing.T, got map[string]any, raw string) {
		return func(t *testing.T, got map[string]any, raw string) {
			tuple, ok := got[field].(map[string]any)
			if !ok {
				t.Fatalf("missing %s field in json output: %s", field, raw)
			}
			if _, ok := got[absentField]; ok {
				t.Fatalf("unexpected %s field in json output: %s", absentField, raw)
			}
			flags, flagsPresent := tuple["flags"]
			if flagsPresent != wantFlagsPresent {
				t.Fatalf("%s.flags presence = %v, want %v: %s", field, flagsPresent, wantFlagsPresent, raw)
			}
			if wantFlagsPresent && flags != wantFlags {
				t.Fatalf("%s.flags = %v, want %s: %s", field, flags, wantFlags, raw)
			}
		}
	}

	cbEvent := func() []*Event {
		event := newBenchmarkEvent()
		event.Meta.Cb = [5]uint32{1, 2, 3, 4, 5}
		return []*Event{event}
	}
	checkCB := func(wantPresent bool) func(t *testing.T, got map[string]any, raw string) {
		return func(t *testing.T, got map[string]any, raw string) {
			if _, ok := got["cb"]; ok != wantPresent {
				t.Fatalf("cb presence = %v, want %v: %s", ok, wantPresent, raw)
			}
		}
	}

	tests := []struct {
		name   string
		flags  func(f *Flags)  // nil keeps newBenchmarkOutput's defaults
		events func() []*Event // nil sends a single unmodified benchmark event
		check  func(t *testing.T, got map[string]any, raw string)
	}{
		{
			name:   "tuple flags off",
			flags:  tupleFlags(false, false),
			events: tupleEvent,
			check:  checkTuple("tuple", "tunnel_tuple", false),
		},
		{
			name:   "tuple flags on",
			flags:  tupleFlags(false, true),
			events: tupleEvent,
			check:  checkTuple("tuple", "tunnel_tuple", true),
		},
		{
			name:   "tunnel tuple flags off",
			flags:  tupleFlags(true, false),
			events: tupleEvent,
			check:  checkTuple("tunnel_tuple", "tuple", false),
		},
		{
			name:   "tunnel tuple flags on",
			flags:  tupleFlags(true, true),
			events: tupleEvent,
			check:  checkTuple("tunnel_tuple", "tuple", true),
		},
		{
			name:   "cb disabled",
			events: cbEvent,
			check:  checkCB(false),
		},
		{
			name:   "cb output skb cb",
			flags:  func(f *Flags) { f.OutputSkbCB = true },
			events: cbEvent,
			check:  checkCB(true),
		},
		{
			name:   "cb trace tc",
			flags:  func(f *Flags) { f.FilterTraceTc = true },
			events: cbEvent,
			check:  checkCB(true),
		},
		{
			name: "cpu zero",
			events: func() []*Event {
				event := newBenchmarkEvent()
				event.CPU = 0
				return []*Event{event}
			},
			check: func(t *testing.T, got map[string]any, raw string) {
				if cpu, ok := got["cpu"]; !ok || cpu != float64(0) {
					t.Fatalf("cpu = %v, present = %v; want 0, true: %s", cpu, ok, raw)
				}
			},
		},
		{
			name:  "relative timestamp",
			flags: func(f *Flags) { f.OutputTS = "relative" },
			events: func() []*Event {
				first := newBenchmarkEvent()
				first.Timestamp = 100
				second := newBenchmarkEvent()
				second.Timestamp = 250
				return []*Event{first, second}
			},
			check: func(t *testing.T, got map[string]any, raw string) {
				if got["time"] != float64(150) {
					t.Fatalf("relative time = %v, want 150: %s", got["time"], raw)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			out := newBenchmarkOutput(&buf)
			if tt.flags != nil {
				tt.flags(out.flags)
			}

			events := []*Event{newBenchmarkEvent()}
			if tt.events != nil {
				events = tt.events()
			}
			for _, event := range events {
				if err := out.PrintJson(event); err != nil {
					t.Fatalf("PrintJson() error = %v", err)
				}
			}

			lines := bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte{'\n'})
			var got map[string]any
			if err := json.Unmarshal(lines[len(lines)-1], &got); err != nil {
				t.Fatalf("failed to unmarshal json output: %v", err)
			}
			tt.check(t, got, buf.String())
		})
	}
}

func TestSetJSONPacketData(t *testing.T) {
	d := &jsonPrinter{}
	flags := &Flags{OutputSkb: true, OutputShinfo: true}

	setJSONPacketData(d, flags, "skb", "shared info")

	if d.SkbMetadata != "skb" {
		t.Fatalf("skb_metadata = %q, want %q", d.SkbMetadata, "skb")
	}
	if d.Shinfo != "shared info" {
		t.Fatalf("skb_shared_info = %q, want %q", d.Shinfo, "shared info")
	}
}

// newCacheOutput returns a benchmark output with every cache cap/refresh knob
// zeroed so individual tests can set only the knobs they exercise.
func newCacheOutput(writer *bytes.Buffer) *output {
	o := newBenchmarkOutput(writer)
	o.lastSeenSkbCap = 0
	o.procCacheCap = 0
	o.procCacheRefresh = 0
	return o
}

// TestLastSeenSkbOnlyWhenRelative is regression test #1 from issue #708:
// non-relative timestamp modes must not grow the lastSeenSkb cache.
func TestLastSeenSkbOnlyWhenRelative(t *testing.T) {
	for _, mode := range []string{"none", "absolute", "current"} {
		t.Run("gated/"+mode, func(t *testing.T) {
			o := newCacheOutput(&bytes.Buffer{})
			o.flags.OutputTS = mode
			for i := 0; i < 100; i++ {
				e := newBenchmarkEvent()
				e.SkbAddr = uint64(0x1000 + i)
				if err := o.Print(e); err != nil {
					t.Fatal(err)
				}
			}
			if got := len(o.lastSeenSkb); got != 0 {
				t.Fatalf("OutputTS=%q grew lastSeenSkb to %d, want 0", mode, got)
			}
		})
	}
}

// TestLastSeenSkbBounded is regression test #2 from issue #708: an insertion
// count above the configured capacity must not retain every entry.
func TestLastSeenSkbBounded(t *testing.T) {
	cases := []struct {
		name      string
		cap       int
		inserts   int
		unbounded bool
	}{
		{name: "unbounded", cap: 0, inserts: 100, unbounded: true},
		{name: "bounded-5", cap: 5, inserts: 100},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := newCacheOutput(&bytes.Buffer{})
			o.flags.OutputTS = "relative"
			o.lastSeenSkbCap = tc.cap
			for i := 0; i < tc.inserts; i++ {
				e := newBenchmarkEvent()
				e.SkbAddr = uint64(0x2000 + i)
				if err := o.Print(e); err != nil {
					t.Fatal(err)
				}
			}
			got := len(o.lastSeenSkb)
			if tc.unbounded && got != tc.inserts {
				t.Fatalf("unbounded lastSeenSkb len = %d, want %d", got, tc.inserts)
			}
			if !tc.unbounded && got > tc.cap {
				t.Fatalf("lastSeenSkb grew to %d, want <= %d", got, tc.cap)
			}
			if got == 0 {
				t.Fatalf("relative mode recorded no last-seen timestamps")
			}
		})
	}
}

// TestProcCacheBounded verifies procCache stops growing once it hits its cap,
// instead of retaining every PID encountered (half of issue #708).
func TestProcCacheBounded(t *testing.T) {
	const cap = 32
	o := newCacheOutput(&bytes.Buffer{})
	o.procCacheCap = cap

	orig := processNameResolver
	defer func() { processNameResolver = orig }()
	seen := 0
	processNameResolver = func(pid int) string {
		seen++
		return fmt.Sprintf("p:%d", pid)
	}

	const inserts = 1000
	for i := 0; i < inserts; i++ {
		_ = o.getExecName(10_000 + i)
	}
	if got := len(o.procCache); got > cap {
		t.Fatalf("procCache grew to %d, want <= %d", got, cap)
	}
	if seen == 0 {
		t.Fatal("resolver was never called")
	}
	t.Logf("procCache bounded to %d after %d PIDs (resolver called %d times)",
		len(o.procCache), inserts, seen)
}

// TestGetExecNameRefreshesOnReuse is the core regression for the "stale PID
// attribution" half of issue #708: when a PID is reused by a new process its
// cached name must be refreshed rather than returned forever.
func TestGetExecNameRefreshesOnReuse(t *testing.T) {
	o := newCacheOutput(&bytes.Buffer{})
	// A very short refresh window so a reused PID is re-resolved promptly.
	o.procCacheRefresh = 4

	orig := processNameResolver
	defer func() { processNameResolver = orig }()

	// A PID that outlives the refresh window must be re-resolved and can pick up
	// a new owner's name.
	owner := 0
	processNameResolver = func(pid int) string {
		owner++
		return fmt.Sprintf("owner%d:%d", owner, pid)
	}

	// Warm the cache: the first call resolves, the next few hits.
	first := o.getExecName(9876)
	_ = o.getExecName(9876)
	_ = o.getExecName(9876)

	// Simulate PID reuse by the next incarnation of the process.
	const reuseOwner = 100
	owner = reuseOwner
	// Force the refresh window to elapse without resolving other PIDs.
	o.procGetSeq += int64(o.procCacheRefresh) + 1
	second := o.getExecName(9876)

	if first == second {
		t.Fatalf("reused PID 9876 still resolved to stale name %q after refresh", first)
	}
	t.Logf("PID reused: %q -> %q", first, second)
}

// TestGetExecNameCacheHit verifies the fast path stays cache-only (no resolver
// call) while a pid is the same and the refresh window hasn't elapsed.
func TestGetExecNameCacheHit(t *testing.T) {
	o := newCacheOutput(&bytes.Buffer{})
	o.procCacheRefresh = 1000

	orig := processNameResolver
	defer func() { processNameResolver = orig }()
	calls := 0
	processNameResolver = func(pid int) string {
		calls++
		return fmt.Sprintf("resolved:%d", pid)
	}

	// First call populates the cache.
	first := o.getExecName(4321)
	if calls != 1 {
		t.Fatalf("resolver called %d times, want 1 on first lookup", calls)
	}
	got := o.getExecName(4321) // within the refresh window -> cache hit
	if got != first {
		t.Fatalf("cache hit returned %q, want %q", got, first)
	}
	if calls != 1 {
		t.Fatalf("resolver called %d times on a cache hit, want 1", calls)
	}
}

// TestOutputCacheEvictionLogs verifies eviction is observable: the cache-bounding
// path emits a log line, so the behavior is testable and debuggable while we
// exercise the fix.
func TestOutputCacheEvictionLogs(t *testing.T) {
	var logBuf bytes.Buffer
	origLog := slog.Default()
	defer slog.SetDefault(origLog)
	slog.SetDefault(slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug})))

	o := newCacheOutput(&bytes.Buffer{})
	o.flags.OutputTS = "relative"
	o.lastSeenSkbCap = 4

	orig := processNameResolver
	defer func() { processNameResolver = orig }()
	processNameResolver = func(pid int) string { return "p:" + fmt.Sprint(pid) }

	// 100 distinct SKB addresses against a 4-entry cap forces lastSeenSkb evictions.
	for i := 0; i < 100; i++ {
		e := newBenchmarkEvent()
		e.SkbAddr = uint64(30_000 + i)
		if err := o.Print(e); err != nil {
			t.Fatal(err)
		}
	}
	if got := len(o.lastSeenSkb); got > 4 {
		t.Fatalf("lastSeenSkb grew to %d, want <= 4", got)
	}
	if !strings.Contains(logBuf.String(), "evicted lastSeenSkb entries") {
		t.Fatalf("expected a lastSeenSkb eviction log, got:\n%s", logBuf.String())
	}
}
