// SPDX-License-Identifier: Apache-2.0
/* Copyright Authors of Cilium */

package pwru

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
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
