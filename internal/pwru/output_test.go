// SPDX-License-Identifier: Apache-2.0
/* Copyright Authors of Cilium */

package pwru

import (
	"bytes"
	"encoding/json"
	"regexp"
	"testing"
	"time"
)

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

func TestPrintJSONTupleFields(t *testing.T) {
	const (
		tcpFlagSYN tcpFlag = 1 << 1
		tcpFlagACK tcpFlag = 1 << 4
		wantFlags          = "SYN|ACK"
	)

	tests := []struct {
		name           string
		outputTunnel   bool
		outputTCPFlags bool
	}{
		{
			name:           "tuple flags off",
			outputTCPFlags: false,
		},
		{
			name:           "tuple flags on",
			outputTCPFlags: true,
		},
		{
			name:           "tunnel tuple flags off",
			outputTunnel:   true,
			outputTCPFlags: false,
		},
		{
			name:           "tunnel tuple flags on",
			outputTunnel:   true,
			outputTCPFlags: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			outBuf := &bytes.Buffer{}
			out := newBenchmarkOutput(outBuf)
			out.flags.OutputTuple = !tt.outputTunnel
			out.flags.OutputTunnel = tt.outputTunnel
			out.flags.OutputTCPFlags = tt.outputTCPFlags

			event := newBenchmarkEvent()
			event.Tuple.TCPFlag = tcpFlagSYN | tcpFlagACK
			event.TunnelTuple = event.Tuple

			if err := out.PrintJson(event); err != nil {
				t.Fatalf("PrintJson() error = %v", err)
			}

			var got map[string]any
			if err := json.Unmarshal(outBuf.Bytes(), &got); err != nil {
				t.Fatalf("failed to unmarshal json output: %v", err)
			}

			tupleField, absentField := "tuple", "tunnel_tuple"
			if tt.outputTunnel {
				tupleField, absentField = absentField, tupleField
			}

			tuple, ok := got[tupleField].(map[string]any)
			if !ok {
				t.Fatalf("missing %s field in json output: %s", tupleField, outBuf.String())
			}
			if _, ok := got[absentField]; ok {
				t.Fatalf("unexpected %s field in json output: %s", absentField, outBuf.String())
			}

			flags, flagsPresent := tuple["flags"]
			if flagsPresent != tt.outputTCPFlags {
				t.Fatalf("%s.flags presence = %v, want %v: %s", tupleField, flagsPresent, tt.outputTCPFlags, outBuf.String())
			}
			if tt.outputTCPFlags && flags != wantFlags {
				t.Fatalf("%s.flags = %v, want %s: %s", tupleField, flags, wantFlags, outBuf.String())
			}
		})
	}
}
