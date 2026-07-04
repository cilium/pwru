// SPDX-License-Identifier: Apache-2.0
/* Copyright Authors of Cilium */

package pwru

import (
	"bytes"
	"encoding/json"
	"regexp"
	"syscall"
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

func TestPrintJSONTunnelTupleOn(t *testing.T) {
	outBuf := &bytes.Buffer{}
	out := newBenchmarkOutput(outBuf)
	out.flags.OutputTuple = false
	out.flags.OutputTunnel = true

	event := newBenchmarkEvent()
	event.TunnelTuple = Tuple{
		Saddr:   [16]byte{10, 0, 0, 1},
		Daddr:   [16]byte{10, 0, 0, 2},
		Sport:   4789,
		Dport:   8472,
		L3Proto: syscall.ETH_P_IP,
		L4Proto: syscall.IPPROTO_UDP,
	}

	if err := out.PrintJson(event); err != nil {
		t.Fatalf("PrintJson() error = %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(outBuf.Bytes(), &got); err != nil {
		t.Fatalf("failed to unmarshal json output: %v", err)
	}

	if _, ok := got["tuple"]; ok {
		t.Fatalf("unexpected tuple field in json output: %s", outBuf.String())
	}
	if _, ok := got["tunnel_tuple"]; !ok {
		t.Fatalf("missing tunnel_tuple field in json output: %s", outBuf.String())
	}
}

func TestPrintJSONTunnelTupleOff(t *testing.T) {
	outBuf := &bytes.Buffer{}
	out := newBenchmarkOutput(outBuf)
	out.flags.OutputTuple = true
	out.flags.OutputTunnel = false

	event := newBenchmarkEvent()
	event.TunnelTuple = Tuple{
		Saddr:   [16]byte{10, 0, 0, 1},
		Daddr:   [16]byte{10, 0, 0, 2},
		Sport:   4789,
		Dport:   8472,
		L3Proto: syscall.ETH_P_IP,
		L4Proto: syscall.IPPROTO_UDP,
	}

	if err := out.PrintJson(event); err != nil {
		t.Fatalf("PrintJson() error = %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(outBuf.Bytes(), &got); err != nil {
		t.Fatalf("failed to unmarshal json output: %v", err)
	}

	if _, ok := got["tuple"]; !ok {
		t.Fatalf("missing tuple field in json output: %s", outBuf.String())
	}
	if _, ok := got["tunnel_tuple"]; ok {
		t.Fatalf("unexpected tunnel_tuple field in json output: %s", outBuf.String())
	}
}
