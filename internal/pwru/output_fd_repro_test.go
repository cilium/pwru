// SPDX-License-Identifier: Apache-2.0
/* Copyright Authors of Cilium */

package pwru

import (
	"os"
	"testing"
)

func TestGetIfacesDoesNotLeakNamespaceFDs(t *testing.T) {
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}

	_, _ = getIfaces()

	after, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatalf("getIfaces left %d namespace descriptors open", len(after)-len(before))
	}
}
