// SPDX-License-Identifier: Apache-2.0
/* Copyright Authors of Cilium */

package pwru

import "testing"

func TestMarkFlagValue(t *testing.T) {
	var mark, mask uint32
	f := newMarkFlagValue(&mark, &mask)

	if got, want := f.String(), "0x0/0x0"; got != want {
		t.Fatalf("default String() = %q, want %q", got, want)
	}

	if err := f.Set("0xa5"); err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	if mark != 0xa5 || mask != 0xffffffff {
		t.Fatalf("Set() = mark %#x, mask %#x; want mark %#x, mask %#x", mark, mask, uint32(0xa5), uint32(0xffffffff))
	}

	if err := f.Set("0xaf/0x0f"); err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	if mark != 0xaf || mask != 0x0f {
		t.Fatalf("Set() = mark %#x, mask %#x; want mark %#x, mask %#x", mark, mask, uint32(0xaf), uint32(0x0f))
	}
}
