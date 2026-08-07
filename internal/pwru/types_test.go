// SPDX-License-Identifier: Apache-2.0
/* Copyright Authors of Cilium */

package pwru

import (
	"encoding/hex"
	"fmt"
	"math"
	"strings"
	"testing"
)

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

func TestPrintBpfmapValueStringTruncatesOversizedFields(t *testing.T) {
	tests := []struct {
		name    string
		size    uint32
		wantLen int
	}{
		{"zero", 0, 0},
		{"maximum captured", 256, 256},
		{"oversized", 257, 256},
		{"maximum uint32", math.MaxUint32, 256},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := printBpfmapValue{KeySize: tt.size, ValueSize: tt.size}
			for i := range v.Key {
				v.Key[i] = byte(i)
				v.Value[i] = byte(i)
			}

			got := v.String()
			want := fmt.Sprintf(
				"key(%d):\n%svalue(%d):\n%s",
				tt.size, hex.Dump(v.Key[:tt.wantLen]),
				tt.size, hex.Dump(v.Value[:tt.wantLen]),
			)
			if !strings.Contains(got, want) {
				t.Fatalf("String() missing expected dump:\n%s", got)
			}
		})
	}
}
