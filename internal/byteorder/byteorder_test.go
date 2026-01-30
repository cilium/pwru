// SPDX-License-Identifier: Apache-2.0
// Copyright 2017-2022 Authors of Cilium

package byteorder

import (
	"testing"

	"golang.org/x/sys/cpu"
)

func TestHostToNetwork(t *testing.T) {
	if cpu.IsBigEndian {
		if got, want := HostToNetwork16(0xAABB), uint16(0xAABB); got != want {
			t.Errorf("HostToNetwork16(0xAABB) = %#X, want %#X", got, want)
		}
		if got, want := HostToNetwork32(0xAABBCCDD), uint32(0xAABBCCDD); got != want {
			t.Errorf("HostToNetwork32(0xAABBCCDD) = %#X, want %#X", got, want)
		}
	} else {
		if got, want := HostToNetwork16(0xAABB), uint16(0xBBAA); got != want {
			t.Errorf("HostToNetwork16(0xAABB) = %#X, want %#X", got, want)
		}
		if got, want := HostToNetwork32(0xAABBCCDD), uint32(0xDDCCBBAA); got != want {
			t.Errorf("HostToNetwork32(0xAABBCCDD) = %#X, want %#X", got, want)
		}
	}
}
