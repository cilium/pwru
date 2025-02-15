package tui

import (
	"fmt"
	"testing"

	"github.com/cilium/pwru/internal/pwru"
)

func TestRev(t *testing.T) {
	tp := pwru.Tuple{
		Saddr: [16]byte{1, 1, 1, 1},
		Daddr: [16]byte{2, 2, 2, 2},
	}
	fmt.Println(tp.Saddr)
	fmt.Println(tp.Daddr)

	tp = revTuple(tp)
	fmt.Println(tp.Saddr)
	fmt.Println(tp.Daddr)

}
