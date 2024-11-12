// SPDX-License-Identifier: Apache-2.0
/* Copyright Leon Hwang */
/* Copyright Authors of Cilium */

package pwru

import (
	"fmt"

	"github.com/cilium/ebpf/btf"
)

func GetStructBtfID(btfSpec *btf.Spec, structName string) (btf.TypeID, error) {
	types, err := btfSpec.AnyTypesByName(structName)
	if err != nil {
		return 0, fmt.Errorf("failed to get BTF types by name %s: %w", structName, err)
	}

	for _, t := range types {
		if s, ok := t.(*btf.Struct); ok {
			return btfSpec.TypeID(s)
		}
	}

	return 0, fmt.Errorf("struct %s not found", structName)
}
