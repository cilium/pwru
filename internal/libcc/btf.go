// SPDX-License-Identifier: Apache-2.0
/* Copyright Leon Hwang */
/* Copyright Authors of Cilium */

package libcc

import (
	"fmt"
	"strings"

	"github.com/cilium/ebpf/btf"
)

func isBigEndian(t btf.Type) bool {
	for {
		switch v := t.(type) {
		case *btf.Typedef:
			t = v.Type
			if strings.HasPrefix(v.Name, "__be") {
				return true
			}
		case *btf.Volatile:
			t = v.Type
		case *btf.Const:
			t = v.Type
		case *btf.Restrict:
			t = v.Type
		default:
			return false
		}
	}
}

func underlyingType(t btf.Type) btf.Type {
	for {
		switch v := t.(type) {
		case *btf.Typedef:
			t = v.Type
		case *btf.Volatile:
			t = v.Type
		case *btf.Const:
			t = v.Type
		case *btf.Restrict:
			t = v.Type
		case *btf.TypeTag:
			t = v.Type
		default:
			return t
		}
	}
}

func findStructMember(strct *btf.Struct, name string) (*btf.Member, error) {
	for _, m := range strct.Members {
		if m.Name == name {
			return &m, nil
		}

		if m.Name != "" {
			continue
		}

		var (
			mem *btf.Member
			err error
		)

		// embedded anonymous struct/union
		switch v := m.Type.(type) {
		case *btf.Struct:
			mem, err = findStructMember(v, name)
		case *btf.Union:
			mem, err = findUnionMember(v, name)

		default:
			return nil, fmt.Errorf("unexpected anonymous member type: %s", m.Type)
		}

		if err == errNotFound {
			continue
		}
		if err == nil {
			return mem, nil
		}
		return nil, fmt.Errorf("failed to find member %s in struct %s: %w", name, strct.Name, err)
	}

	return nil, errNotFound
}

func findUnionMember(union *btf.Union, name string) (*btf.Member, error) {
	for _, m := range union.Members {
		if m.Name == name {
			return &m, nil
		}

		if m.Name != "" {
			continue
		}

		var (
			mem *btf.Member
			err error
		)

		// embedded anonymous struct/union
		switch v := m.Type.(type) {
		case *btf.Struct:
			mem, err = findStructMember(v, name)
		case *btf.Union:
			mem, err = findUnionMember(v, name)

		default:
			return nil, fmt.Errorf("unexpected anonymous member type: %s", m.Type)
		}

		if err == errNotFound {
			continue
		}
		if err == nil {
			return mem, nil
		}
		return nil, fmt.Errorf("failed to find member %s in union %s: %w", name, union.Name, err)
	}

	return nil, errNotFound
}

func structMemberOffset(strct *btf.Struct, name string, offset uint32) (uint32, error) {
	for _, m := range strct.Members {
		if m.Name == name {
			return offset + m.Offset.Bytes(), nil
		}

		if m.Name != "" {
			continue
		}

		var (
			off uint32
			err error
		)

		// embedded anonymous struct/union
		switch v := m.Type.(type) {
		case *btf.Struct:
			off, err = structMemberOffset(v, name, offset+m.Offset.Bytes())
		case *btf.Union:
			off, err = unionMemberOffset(v, name, offset+m.Offset.Bytes())

		default:
			return 0, fmt.Errorf("unexpected anonymous member type: %s", m.Type)
		}

		if err == errNotFound {
			continue
		}
		if err == nil {
			return off, nil
		}
		return 0, fmt.Errorf("failed to find %s member in struct %s: %w", name, strct.Name, err)
	}

	return 0, errNotFound
}

func unionMemberOffset(union *btf.Union, name string, offset uint32) (uint32, error) {
	for _, m := range union.Members {
		if m.Name == name {
			return offset + m.Offset.Bytes(), nil
		}

		if m.Name != "" {
			continue
		}

		var (
			off uint32
			err error
		)

		// embedded anonymous struct/union
		switch v := m.Type.(type) {
		case *btf.Struct:
			off, err = structMemberOffset(v, name, offset+m.Offset.Bytes())
		case *btf.Union:
			off, err = unionMemberOffset(v, name, offset+m.Offset.Bytes())

		default:
			return 0, fmt.Errorf("unexpected anonymous member type: %s", m.Type)
		}

		if err == errNotFound {
			continue
		}
		if err == nil {
			return off, nil
		}
		return 0, fmt.Errorf("failed to find %s member in union %s: %w", name, union.Name, err)
	}

	return 0, errNotFound
}

func findStruct(spec *btf.Spec, name string) (*btf.Struct, error) {
	types, err := spec.AnyTypesByName(name)
	if err != nil {
		return nil, fmt.Errorf("failed to find %s type: %w", name, err)
	}
	if len(types) == 0 {
		return nil, fmt.Errorf("%s type not found", name)
	}

	typ, ok := types[0].(*btf.Struct)
	if !ok {
		return nil, fmt.Errorf("%s is not a struct", name)
	}

	return typ, nil
}

func struct2pointer(strct *btf.Struct) *btf.Pointer {
	return &btf.Pointer{
		Target: strct,
	}
}
