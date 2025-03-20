package mybtf

import (
	"fmt"

	"github.com/cilium/ebpf/btf"
)

// FindStruct finds a struct by name in the BTF spec. It returns the very first
// struct with the given name even if there are multiple structs with the same
// name, i.e. Ubuntu 20.04 has a malformed BTF with multiple sk_buff structs.
func FindStruct(spec *btf.Spec, name string) (*btf.Struct, error) {
	types, err := spec.AnyTypesByName(name)
	if err != nil {
		return nil, fmt.Errorf("failed to find %s type: %w", name, err)
	}
	if len(types) == 0 {
		return nil, fmt.Errorf("struct '%s': %w", name, ErrNotFound)
	}

	typ, ok := types[0].(*btf.Struct)
	if !ok {
		return nil, fmt.Errorf("%s is not a struct", name)
	}

	return typ, nil
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

		if err == ErrNotFound {
			continue
		}
		if err == nil {
			return off, nil
		}
		return 0, fmt.Errorf("failed to find %s member in struct %s: %w", name, strct.Name, err)
	}

	return 0, ErrNotFound
}

// StructMemberOffset calculates the offset of a member in a struct, even if the
// member is in embedded anonymous struct/union.
func StructMemberOffset(strct *btf.Struct, name string) (uint32, error) {
	return structMemberOffset(strct, name, 0)
}

// FindStructMember finds a member in a struct by name, even if the member is in
// embedded anonymous struct/union.
func FindStructMember(strct *btf.Struct, name string) (*btf.Member, error) {
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
			mem, err = FindStructMember(v, name)
		case *btf.Union:
			mem, err = FindUnionMember(v, name)

		default:
			return nil, fmt.Errorf("unexpected anonymous member type: %s", m.Type)
		}

		if err == ErrNotFound {
			continue
		}
		if err == nil {
			return mem, nil
		}
		return nil, fmt.Errorf("failed to find member %s in struct %s: %w", name, strct.Name, err)
	}

	return nil, ErrNotFound
}
