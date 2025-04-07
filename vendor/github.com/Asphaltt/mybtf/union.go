package mybtf

import (
	"fmt"

	"github.com/cilium/ebpf/btf"
)

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

		if err == ErrNotFound {
			continue
		}
		if err == nil {
			return off, nil
		}
		return 0, fmt.Errorf("failed to find %s member in union %s: %w", name, union.Name, err)
	}

	return 0, ErrNotFound
}

// UnionMemberOffset calculates the offset of a member in a union, even if the
// member is in embedded anonymous struct/union.
func UnionMemberOffset(union *btf.Union, name string) (uint32, error) {
	return unionMemberOffset(union, name, 0)
}

// FindUnionMember finds a member in a union by name, even if the member is in
// embedded anonymous struct/union.
func FindUnionMember(union *btf.Union, name string) (*btf.Member, error) {
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
		return nil, fmt.Errorf("failed to find member %s in union %s: %w", name, union.Name, err)
	}

	return nil, ErrNotFound
}
