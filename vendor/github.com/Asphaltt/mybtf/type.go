package mybtf

import (
	"strings"

	"github.com/cilium/ebpf/btf"
)

func IsChar(t btf.Type) bool {
	t = UnderlyingType(t)
	i, ok := t.(*btf.Int)
	return ok && i.Size == 1 && i.Name == "char"
}

func IsConstCharPtr(t btf.Type) bool {
	t = UnderlyingType(t)
	ptr, isPtr := t.(*btf.Pointer)
	if !isPtr {
		return false
	}

	t = ptr.Target
	cnst, isConst := t.(*btf.Const)
	return isConst && IsChar(cnst.Type)
}

func IsCharArray(t btf.Type) bool {
	t = UnderlyingType(t)
	arr, isArr := t.(*btf.Array)
	return isArr && IsChar(UnderlyingType(arr.Type))
}

func IsInt(typ btf.Type) bool {
	i, ok := typ.(*btf.Int)
	return ok && i.Name == "int"
}

func IsBool(typ btf.Type) bool {
	def, ok := typ.(*btf.Typedef)
	return ok && def.Name == "bool"
}

func IsVoid(t btf.Type) bool {
	_, ok := t.(*btf.Void)
	return ok
}

func IsVoidPointer(t btf.Type) bool {
	p, ok := t.(*btf.Pointer)
	return ok && IsVoid(p.Target)
}

func IsStructPointer(t btf.Type, structName string) bool {
	p, ok := t.(*btf.Pointer)
	if !ok {
		return false
	}

	s, ok := p.Target.(*btf.Struct)
	return ok && s.Name == structName
}

// IsBigEndian checks if the given btf.Type is big-endian or not by checking
// if it is typedef with a name starting with "__be". At most time, the
// big-endian type is typedef with a name starting with "__be" in the kernel.
func IsBigEndian(t btf.Type) bool {
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

// UnderlyingType returns the underlying type of the given btf.Type if it is
// typedef, volatile, const, restrict or type tag.
func UnderlyingType(t btf.Type) btf.Type {
	var ptrs []*btf.Pointer

loop:
	for {
		switch v := t.(type) {
		case *btf.Pointer:
			ptrs = append(ptrs, v)
			t = v.Target
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
			break loop
		}
	}

	if len(ptrs) == 0 {
		return t
	}

	for i := len(ptrs) - 1; i >= 0; i-- {
		t = &btf.Pointer{Target: t}
	}

	return t
}

func HaveEnumValue(spec *btf.Spec, enumName, enumValue string) bool {
	types, err := spec.AnyTypesByName(enumName)
	if err != nil {
		return false
	}

	for _, t := range types {
		e, ok := t.(*btf.Enum)
		if !ok {
			continue
		}

		for _, v := range e.Values {
			if v.Name == enumValue {
				return true
			}
		}
	}

	return false
}
