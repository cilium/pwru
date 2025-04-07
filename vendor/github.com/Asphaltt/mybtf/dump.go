package mybtf

import (
	"fmt"
	"strings"
	"unicode"
	"unsafe"

	"github.com/cilium/ebpf/btf"
)

type dataDumper struct {
	sb strings.Builder
}

func (dd *dataDumper) print(format string, args ...interface{}) {
	fmt.Fprintf(&dd.sb, format, args...)
}

func (dd *dataDumper) dumpInt128(lo, hi uint64) {
	if hi == 0 {
		dd.print("%#x", lo)
	} else {
		dd.print("%#x%016x", hi, lo)
	}
}

func (dd *dataDumper) dumpBitfield(bits bitsInfo, data []byte) {
	nrBits := uint32(bits.size)
	var num [16]byte

	nrBitsCopy := uint32(bits.offset) + nrBits
	nrBytesCopy := (uint32(bits.offset) + nrBits + 7) >> 3
	copy(num[:], data[:nrBytesCopy])

	// Little-endian by default

	leftShiftBits := 128 - nrBitsCopy
	rightShiftBits := 128 - nrBits

	lo, hi := shiftInt128(num[:], leftShiftBits, rightShiftBits)
	dd.dumpInt128(lo, hi)
}

func (dd *dataDumper) dumpIntBits(bits bitsInfo, data []byte) {
	offset := bits.offset
	data = data[offset>>3:]
	bits.offset = offset & 0x7
	dd.dumpBitfield(bits, data)
}

func (dd *dataDumper) dumpInt(v *btf.Int, bits bitsInfo, data []byte) {
	if v.Size == 16 /* 128 */ {
		lo, hi := ne.Uint64(data[:8]), ne.Uint64(data[8:])
		dd.dumpInt128(lo, hi)
		return
	}

	switch v.Encoding {
	case btf.Unsigned:
		switch v.Size {
		case 8:
			dd.print("%d", ne.Uint64(data))
		case 4:
			dd.print("%d", ne.Uint32(data))
		case 2:
			dd.print("%d", ne.Uint16(data))
		case 1:
			dd.print("%d", data[0])
		default:
			dd.dumpIntBits(bits, data)
		}

	case btf.Signed:
		switch v.Size {
		case 8:
			dd.print("%d", int64(ne.Uint64(data)))
		case 4:
			dd.print("%d", int32(ne.Uint32(data)))
		case 2:
			dd.print("%d", int16(ne.Uint16(data)))
		case 1:
			dd.print("%d", int8(data[0]))
		default:
			dd.dumpIntBits(bits, data)
		}

	case btf.Char:
		if unicode.IsPrint(rune(data[0])) {
			dd.print("%q", data[0])
		} else {
			dd.print("%#x", data[0])
		}

	case btf.Bool:
		if data[0] == 0 {
			dd.print("false")
		} else {
			dd.print("true")
		}

	default:
		dd.print("(unsupported-encoding)")
	}
}

func (dd *dataDumper) printStartObject() {
	dd.print("{")
}

func (dd *dataDumper) printEndObject() {
	dd.print("}")
}

func (dd *dataDumper) dumpStruct(v *btf.Struct, data []byte) {
	dd.printStartObject()
	defer dd.printEndObject()

	for i, member := range v.Members {
		// dd.print("%s(offset:%d,bitfieldSize:%d,type:%#v): ", member.Name, member.Offset, member.BitfieldSize, UnderlyingType(member.Type)) // debug
		dd.print(`"%s": `, member.Name)

		if member.BitfieldSize > 0 {
			bits := bitsInfo{member.Offset & 0x7, member.BitfieldSize}
			dd.dumpBitfield(bits, data[member.Offset>>3:])
		} else {
			dd.dumpData(member.Type, emptyBits, data[member.Offset>>3:])
		}

		if i < len(v.Members)-1 {
			dd.print(", ")
		}
	}
}

func (dd *dataDumper) dumpUnion(v *btf.Union, data []byte) {
	dd.printStartObject()
	defer dd.printEndObject()

	for i, member := range v.Members {
		dd.print(`"%s": `, member.Name)

		if member.BitfieldSize > 0 {
			bits := bitsInfo{member.Offset & 0x7, member.BitfieldSize}
			dd.dumpBitfield(bits, data[member.Offset>>3:])
		} else {
			dd.dumpData(member.Type, emptyBits, data[member.Offset>>3:])
		}

		if i < len(v.Members)-1 {
			dd.print(", ")
		}
	}
}

func (dd *dataDumper) printStartArray() {
	dd.print("[")
}

func (dd *dataDumper) printEndArray() {
	dd.print("]")
}

func (dd *dataDumper) dumpArray(v *btf.Array, data []byte) {
	if v.Nelems == 0 {
		dd.print("[]")
		return
	}

	// if str array, print as string
	if IsChar(v.Type) {
		dd.print(`"%s"`, unsafe.String(&data[0], v.Nelems-1))
		return
	}

	dd.printStartArray()
	defer dd.printEndArray()

	elemTypeSize, err := btf.Sizeof(v.Type)
	if err != nil {
		dd.print("(unsupported-elem-type)")
		return
	}

	for i := uint32(0); i < v.Nelems; i++ {
		dd.dumpData(v.Type, emptyBits, data[uint32(elemTypeSize)*i:])
		if i < v.Nelems-1 {
			dd.print(", ")
		}
	}
}

func (dd *dataDumper) dumpEnum(v *btf.Enum, data []byte) {
	var val uint64

	switch v.Size {
	case 8:
		val = ne.Uint64(data[:8])
	case 4:
		val = uint64(ne.Uint32(data[:4]))
	case 2:
		val = uint64(ne.Uint16(data[:2]))
	case 1:
		val = uint64(data[0])
	default:
		panic("unknown enum size")
	}

	for _, value := range v.Values {
		if value.Value == val {
			dd.print("%s", value.Name)
			return
		}
	}

	dd.print("%d", val)
}

func (dd *dataDumper) dumpPointer(_ *btf.Pointer, data []byte) {
	dd.print("%#x", ne.Uint64(data[:8]))
}

func (dd *dataDumper) dumpVar(v *btf.Var, bits bitsInfo, data []byte) {
	dd.printStartObject()
	defer dd.printEndObject()

	dd.print(`"%s": `, v.Name)
	dd.dumpData(v.Type, bits, data)
}

func (dd *dataDumper) dumpDataSec(v *btf.Datasec, data []byte) error {
	dd.printStartObject()
	defer dd.printEndObject()

	dd.print(`"%s": `, v.Name)

	dd.printStartArray()
	defer dd.printEndArray()

	nrVars := len(v.Vars)
	for i, v := range v.Vars {
		if err := dd.dumpData(v.Type, emptyBits, data); err != nil {
			return err
		}

		if i < nrVars-1 {
			dd.print(", ")
		}

		data = data[v.Size:]
	}

	return nil
}

func (dd *dataDumper) dumpData(typ btf.Type, bits bitsInfo, data []byte) error {
	switch v := typ.(type) {
	case *btf.Int:
		dd.dumpInt(v, bits, data)

	case *btf.Struct:
		dd.dumpStruct(v, data)

	case *btf.Union:
		dd.dumpUnion(v, data)

	case *btf.Array:
		dd.dumpArray(v, data)

	case *btf.Enum:
		dd.dumpEnum(v, data)

	case *btf.Pointer:
		dd.dumpPointer(v, data)

	case *btf.Fwd:
		dd.print("(fwd-kind-invalid)")
		return fmt.Errorf("fwd kind invalid")

	case *btf.Typedef:
		return dd.dumpData(v.Type, bits, data)

	case *btf.Volatile:
		return dd.dumpData(v.Type, bits, data)

	case *btf.Const:
		return dd.dumpData(v.Type, bits, data)

	case *btf.Restrict:
		return dd.dumpData(v.Type, bits, data)

	case *btf.Var:
		dd.dumpVar(v, bits, data)

	case *btf.Datasec:
		return dd.dumpDataSec(v, data)

	default:
		dd.print("(unsupported-kind)")
		return fmt.Errorf("unsupported kind %T", v)
	}

	return nil
}

func DumpData(typ btf.Type, data []byte) (string, error) {
	var dd dataDumper
	err := dd.dumpData(typ, emptyBits, data)
	if err != nil {
		return dd.sb.String(), err
	}

	return dd.sb.String(), nil
}

func DumpBitfield(offset, size btf.Bits, data []byte) string {
	var dd dataDumper
	bits := bitsInfo{offset: offset, size: size}
	dd.dumpBitfield(bits, data)
	return dd.sb.String()
}
